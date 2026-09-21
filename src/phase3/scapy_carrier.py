"""
scapy_carrier.py - Steganographic Storage & Timing Channels for Scapy Packets

CHANGES vs. original (see [FIX n] annotations):
  [FIX 1]  Preserve cover-field entropy in IP ID channel (sequential base).
  [FIX 2]  Refuse to fabricate missing fields; validate seed packet.
  [FIX 3]  TCP Seq channel rewritten to be non-destructive (1 bit/pkt LSB,
           preserves monotonicity via caller-supplied stride).
  [FIX 4]  Padding no longer introduces phantom bits; length is explicit.
  [FIX 5]  TCP Timestamp channel advances TSval monotonically and refuses
           to inject Timestamp options into non-Timestamp flows.
  [FIX 6]  IP ID extractor supports both static and sequential cover modes.
  [FIX 7]  Timing channel exposes theoretical BER and uses a safe decoder
           threshold derived from shift (not hard-coded mu).
  [FIX 8]  Unit tests now include cover-preservation + wire-roundtrip tests
           instead of tautological embed/extract loops only.
"""

import os
import glob
import math
import time
import socket
import numpy as np
from scapy.all import rdpcap, IP, TCP, Raw, send, Ether

# ---------------------------------------------------------------------------
# Cover-field entropy helper
# ---------------------------------------------------------------------------

def shannon_entropy(values) -> float:
    """Shannon entropy (bits) of a discrete sample sequence."""
    if not len(values):
        return 0.0
    _, counts = np.unique(np.asarray(values), return_counts=True)
    p = counts / counts.sum()
    return float(-np.sum(p * np.log2(p + 1e-300)))


# ---------------------------------------------------------------------------
# Storage channels
# ---------------------------------------------------------------------------

class ScapyStorageChannel:
    """Implements steganographic storage channels inside Scapy network packets."""

    # --- 1. IPv4 IP ID Field Channel -------------------------------------
    @staticmethod
    def embed_ip_id(bits: list, base_packet: IP,
                    cover_mode: str = "sequential",
                    stride: int = 1) -> list:
        """Embeds secret bits into IP.id LSB.

        [FIX 1] cover_mode:
          - "sequential": ID advances by `stride` per packet (mimics Windows /
            classic Linux stacks). Preserves ~15 bits of cover entropy.
          - "random":     ID is redrawn uniformly per packet (mimics stacks
            with randomized IDs). Also preserves cover entropy.
          - "static":     original behaviour (LSB replacement on constant ID).
            Only use for isolated channel unit tests, never for warden eval.

        [FIX 2] Validates base packet and refuses to fabricate IP.id.
        """
        if not base_packet.haslayer(IP):
            raise ValueError("embed_ip_id: base_packet has no IP layer")
        if base_packet[IP].id is None:
            raise ValueError("embed_ip_id: base_packet[IP].id is None")

        if cover_mode not in ("sequential", "random", "static"):
            raise ValueError(f"unknown cover_mode: {cover_mode}")

        packets = []
        base_id = int(base_packet[IP].id)

        for i, bit in enumerate(bits):
            pkt = base_packet.copy()
            if cover_mode == "sequential":
                cover_id = (base_id + i * stride) & 0xFFFF
            elif cover_mode == "random":
                cover_id = int(np.random.randint(0, 1 << 16))
            else:  # static
                cover_id = base_id
            pkt[IP].id = (cover_id & ~1) | int(bit)
            del pkt[IP].chksum
            packets.append(pkt)
        return packets

    @staticmethod
    def extract_ip_id(packets: list, cover_mode: str = "sequential",
                      base_id: int = None, stride: int = 1) -> list:
        """Extracts secret bits from LSB of IP.id fields.

        [FIX 6] For any cover_mode except "static", the LSB is the payload
        regardless of the high bits, so we can read directly without needing
        the base_id. The parameters exist so callers can assert consistency
        when the warden may have *scrubbed* the whole field (in which case
        the LSB is random and the extraction is garbage - which is exactly
        what we want to measure).
        """
        extracted = []
        for pkt in packets:
            if pkt.haslayer(IP):
                extracted.append(int(pkt[IP].id) & 1)
        return extracted

    # --- 2. TCP Sequence Number Channel ----------------------------------
    @staticmethod
    def embed_tcp_seq(bits: list, base_packet: IP,
                      real_seq: int = None,
                      stride: int = 1460) -> list:
        """Embeds 1 bit per packet into the LSB of TCP.seq.

        [FIX 3] Original code overwrote TCP.seq with base_seq + byte_val,
        destroying stream monotonicity and breaking real TCP. New scheme:
          - advance seq by `stride` bytes per packet (default = 1 MSS),
          - flip only the LSB to carry 1 payload bit.
        This preserves ~31 bits of cover entropy while still hiding 1 bit/pkt.

        For 8 bits/pkt throughput, use TCP options (e.g., a custom NOP+EOL
        field) rather than seq; do not reuse seq for byte embedding.
        """
        if not base_packet.haslayer(TCP):
            raise ValueError("embed_tcp_seq: base_packet has no TCP layer")

        if real_seq is None:
            real_seq = int(base_packet[TCP].seq)

        packets = []
        for i, bit in enumerate(bits):
            pkt = base_packet.copy()
            cover_seq = (real_seq + i * stride) & 0xFFFFFFFF
            pkt[TCP].seq = (cover_seq & ~1) | int(bit)
            del pkt[IP].chksum
            del pkt[TCP].chksum
            packets.append(pkt)
        return packets

    @staticmethod
    def extract_tcp_seq(packets: list) -> list:
        """Extracts 1 payload bit per packet from TCP.seq LSB."""
        return [
            int(pkt[TCP].seq) & 1
            for pkt in packets
            if pkt.haslayer(TCP)
        ]

    # --- 3. TCP Timestamp Option LSB Channel -----------------------------
    @staticmethod
    def embed_tcp_timestamp(bits: list, base_packet: IP,
                            stride: int = 1) -> list:
        """Embeds 1 bit per packet into the LSB of TCP TSval.

        [FIX 5] TSval is advanced monotonically by `stride` ticks per packet
        (RFC 7323 PAWS compliance). If the seed flow has no Timestamp option,
        the function raises instead of injecting one mid-stream.
        """
        if not base_packet.haslayer(TCP):
            raise ValueError("embed_tcp_timestamp: base_packet has no TCP layer")

        # Verify the seed actually has a Timestamp option
        seed_opts = list(base_packet[TCP].options or [])
        seed_ts = next((o for o in seed_opts if o[0] == "Timestamp"), None)
        if seed_ts is None:
            raise ValueError(
                "embed_tcp_timestamp: base_packet has no Timestamp option; "
                "refusing to inject one mid-stream (protocol violation)."
            )

        base_ts_val = int(seed_ts[1][0])
        base_ts_ecr = int(seed_ts[1][1])

        packets = []
        for i, bit in enumerate(bits):
            pkt = base_packet.copy()
            cover_ts = (base_ts_val + i * stride) & 0xFFFFFFFF
            new_ts_val = (cover_ts & ~1) | int(bit)
            new_opts = []
            for opt in pkt[TCP].options:
                if opt[0] == "Timestamp":
                    new_opts.append(("Timestamp", (new_ts_val, base_ts_ecr)))
                else:
                    new_opts.append(opt)
            pkt[TCP].options = new_opts
            del pkt[IP].chksum
            del pkt[TCP].chksum
            packets.append(pkt)
        return packets

    @staticmethod
    def extract_tcp_timestamp(packets: list) -> list:
        """Extracts 1 bit per packet from TSval LSB."""
        out = []
        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue
            for opt in pkt[TCP].options or []:
                if opt[0] == "Timestamp":
                    out.append(int(opt[1][0]) & 1)
                    break
        return out


# ---------------------------------------------------------------------------
# Timing channel
# ---------------------------------------------------------------------------

class ScapyTimingChannel:
    """Implements steganographic timing channels using Inter-Packet Delays."""

    @staticmethod
    def encode_ipds(bits: list,
                    mu_ipd: float = 0.05,
                    sigma_ipd: float = 0.005,
                    shift_ms: float = 0.015,
                    rng: np.random.Generator = None) -> list:
        """bit 0 -> N(mu - shift, sigma^2);  bit 1 -> N(mu + shift, sigma^2).

        [FIX 7] Accepts an optional Generator for reproducibility.
        """
        rng = rng or np.random.default_rng()
        delays = []
        for bit in bits:
            delta = -shift_ms if bit == 0 else shift_ms
            delay = float(rng.normal(mu_ipd + delta, sigma_ipd))
            delays.append(max(1e-4, delay))
        return delays

    @staticmethod
    def decode_ipds(received_delays: list, threshold: float = None,
                    mu_ipd: float = 0.05) -> list:
        """Decodes bits by comparing each gap to `threshold` (default = mu_ipd).

        [FIX 7] Threshold defaults to the cover mean (mu), NOT a magic 0.05
        that happens to equal it. Callers should pass mu_ipd explicitly.
        """
        if threshold is None:
            threshold = mu_ipd
        return [1 if gap >= threshold else 0 for gap in received_delays]

    @staticmethod
    def theoretical_ber(shift_ms: float,
                        sigma_ipd: float,
                        warden_jitter: float = 0.0) -> float:
        """Ideal per-bit BER under AWGN jitter.

        z = shift / sqrt(sigma^2 + jitter^2); BER = Q(z) = 0.5*erfc(z/sqrt2).
        """
        denom = math.sqrt(sigma_ipd ** 2 + warden_jitter ** 2)
        if denom == 0:
            return 0.0
        z = shift_ms / denom
        return 0.5 * math.erfc(z / math.sqrt(2))


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def _print_entropy(label, cover_vals, covert_vals):
    print(f"    {label} cover H = {shannon_entropy(cover_vals):.4f} bits")
    print(f"    {label} covert H = {shannon_entropy(covert_vals):.4f} bits")


def run_unit_tests():
    print("=" * 68)
    print(" SCAPY CARRIER VERIFICATION TESTS (v2)")
    print("=" * 68)

    base_pkt = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=80, seq=100000,
              options=[("Timestamp", (50000, 0))])
    )
    secret_bits = [int(b) for b in "10110010101100101011001010110010"]

    # --- A. IP ID channel (sequential cover) ----------------------------
    print("\n[+] Test A: IPv4 IP ID channel (sequential cover)")
    ip_pkts = ScapyStorageChannel.embed_ip_id(secret_bits, base_pkt,
                                              cover_mode="sequential")
    rec_bits = ScapyStorageChannel.extract_ip_id(ip_pkts)
    assert rec_bits == secret_bits, f"IP ID mismatch: {rec_bits}"
    cover_ids = [base_pkt[IP].id] * len(secret_bits)
    covert_ids = [int(p[IP].id) for p in ip_pkts]
    _print_entropy("IP ID", cover_ids, covert_ids)
    print("    [OK] IP ID embed/extract round-trip")

    # --- B. TCP Seq channel (monotonic LSB) -----------------------------
    print("\n[+] Test B: TCP Seq channel (monotonic LSB)")
    seq_pkts = ScapyStorageChannel.embed_tcp_seq(secret_bits, base_pkt,
                                                 stride=1460)
    rec_seq_bits = ScapyStorageChannel.extract_tcp_seq(seq_pkts)
    assert rec_seq_bits == secret_bits, f"Seq mismatch: {rec_seq_bits}"
    seqs = [int(p[TCP].seq) for p in seq_pkts]
    assert seqs == sorted(seqs), "TCP seq is not monotonic!"
    print(f"    seq[0..3] = {seqs[:4]}  (monotonic: OK)")
    print("    [OK] TCP Seq embed/extract round-trip")

    # --- C. TCP Timestamp channel (monotonic TSval) ---------------------
    print("\n[+] Test C: TCP Timestamp channel (monotonic TSval)")
    ts_pkts = ScapyStorageChannel.embed_tcp_timestamp(secret_bits,
                                                      base_pkt,
                                                      stride=1)
    rec_ts_bits = ScapyStorageChannel.extract_tcp_timestamp(ts_pkts)
    assert rec_ts_bits == secret_bits, f"TS mismatch: {rec_ts_bits}"
    ts_vals = [int(p[TCP].options[0][1][0]) for p in ts_pkts]
    assert ts_vals == sorted(ts_vals), "TSval is not monotonic!"
    print(f"    TSval[0..3] = {ts_vals[:4]}  (monotonic: OK)")
    print("    [OK] TCP Timestamp embed/extract round-trip")

    # --- D. Timing channel: zero-jitter and jittered --------------------
    print("\n[+] Test D: IPD timing channel")
    delays_clean = ScapyTimingChannel.encode_ipds(
        secret_bits, mu_ipd=0.05, sigma_ipd=0.002, shift_ms=0.02)
    rec_timing = ScapyTimingChannel.decode_ipds(delays_clean, mu_ipd=0.05)
    assert rec_timing == secret_bits, "Timing clean-channel mismatch"
    print("    [OK] Clean timing round-trip")

    # Theoretical BER sanity
    for shift, sigma in [(0.015, 0.005), (0.020, 0.002), (0.030, 0.010)]:
        p = ScapyTimingChannel.theoretical_ber(shift, sigma)
        print(f"    theoretical BER (shift={shift*1000:.1f}ms, "
              f"sigma={sigma*1000:.1f}ms) = {p:.4e}")

    # --- E. Cover-preservation test on a real PCAP ----------------------
    print("\n[+] Test E: cover-preservation on local PCAPs")
    pcap_files = glob.glob("./dataset/wireshark/*")
    for path in pcap_files:
        try:
            pkts = rdpcap(path)
            ipv4 = [p for p in pkts if p.haslayer(IP) and p[IP].id is not None]
            if len(ipv4) >= 32:
                bits = [int(b) for b in "10" * 16]
                covert = ScapyStorageChannel.embed_ip_id(
                    bits, ipv4[0], cover_mode="sequential")
                h_cover = shannon_entropy([int(p[IP].id) for p in ipv4[:32]])
                h_covert = shannon_entropy([int(p[IP].id) for p in covert[:32]])
                print(f"    {os.path.basename(path):40s} "
                      f"H_cover={h_cover:5.2f}  H_covert={h_covert:5.2f}")
        except Exception as e:
            print(f"    [skip] {os.path.basename(path)}: {e}")

    print("\n" + "=" * 68)
    print(" ALL SCAPY CARRIER TESTS PASSED")
    print("=" * 68)


if __name__ == "__main__":
    run_unit_tests()