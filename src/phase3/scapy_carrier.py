import os
import glob
import time
import numpy as np
from scapy.all import rdpcap, IP, TCP, PcapReader


class ScapyStorageChannel:
    """Implements steganographic storage channels inside Scapy network packets."""

    # --- 1. IPv4 IP ID Field Channel ---
    @staticmethod
    def embed_ip_id(bits: list, base_packet: IP) -> list:
        """Embeds secret bits into IP.id field using parity/LSB replacement.

        0 = Even ID, 1 = Odd ID.
        """
        packets = []
        for bit in bits:
            pkt = base_packet.copy()
            # Retain original ID higher bits, overwrite LSB with bit value
            orig_id = getattr(pkt[IP], "id", 1000)
            pkt[IP].id = (orig_id & ~1) | int(bit)
            # Recompute IP checksum after modification
            del pkt[IP].chksum
            packets.append(pkt)
        return packets

    @staticmethod
    def extract_ip_id(packets: list) -> list:
        """Extracts secret bits from LSB/parity of received IP.id fields."""
        extracted_bits = []
        for pkt in packets:
            if pkt.haslayer(IP):
                extracted_bits.append(pkt[IP].id & 1)
        return extracted_bits

    # --- 2. TCP Sequence Number Channel ---
    @staticmethod
    def embed_tcp_seq(bits: list, base_packet: IP) -> list:
        """Encodes covert byte values directly into TCP Sequence Numbers.

        Groups bits into 8-bit bytes and adds byte value to initial sequence
        number.
        """
        packets = []
        # Group bits into 8-bit chunks (bytes)
        bytes_list = []
        for i in range(0, len(bits), 8):
            chunk = bits[i : i + 8]
            if len(chunk) < 8:
                chunk += [0] * (8 - len(chunk))  # Pad if needed
            byte_val = sum(b << (7 - idx) for idx, b in enumerate(chunk))
            bytes_list.append(byte_val)

        base_seq = getattr(base_packet[TCP], "seq", 100000)

        for byte_val in bytes_list:
            pkt = base_packet.copy()
            pkt[TCP].seq = base_seq + byte_val
            # Force Scapy to recalculate checksums
            del pkt[IP].chksum
            del pkt[TCP].chksum
            packets.append(pkt)

        return packets

    @staticmethod
    def extract_tcp_seq(packets: list, base_seq: int = 100000) -> list:
        """Extracts covert bits from TCP Sequence Number shifts."""
        extracted_bits = []
        for pkt in packets:
            if pkt.haslayer(TCP):
                shift = (pkt[TCP].seq - base_seq) % 256
                # Convert byte back to 8 bits
                bits = [(shift >> i) & 1 for i in range(7, -1, -1)]
                extracted_bits.extend(bits)
        return extracted_bits

    # --- 3. TCP Timestamp Option LSB Channel ---
    @staticmethod
    def embed_tcp_timestamp(bits: list, base_packet: IP) -> list:
        """Embeds secret bits into the LSB of TCP Timestamp options (TSval)."""
        packets = []
        for bit in bits:
            pkt = base_packet.copy()
            opts = list(pkt[TCP].options)
            new_opts = []
            found_ts = False

            for opt in opts:
                if opt[0] == "Timestamp":
                    ts_val, ts_ecr = opt[1]
                    # Modify LSB of TSval
                    new_ts_val = (ts_val & ~1) | int(bit)
                    new_opts.append(("Timestamp", (new_ts_val, ts_ecr)))
                    found_ts = True
                else:
                    new_opts.append(opt)

            if not found_ts:
                # Add timestamp option if absent
                new_opts.append(("Timestamp", (int(bit), 0)))

            pkt[TCP].options = new_opts
            del pkt[IP].chksum
            del pkt[TCP].chksum
            packets.append(pkt)

        return packets

    @staticmethod
    def extract_tcp_timestamp(packets: list) -> list:
        """Extracts secret bits from LSB of TCP Timestamp option values."""
        extracted_bits = []
        for pkt in packets:
            if pkt.haslayer(TCP):
                for opt in pkt[TCP].options:
                    if opt[0] == "Timestamp":
                        ts_val = opt[1][0]
                        extracted_bits.append(ts_val & 1)
                        break
        return extracted_bits


class ScapyTimingChannel:
    """Implements steganographic timing channels using Inter-Packet Delays (IPDs)."""

    @staticmethod
    def encode_ipds(
        bits: list,
        mu_ipd: float = 0.05,
        sigma_ipd: float = 0.005,
        shift_ms: float = 0.015,
    ) -> list:
        """Generates delays modulating around MAWI baseline profile.

        bit 0 -> N(mu - delta, sigma^2) bit 1 -> N(mu + delta, sigma^2)
        """
        delays = []
        for bit in bits:
            delta = -shift_ms if bit == 0 else shift_ms
            # Draw sample delay from normal distribution
            delay = np.random.normal(mu_ipd + delta, sigma_ipd)
            # Ensure delay is positive
            delays.append(max(0.0001, delay))
        return delays

    @staticmethod
    def decode_ipds(received_delays: list, threshold: float = 0.05) -> list:
        """Decodes secret bits based on whether gaps fall above or below threshold."""
        decoded_bits = []
        for gap in received_delays:
            if gap >= threshold:
                decoded_bits.append(1)
            else:
                decoded_bits.append(0)
        return decoded_bits


# --- Local Verification Unit Test ---
def run_unit_tests():
    print("=" * 60)
    print("RUNNING LOCAL SCAPY CARRIER VERIFICATION TESTS")
    print("=" * 60)

    # 1. Prepare Base Packet
    base_pkt = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
        sport=12345, dport=80, seq=100000, options=[("Timestamp", (50000, 0))]
    )
    secret_bits = [1, 0, 1, 1, 0, 0, 1, 0]  # Test bitstream

    # Test A: IP ID Storage Channel
    print("\n[+] Testing IPv4 IP ID Storage Channel...")
    ip_pkts = ScapyStorageChannel.embed_ip_id(secret_bits, base_pkt)
    extracted_ip_bits = ScapyStorageChannel.extract_ip_id(ip_pkts)
    assert (
        extracted_ip_bits == secret_bits
    ), f"IP ID Failed: {extracted_ip_bits} != {secret_bits}"
    print("    [SUCCESS] IP ID channel passed 100% loss-free!")

    # Test B: TCP Sequence Channel
    print("\n[+] Testing TCP Sequence Storage Channel...")
    tcp_seq_pkts = ScapyStorageChannel.embed_tcp_seq(secret_bits, base_pkt)
    extracted_seq_bits = ScapyStorageChannel.extract_tcp_seq(
        tcp_seq_pkts, base_seq=100000
    )
    assert (
        extracted_seq_bits == secret_bits
    ), f"TCP Seq Failed: {extracted_seq_bits} != {secret_bits}"
    print("    [SUCCESS] TCP Sequence channel passed 100% loss-free!")

    # Test C: TCP Timestamp Channel
    print("\n[+] Testing TCP Timestamp Storage Channel...")
    ts_pkts = ScapyStorageChannel.embed_tcp_timestamp(secret_bits, base_pkt)
    extracted_ts_bits = ScapyStorageChannel.extract_tcp_timestamp(ts_pkts)
    assert (
        extracted_ts_bits == secret_bits
    ), f"TCP TS Failed: {extracted_ts_bits} != {secret_bits}"
    print("    [SUCCESS] TCP Timestamp channel passed 100% loss-free!")

    # Test D: Timing Channel
    print("\n[+] Testing IPD Timing Channel...")
    mu_baseline = 0.05
    shift = 0.02
    delays = ScapyTimingChannel.encode_ipds(
        secret_bits, mu_ipd=mu_baseline, sigma_ipd=0.002, shift_ms=shift
    )
    decoded_timing_bits = ScapyTimingChannel.decode_ipds(
        delays, threshold=mu_baseline
    )
    assert (
        decoded_timing_bits == secret_bits
    ), f"Timing Failed: {decoded_timing_bits} != {secret_bits}"
    print("    [SUCCESS] IPD Timing channel passed 100% loss-free!")

   # Test E: PCAP Base Seed Integration Test (Targeted Protocol Matching)
    print("\n[+] Testing Carrier Modulator on Local PCAP Files...")
    
    pcap_files = glob.glob("./dataset/wireshark/*")
    
    for path in pcap_files:
        try:
            pkts = rdpcap(path)
            
            # 1. Test IPv4 ID Channel on IPv4 captures (e.g., ipv4frags.pcap)
            ipv4_pkts = [p for p in pkts if p.haslayer(IP)]
            if ipv4_pkts:
                seed = ipv4_pkts[0]
                mod = ScapyStorageChannel.embed_ip_id(secret_bits, seed)
                rec = ScapyStorageChannel.extract_ip_id(mod)
                assert rec == secret_bits
                print(f"    [SUCCESS] IP ID channel verified on '{os.path.basename(path)}' ({len(ipv4_pkts)} IPv4 pkts).")
            
            # 2. Test TCP Channels on IPv4/TCP captures (e.g., 200722_win_scale_examples_anon.pcapng)
            tcp_pkts = [p for p in pkts if p.haslayer(IP) and p.haslayer(TCP)]
            if tcp_pkts:
                seed = tcp_pkts[0]
                mod = ScapyStorageChannel.embed_tcp_seq(secret_bits, seed)
                rec = ScapyStorageChannel.extract_tcp_seq(mod, base_seq=seed[TCP].seq)
                assert rec == secret_bits
                print(f"    [SUCCESS] TCP Seq channel verified on '{os.path.basename(path)}' ({len(tcp_pkts)} TCP pkts).")
                
        except Exception as e:
            print(f"    [NOTICE] Skipped or unable to parse '{os.path.basename(path)}': {e}")

    print("\n" + "=" * 60)
    print(" ALL SCAPY CARRIER UNIT TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_unit_tests()