"""
simulator.py — HMM-Guided Hybrid Steganography Simulation Loop

This module runs the in-process simulation of the closed-loop protocol.
It is the *only* place where ground truth (warden.true_state) is known.

Two invariants this file must uphold:

  (1) The observation v_t fed to the HMM belief filter MUST be derived only
      from quantities the receiver can measure: sync-bit BER, packet loss,
      IPD statistics. The warden's true_state is never exposed.

  (2) The timing channel is designed with enough SNR that the decoder is
      not operating in the coin-flip regime. See TimingChannel docs.
"""

import random
import numpy as np

from hmm_engine import HMMEngine
from splitter import PayloadSplitter
from channels import StorageChannel, TimingChannel


# ---------------------------------------------------------------------------
# Configuration (single source of truth)
# ---------------------------------------------------------------------------

# Warden behaviour parameters. Probability of scrubbing an IP.id in each state.
WARDEN_SCRUB_PROB = {0: 0.00, 1: 0.20, 2: 0.70}

# Timing jitter (std dev, seconds) injected by the warden in each state.
WARDEN_JITTER_STD = {0: 0.002, 1: 0.015, 2: 0.040}

# Sync-pattern length per channel per epoch (bits).
SYNC_LEN = 16

# Fixed sync pattern (same on both channels, known to sender + receiver).
SYNC_PATTERN = [0, 1] * (SYNC_LEN // 2)

# Observation thresholds (applied to worst-channel sync BER).
OBS_THRESH_DEGRADED = 0.05
OBS_THRESH_SCRUBBING = 0.20


# ---------------------------------------------------------------------------
# Warden model
# ---------------------------------------------------------------------------

class SimulatedWarden:
    """Simulates an active warden with state-dependent scrubbing and jitter.

    IMPORTANT: this class exposes no state to the receiver. Anything the
    receiver observes must flow through `process_traffic`'s return values,
    which are corrupted packets and delayed IPDs — never `true_state`.
    """

    def __init__(self, true_state: int = 0):
        if true_state not in WARDEN_SCRUB_PROB:
            raise ValueError(f"unknown warden state: {true_state}")
        self.true_state = true_state

    def process_traffic(self, storage_packets: list, timing_delays: list,
                        rng: random.Random = None):
        rng = rng or random
        scrub_p = WARDEN_SCRUB_PROB[self.true_state]
        jitter_std = WARDEN_JITTER_STD[self.true_state]

        # --- Storage channel corruption --------------------------------
        received_packets = []
        for pkt in storage_packets:
            pkt_copy = pkt.copy()
            if rng.random() < scrub_p:
                pkt_copy["ip_id"] = rng.randint(1000, 65000)
            received_packets.append(pkt_copy)

        # --- Timing channel jitter -------------------------------------
        # Rejection-sample to avoid the clamping-induced bias that made
        # decoder BER diverge from the analytical value.
        received_delays = []
        for d in timing_delays:
            sample = d + rng.normalvariate(0.0, jitter_std)
            while sample <= 0.0:
                sample = d + rng.normalvariate(0.0, jitter_std)
            received_delays.append(sample)

        return received_packets, received_delays


# ---------------------------------------------------------------------------
# Receiver-side observation function (no ground truth)
# ---------------------------------------------------------------------------

def measure_observation(sync_storage_tx, sync_storage_rx,
                        sync_timing_tx,  sync_timing_rx):
    """Derive v_t from receiver-observable sync-bit error statistics.

    Returns
    -------
    v : int in {0, 1, 2}
        Clean / Degraded / Scrubbing.
    detail : dict
        Per-channel BER, for logging / debugging.
    """
    def _ber(tx, rx):
        if not tx:
            return 0.0
        return sum(a != b for a, b in zip(tx, rx)) / len(tx)

    ber_storage = _ber(sync_storage_tx, sync_storage_rx)
    ber_timing = _ber(sync_timing_tx,  sync_timing_rx)
    ber_max = max(ber_storage, ber_timing)

    if ber_max >= OBS_THRESH_SCRUBBING:
        v = 2
    elif ber_max >= OBS_THRESH_DEGRADED:
        v = 1
    else:
        v = 0

    return v, {
        "sync_ber_storage": ber_storage,
        "sync_ber_timing":  ber_timing,
        "sync_ber_max":     ber_max,
    }


# ---------------------------------------------------------------------------
# Main simulation loop
# ---------------------------------------------------------------------------

def run_simulation(warden_schedule=None, chunk_size=64, seed=42):
    if warden_schedule is None:
        warden_schedule = [0, 0, 1, 2, 2, 2, 1, 1, 0, 0, 2, 0]

    rng = random.Random(seed)
    np.random.seed(seed)

    print("=" * 78)
    print(" HMM-GUIDED HYBRID NETWORK STEGANOGRAPHY — SIMULATION (v2)")
    print("=" * 78)

    secret_message = (
        "CONFIDENTIAL_PAYLOAD_HMM_GUIDED_HYBRID_STEGANOGRAPHY_PROTOCOL_TEST_DATA_"
        "EVADING_SOTA_ACTIVE_WARDEN_VIA_DYNAMIC_STORAGE_TIMING_RATIO_ALLOCATION"
    )

    hmm = HMMEngine()
    splitter = PayloadSplitter(secret_message)
    storage_ch = StorageChannel()
    timing_ch = TimingChannel()

    total_bits_sent = 0
    total_bit_errors = 0

    print(f"\n[+] Payload size: {len(splitter.binary_payload)} bits "
          f"({len(secret_message)} chars)")
    print(f"[+] Warden schedule: {warden_schedule}")
    print(f"[+] Sync length per channel per epoch: {SYNC_LEN} bits")
    print()
    header = (f"{'Ep':<4} | {'True':<5} | {'Infer':<6} | "
              f"{'alpha':<6} | {'beta':<6} | {'v':<3} | "
              f"{'stErr':<6} | {'tmErr':<6} | {'BER':<7}")
    print(header)
    print("-" * len(header))

    for epoch, true_state in enumerate(warden_schedule, start=1):
        if splitter.is_complete():
            print(f"[*] Payload complete at epoch {epoch - 1}.")
            break

        # --- 1. Controller decides allocation ------------------------
        alpha, beta = hmm.get_allocation_ratio()
        inferred_state = hmm.get_most_likely_state()

        # --- 2. Split payload -----------------------------------------
        storage_bits, timing_bits = splitter.fetch_next_chunk(
            chunk_size, alpha, beta)
        epoch_sent_bits = list(storage_bits) + list(timing_bits)
        total_bits_sent += len(epoch_sent_bits)

        if not epoch_sent_bits:
            break

        # --- 3. Prepend sync pattern for receiver-side observation ---
        # The sync bits are NOT counted in the BER denominator, because
        # they are not payload — they are a measurement aid.
        tx_storage = list(SYNC_PATTERN) + list(storage_bits)
        tx_timing  = list(SYNC_PATTERN) + list(timing_bits)

        # --- 4. Encode ------------------------------------------------
        storage_pkts = storage_ch.embed_in_ip_id(tx_storage)
        timing_delays = timing_ch.encode_ipds(tx_timing)

        # --- 5. Pass through the warden (only source of truth) --------
        warden = SimulatedWarden(true_state=true_state)
        rx_pkts, rx_delays = warden.process_traffic(
            storage_pkts, timing_delays, rng=rng)

        # --- 6. Receiver extracts -------------------------------------
        rx_storage = storage_ch.extract_from_ip_id(rx_pkts)
        rx_timing  = timing_ch.decode_ipds(rx_delays)

        # --- 7. Split sync from payload at the receiver --------------
        sync_storage_tx = tx_storage[:SYNC_LEN]
        sync_storage_rx = rx_storage[:SYNC_LEN]
        sync_timing_tx  = tx_timing[:SYNC_LEN]
        sync_timing_rx  = rx_timing[:SYNC_LEN]

        rx_storage_payload = rx_storage[SYNC_LEN:SYNC_LEN + len(storage_bits)]
        rx_timing_payload  = rx_timing[SYNC_LEN:SYNC_LEN + len(timing_bits)]

        

        # --- 8. Observation for HMM (receiver-visible only) -----------
        obs, obs_detail = measure_observation(
            sync_storage_tx, sync_storage_rx,
            sync_timing_tx,  sync_timing_rx)

        # --- 9. BER on payload ----------------------------------------
        storage_errors = sum(a != b for a, b in zip(storage_bits, rx_storage_payload))
        timing_errors  = sum(a != b for a, b in zip(timing_bits,  rx_timing_payload))
        epoch_errors = storage_errors + timing_errors
        total_bit_errors += epoch_errors
        epoch_ber = epoch_errors / len(epoch_sent_bits)

        # --- 10. Log ---------------------------------------------------
        print(f"{epoch:<4} | {true_state:<5} | {inferred_state:<6} | "
              f"{alpha:<6.3f} | {beta:<6.3f} | {obs:<3} | "
              f"{storage_errors:<6} | {timing_errors:<6} | {epoch_ber:<7.2%}")

        # --- 11. HMM belief update -------------------------------------
        hmm.update_belief(obs)

    # --- Summary --------------------------------------------------------
    overall_ber = (total_bit_errors / total_bits_sent
                   if total_bits_sent > 0 else 0.0)
    print("-" * len(header))
    print(f"\n[+] SUMMARY")
    print(f"    Total payload bits: {total_bits_sent}")
    print(f"    Total bit errors:   {total_bit_errors}")
    print(f"    Overall BER:        {overall_ber:.2%}")
    print("=" * 78)

    return {
        "total_bits_sent": total_bits_sent,
        "total_bit_errors": total_bit_errors,
        "overall_ber": overall_ber,
    }


if __name__ == "__main__":
    run_simulation()