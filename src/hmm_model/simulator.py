import random
from hmm_engine import HMMEngine
from splitter import PayloadSplitter
from channels import StorageChannel, TimingChannel

class SimulatedWarden:
    """
    Simulates an Active Warden with variable scrubbing and jitter intensity.
    """
    def __init__(self, true_state: int = 0):
        self.true_state = true_state  # 0: Low, 1: Med, 2: High Scrubbing

    def process_traffic(self, storage_packets: list, timing_delays: list):
        received_packets = []
        received_delays = []
        scrubbed_count = 0

        # Storage field scrubbing
        for pkt in storage_packets:
            pkt_copy = pkt.copy()
            if self.true_state == 2 and random.random() < 0.70:
                pkt_copy["ip_id"] = random.randint(1000, 65000)  # Corrupt storage
                scrubbed_count += 1
            elif self.true_state == 1 and random.random() < 0.20:
                pkt_copy["ip_id"] = random.randint(1000, 65000)
                scrubbed_count += 1
            received_packets.append(pkt_copy)

        # Timing jitter injection
        for d in timing_delays:
            noise_scale = 0.04 if self.true_state == 2 else (0.015 if self.true_state == 1 else 0.002)
            noise = random.normalvariate(0.0, noise_scale)
            received_delays.append(max(0.01, d + noise))

        total_storage = len(storage_packets)
        scrub_ratio = scrubbed_count / total_storage if total_storage > 0 else 0.0

        # Formulate observation feedback signal v_t
        if scrub_ratio > 0.40 or self.true_state == 2:
            obs = 2  # Active Interference
        elif scrub_ratio > 0.10 or self.true_state == 1:
            obs = 1  # Degraded Traffic
        else:
            obs = 0  # Clean Traffic

        return received_packets, received_delays, obs


def run_simulation():
    print("=" * 70)
    print(" HMM-GUIDED HYBRID NETWORK STEGANOGRAPHY SIMULATION ")
    print("=" * 70)

    secret_message = (
        "CONFIDENTIAL_PAYLOAD_HMM_GUIDED_HYBRID_STEGANOGRAPHY_PROTOCOL_TEST_DATA_"
        "EVADING_SOTA_ACTIVE_WARDEN_VIA_DYNAMIC_STORAGE_TIMING_RATIO_ALLOCATION"
    )

    hmm = HMMEngine()
    splitter = PayloadSplitter(secret_message)
    storage_ch = StorageChannel()
    timing_ch = TimingChannel()

    # Warden schedule across 10 transmission epochs:
    # Epochs 1-3: Low Threat -> Epochs 4-7: High Threat Scrubbing -> Epochs 8-10: Medium/Low
    warden_schedule = [1, 9]

    reconstructed_bits = ""
    total_bits_sent = 0
    total_bit_errors = 0

    print(f"\n[+] Payload Size: {len(splitter.binary_payload)} bits ({len(secret_message)} chars)")
    print(f"{'Epoch':<6} | {'Warden State':<13} | {'Inferred State':<15} | {'Alpha (Storage)':<15} | {'Beta (Timing)':<14} | {'Obs':<5} | {'BER':<6}")
    print("-" * 88)

    chunk_size = 64  # bits per epoch

    for epoch, true_state in enumerate(warden_schedule, start=1):
        if splitter.is_complete():
            break

        # 1. HMM Controller determines allocation ratios
        alpha, beta = hmm.get_allocation_ratio()
        inferred_state = hmm.get_most_likely_state()

        # 2. Split payload
        storage_bits, timing_bits = splitter.fetch_next_chunk(chunk_size, alpha, beta)
        epoch_sent_bits = storage_bits + timing_bits
        total_bits_sent += len(epoch_sent_bits)

        # 3. Encode into channels
        storage_pkts = storage_ch.embed_in_ip_id(storage_bits)
        timing_delays = timing_ch.encode_ipds(timing_bits)

        # 4. Pass through simulated Active Warden
        warden = SimulatedWarden(true_state=true_state)
        rx_pkts, rx_delays, obs = warden.process_traffic(storage_pkts, timing_delays)

        # 5. Receiver extracts secret bits
        rx_storage_bits = storage_ch.extract_from_ip_id(rx_pkts)
        rx_timing_bits = timing_ch.decode_ipds(rx_delays)

        epoch_rx_bits = rx_storage_bits + rx_timing_bits
        reconstructed_bits += epoch_rx_bits

        epoch_errors = sum(1 for b1, b2 in zip(epoch_sent_bits, epoch_rx_bits) if b1 != b2)
        total_bit_errors += epoch_errors
        epoch_ber = epoch_errors / len(epoch_sent_bits) if epoch_sent_bits else 0.0

        print(f"{epoch:<6} | {true_state:<13} | {inferred_state:<15} | {alpha:<15.2f} | {beta:<14.2f} | {obs:<5} | {epoch_ber:<6.2%}")

        # 6. Update HMM belief based on observation feedback
        hmm.update_belief(obs)

    overall_ber = total_bit_errors / total_bits_sent if total_bits_sent > 0 else 0.0
    print("-" * 88)
    print(f"\n[+] SUMMARY RESULTS:")
    print(f"    - Total Bits Transmitted: {total_bits_sent}")
    print(f"    - Overall Bit Error Rate (BER): {overall_ber:.2%}")
    print("=" * 70)

if __name__ == "__main__":
    run_simulation()