import os
import sys
import json
import csv
import numpy as np
from scapy.all import IP, TCP

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

HMM_MODEL_DIR = os.path.join(PROJECT_ROOT, "src", "hmm_model")
if HMM_MODEL_DIR not in sys.path:
    sys.path.insert(0, HMM_MODEL_DIR)

# Import project modules
from src.hmm_model.splitter import PayloadSplitter
from src.hmm_model.simulator import SimulatedWarden
from scapy_carrier import ScapyStorageChannel, ScapyTimingChannel


class HMMEngineBridge:
    """HMM Belief Filtering Engine driven by learned model matrices (A, B, pi)."""

    def __init__(self, model_path: str, alpha_base: list = None):
        """
        :param model_path: Path to learned_hmm_model.json
        :param alpha_base: Base storage allocation ratios for states [0, 1, 2]
        """
        if alpha_base is None:
            # High storage for low threat (0), balanced for med threat (1), low storage for high threat (2)
            self.alpha_base = np.array([0.8, 0.5, 0.2])
        else:
            self.alpha_base = np.array(alpha_base)

        self.load_model(model_path)
        # Initialize belief vector gamma to initial state distribution pi
        self.gamma = np.copy(self.pi)

    def load_model(self, model_path: str):
        with open(model_path, "r") as f:
            data = json.load(f)

        self.A = np.array(data["A"])
        self.B = np.array(data["B"])
        self.pi = np.array(data["pi"])
        self.num_states = len(self.pi)

    def get_allocation_ratio(self) -> tuple:
        """Calculates continuous payload split ratios (alpha_t, beta_t).

        alpha_t = sum(gamma_t(i) * alpha_base_i)
        beta_t  = 1.0 - alpha_t
        """
        alpha_t = float(np.sum(self.gamma * self.alpha_base))
        beta_t = 1.0 - alpha_t
        return alpha_t, beta_t

    def get_most_likely_state(self) -> int:
        """Returns argmax(gamma_t)."""
        return int(np.argmax(self.gamma))

    def update_belief(self, obs: int):
        """Performs Forward belief update step given observation v_t (obs):

        gamma_{t+1} proportional to B[:, obs] * (A^T * gamma_t)
        """
        # Prior update step via state transition matrix A
        prior = np.dot(self.gamma, self.A)
        # Likelihood observation update step via observation matrix B
        likelihood = self.B[:, obs]
        posterior = prior * likelihood

        # Normalize posterior probability distribution
        total_mass = np.sum(posterior)
        if total_mass > 0:
            self.gamma = posterior / total_mass
        else:
            self.gamma = np.ones(self.num_states) / self.num_states


def adapt_warden_for_scapy(warden: SimulatedWarden, storage_packets: list, timing_delays: list):
    """Adapts SimulatedWarden logic to handle real Scapy IP packets safely."""
    received_packets = []
    received_delays = []
    scrubbed_count = 0

    # Process storage packets with Scapy IP ID scrubbing simulation
    for pkt in storage_packets:
        pkt_copy = pkt.copy()
        # Corrupt IP ID LSB if scrubbed by warden based on threat state
        if warden.true_state == 2 and np.random.random() < 0.70:
            pkt_copy[IP].id = np.random.randint(1000, 65000)
            del pkt_copy[IP].chksum
            scrubbed_count += 1
        elif warden.true_state == 1 and np.random.random() < 0.20:
            pkt_copy[IP].id = np.random.randint(1000, 65000)
            del pkt_copy[IP].chksum
            scrubbed_count += 1
        received_packets.append(pkt_copy)

    # Inject timing jitter into Scapy timing delays
    for d in timing_delays:
        noise_scale = 0.04 if warden.true_state == 2 else (0.015 if warden.true_state == 1 else 0.002)
        noise = float(np.random.normal(0.0, noise_scale))
        received_delays.append(max(0.001, d + noise))

    total_storage = len(storage_packets)
    scrub_ratio = scrubbed_count / total_storage if total_storage > 0 else 0.0

    # Calculate observation feedback signal v_t
    if scrub_ratio > 0.40 or warden.true_state == 2:
        obs = 2  # Active Interference
    elif scrub_ratio > 0.10 or warden.true_state == 1:
        obs = 1  # Degraded Traffic
    else:
        obs = 0  # Clean Traffic

    return received_packets, received_delays, obs


def run_scapy_hmm_bridge():
    print("=" * 80)
    print(" PHASE 3: HMM-DRIVEN LIVE SCAPY PACKET TRANSMISSION ENGINE ")
    print("=" * 80)

    # 1. Paths and Setup
    model_path = "results/aligned_hmm_output/learned_hmm_model.json"
    results_csv_path = "results/hmm_scapy_bridge/scapy_hmm_results.csv"

    # Ensure output directory exists
    os.makedirs(os.path.dirname(results_csv_path), exist_ok=True)

    secret_message = (
        "CONFIDENTIAL_PAYLOAD_HMM_GUIDED_HYBRID_STEGANOGRAPHY_PROTOCOL_TEST_DATA_"
        "EVADING_SOTA_ACTIVE_WARDEN_VIA_DYNAMIC_STORAGE_TIMING_RATIO_ALLOCATION"
    )

    # 2. Initialize Core Engines
    hmm_engine = HMMEngineBridge(model_path=model_path)
    splitter = PayloadSplitter(secret_message)
    base_template = IP(src="192.168.1.100", dst="192.168.1.200") / TCP(sport=4433, dport=80)

    # Simulated Dynamic Warden Threat Schedule across 12 Transmission Epochs
    warden_schedule = [0, 0, 1, 2, 2, 2, 1, 1, 0, 0, 2, 0]
    chunk_size = 64  # Total secret bits attempted per epoch

    # Logging headers & containers
    csv_rows = []
    total_bits_sent = 0
    total_bit_errors = 0

    print(f"[+] Secret Payload Size: {len(splitter.binary_payload)} bits ({len(secret_message)} chars)")
    print(f"{'Epoch':<6} | {'Warden':<8} | {'Inferred':<10} | {'Alpha':<7} | {'Beta':<7} | {'Obs':<5} | {'Storage err':<12} | {'Timing err':<11} | {'BER':<7}")
    print("-" * 92)

    for epoch, true_state in enumerate(warden_schedule, start=1):
        if splitter.is_complete():
            print(f"[*] Payload transmission complete at epoch {epoch-1}.")
            break

        # A. Calculate continuous split ratios via HMM Forward Belief Filtering
        alpha_t, beta_t = hmm_engine.get_allocation_ratio()
        inferred_state = hmm_engine.get_most_likely_state()

        # B. Fetch secret bits for storage and timing streams
        storage_str, timing_str = splitter.fetch_next_chunk(chunk_size, alpha_t, beta_t)
        storage_bits = [int(b) for b in storage_str] if storage_str else []
        timing_bits = [int(b) for b in timing_str] if timing_str else []
        epoch_sent_bits = storage_bits + timing_bits

        if not epoch_sent_bits:
            break

        # C. Construct real Scapy Packet structures & compute timing delays
        storage_pkts = ScapyStorageChannel.embed_ip_id(storage_bits, base_template) if storage_bits else []
        timing_delays = ScapyTimingChannel.encode_ipds(
            timing_bits, mu_ipd=0.05, sigma_ipd=0.005, shift_ms=0.015
        ) if timing_bits else []

        # D. Pass packet stream through Active Simulated Warden
        warden = SimulatedWarden(true_state=true_state)
        rx_pkts, rx_delays, obs = adapt_warden_for_scapy(warden, storage_pkts, timing_delays)

        # E. Extract payload at Receiver side
        rx_storage_bits = ScapyStorageChannel.extract_ip_id(rx_pkts) if rx_pkts else []
        rx_timing_bits = ScapyTimingChannel.decode_ipds(rx_delays, threshold=0.05) if rx_delays else []

        # F. Epoch Accuracy & Error Metrics Calculation
        storage_errors = sum(1 for b1, b2 in zip(storage_bits, rx_storage_bits) if b1 != b2)
        timing_errors = sum(1 for b1, b2 in zip(timing_bits, rx_timing_bits) if b1 != b2)
        epoch_errors = storage_errors + timing_errors

        epoch_bit_count = len(epoch_sent_bits)
        total_bits_sent += epoch_bit_count
        total_bit_errors += epoch_errors

        epoch_ber = epoch_errors / epoch_bit_count if epoch_bit_count > 0 else 0.0
        goodput_bits = epoch_bit_count - epoch_errors
        state_accuracy = 1.0 if inferred_state == true_state else 0.0

        # Output console progress
        print(
            f"{epoch:<6} | {true_state:<8} | {inferred_state:<10} | {alpha_t:<7.2f} | {beta_t:<7.2f} | "
            f"{obs:<5} | {storage_errors:<12} | {timing_errors:<11} | {epoch_ber:<7.2%}"
        )

        # Log metrics to output artifact container
        csv_rows.append({
            "epoch": epoch,
            "true_warden_state": true_state,
            "inferred_state": inferred_state,
            "state_accuracy": state_accuracy,
            "alpha_storage_ratio": round(alpha_t, 4),
            "beta_timing_ratio": round(beta_t, 4),
            "observation_feedback": obs,
            "storage_bits_sent": len(storage_bits),
            "storage_errors": storage_errors,
            "timing_bits_sent": len(timing_bits),
            "timing_errors": timing_errors,
            "epoch_sent_bits": epoch_bit_count,
            "epoch_goodput_bits": goodput_bits,
            "epoch_ber": round(epoch_ber, 4)
        })

        # G. Update HMM belief with observation feedback v_t
        hmm_engine.update_belief(obs)

    # 3. Save Expected Output Artifact: scapy_hmm_results.csv
    fieldnames = [
        "epoch", "true_warden_state", "inferred_state", "state_accuracy",
        "alpha_storage_ratio", "beta_timing_ratio", "observation_feedback",
        "storage_bits_sent", "storage_errors", "timing_bits_sent",
        "timing_errors", "epoch_sent_bits", "epoch_goodput_bits", "epoch_ber"
    ]

    with open(results_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print("-" * 92)
    overall_ber = total_bit_errors / total_bits_sent if total_bits_sent > 0 else 0.0
    print(f"[+] SUMMARY METRICS:")
    print(f"    - Total Bits Transmitted: {total_bits_sent}")
    print(f"    - Total Bit Errors: {total_bit_errors}")
    print(f"    - Overall Bit Error Rate (BER): {overall_ber:.2%}")
    print(f"    - Results saved to artifact: {results_csv_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_scapy_hmm_bridge()