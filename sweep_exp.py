"""
Factorial sweep experiment for the HMM-guided hybrid steganography prototype.

Expected project layout:
    sweep_experiment.py
    hmm_engine.py
    splitter.py
    channels.py
    simulator.py

This file integrates the supplied A/B/M parameterization and runs every
combination across several dynamic warden schedules.
"""

import csv
import json
import random
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

from hmm_engine import HMMEngine
from splitter import PayloadSplitter
from channels import StorageChannel, TimingChannel


StateRatio = Tuple[float, float]
RatioMap = Dict[int, StateRatio]


class TransitionStates:
    def __init__(self):
        self.A1 = [
            [0.85, 0.10, 0.05],
            [0.15, 0.70, 0.15],
            [0.05, 0.25, 0.70],
        ]
        self.A2 = [
            [0.50, 0.35, 0.15],
            [0.25, 0.50, 0.25],
            [0.15, 0.35, 0.50],
        ]
        self.A3 = [
            [0.34, 0.33, 0.33],
            [0.33, 0.34, 0.33],
            [0.33, 0.33, 0.34],
        ]


class RatioMapping:
    def __init__(self):
        self.R1 = (0.90, 0.10)
        self.R2 = (0.85, 0.15)
        self.R3 = (0.50, 0.50)
        self.R4 = (0.15, 0.85)


class EmissionStates:
    def __init__(self):
        self.B1 = [
            [0.90, 0.08, 0.02],
            [0.10, 0.80, 0.10],
            [0.02, 0.08, 0.90],
        ]
        self.B2 = [
            [0.70, 0.20, 0.10],
            [0.20, 0.60, 0.20],
            [0.10, 0.20, 0.70],
        ]
        self.B3 = [
            [0.50, 0.30, 0.20],
            [0.25, 0.50, 0.25],
            [0.20, 0.30, 0.50],
        ]


class StrategyMapping:
    def __init__(self, rm: RatioMapping):
        self.M1 = {0: rm.R1, 1: rm.R3, 2: rm.R4}
        self.M2 = {0: rm.R2, 1: rm.R3, 2: rm.R4}
        self.M3 = {0: rm.R1, 1: rm.R2, 2: rm.R3}


class SimulatedWarden:
    """Local copy of the warden model so the sweep is self-contained."""

    def __init__(self, true_state: int):
        self.true_state = true_state

    def process_traffic(self, storage_packets, timing_delays):
        received_packets = []
        received_delays = []
        scrubbed_count = 0

        for packet in storage_packets:
            packet_copy = packet.copy()
            if self.true_state == 2 and random.random() < 0.70:
                packet_copy["ip_id"] = random.randint(1000, 65000)
                scrubbed_count += 1
            elif self.true_state == 1 and random.random() < 0.20:
                packet_copy["ip_id"] = random.randint(1000, 65000)
                scrubbed_count += 1
            received_packets.append(packet_copy)

        noise_scale = {
            0: 0.002,
            1: 0.015,
            2: 0.040,
        }[self.true_state]

        for delay in timing_delays:
            noise = random.normalvariate(0.0, noise_scale)
            received_delays.append(max(0.01, delay + noise))

        total_storage = len(storage_packets)
        scrub_ratio = scrubbed_count / total_storage if total_storage else 0.0

        if scrub_ratio > 0.40 or self.true_state == 2:
            observation = 2
        elif scrub_ratio > 0.10 or self.true_state == 1:
            observation = 1
        else:
            observation = 0

        return received_packets, received_delays, observation


def validate_matrix(matrix, name: str):
    matrix = np.asarray(matrix, dtype=float)
    if matrix.shape != (3, 3):
        raise ValueError(f"{name} must have shape (3, 3), got {matrix.shape}")
    if np.any(matrix < 0) or np.any(matrix > 1):
        raise ValueError(f"{name} contains probabilities outside [0, 1]")
    if not np.allclose(matrix.sum(axis=1), 1.0, atol=1e-9):
        raise ValueError(f"Rows of {name} must sum to 1")
    return matrix


def build_parameter_sets():
    transitions = TransitionStates()
    emissions = EmissionStates()
    ratios = RatioMapping()
    strategies = StrategyMapping(ratios)

    A_sets = {
        "A1": validate_matrix(transitions.A1, "A1"),
        "A2": validate_matrix(transitions.A2, "A2"),
        "A3": validate_matrix(transitions.A3, "A3"),
    }
    B_sets = {
        "B1": validate_matrix(emissions.B1, "B1"),
        "B2": validate_matrix(emissions.B2, "B2"),
        "B3": validate_matrix(emissions.B3, "B3"),
    }
    M_sets = {
        "M1": strategies.M1,
        "M2": strategies.M2,
        "M3": strategies.M3,
    }
    return A_sets, B_sets, M_sets


def build_testcases():
    """Dynamic attack schedules used by the experiment."""
    return {
        "baseline_multistage": [0] * 10 + [2] * 10 + [1] * 10,
        "sudden_attack": [0] * 15 + [2] * 15,
        "bursty_attack": [state for _ in range(5) for state in ([0] * 3 + [2] * 3)],
        "prolonged_high_recovery": [2] * 20 + [0] * 10,
        "medium_dominated": [1] * 5 + [0] * 3 + [1] * 5 + [2] * 3 + [1] * 5,
    }


def make_secret_message():
    return (
        "CONFIDENTIAL_PAYLOAD_HMM_GUIDED_HYBRID_STEGANOGRAPHY_PROTOCOL_TEST_DATA_"
        "EVADING_SOTA_ACTIVE_WARDEN_VIA_DYNAMIC_STORAGE_TIMING_RATIO_ALLOCATION"
    )


def run_single_case(
    A,
    B,
    ratio_map: RatioMap,
    schedule: List[int],
    secret_message: str,
    chunk_size: int = 64,
):
    hmm = HMMEngine(A=A, B=B)
    hmm.ratio_map = ratio_map
    splitter = PayloadSplitter(secret_message)
    storage_channel = StorageChannel()
    timing_channel = TimingChannel()

    total_bits = 0
    total_errors = 0
    storage_bits_sent = 0
    timing_bits_sent = 0
    storage_errors = 0
    timing_errors = 0
    adaptation_errors = []
    ratios_used = []
    inferred_states = []
    observations = []
    true_states = []

    for epoch, true_state in enumerate(schedule, start=1):
        if splitter.is_complete():
            break

        alpha, beta = hmm.get_allocation_ratio()
        inferred_state = hmm.get_most_likely_state()
        storage_bits, timing_bits = splitter.fetch_next_chunk(chunk_size, alpha, beta)

        storage_bits_sent += len(storage_bits)
        timing_bits_sent += len(timing_bits)
        epoch_bits = storage_bits + timing_bits
        total_bits += len(epoch_bits)

        packets = storage_channel.embed_in_ip_id(storage_bits)
        delays = timing_channel.encode_ipds(timing_bits)
        warden = SimulatedWarden(true_state)
        received_packets, received_delays, observation = warden.process_traffic(
            packets, delays
        )

        received_storage = storage_channel.extract_from_ip_id(received_packets)
        received_timing = timing_channel.decode_ipds(received_delays)

        storage_epoch_errors = sum(a != b for a, b in zip(storage_bits, received_storage))
        timing_epoch_errors = sum(a != b for a, b in zip(timing_bits, received_timing))
        epoch_errors = storage_epoch_errors + timing_epoch_errors
        total_errors += epoch_errors
        storage_errors += storage_epoch_errors
        timing_errors += timing_epoch_errors

        ratios_used.append((alpha, beta))
        inferred_states.append(inferred_state)
        observations.append(observation)
        true_states.append(true_state)
        adaptation_errors.append(abs(true_state - inferred_state))

        hmm.update_belief(observation)

    epochs_run = len(true_states)
    ber = total_errors / total_bits if total_bits else 0.0
    goodput = (total_bits - total_errors) / epochs_run if epochs_run else 0.0
    state_accuracy = (
        sum(t == i for t, i in zip(true_states, inferred_states)) / epochs_run
        if epochs_run else 0.0
    )

    return {
        "epochs_run": epochs_run,
        "total_bits": total_bits,
        "storage_bits": storage_bits_sent,
        "timing_bits": timing_bits_sent,
        "total_errors": total_errors,
        "storage_errors": storage_errors,
        "timing_errors": timing_errors,
        "ber": ber,
        "goodput_bits_per_epoch": goodput,
        "state_accuracy": state_accuracy,
        "mean_adaptation_error": float(np.mean(adaptation_errors)) if adaptation_errors else 0.0,
        "max_adaptation_error": max(adaptation_errors) if adaptation_errors else 0,
        "mean_storage_ratio": float(np.mean([r[0] for r in ratios_used])) if ratios_used else 0.0,
        "mean_timing_ratio": float(np.mean([r[1] for r in ratios_used])) if ratios_used else 0.0,
        "observations": observations,
        "true_states": true_states,
        "inferred_states": inferred_states,
        "ratios_used": ratios_used,
    }


def run_sweep(seed: int = 42, chunk_size: int = 64):
    random.seed(seed)
    np.random.seed(seed)

    A_sets, B_sets, M_sets = build_parameter_sets()
    testcases = build_testcases()
    secret_message = make_secret_message()
    results = []

    total_runs = len(testcases) * len(A_sets) * len(B_sets) * len(M_sets)
    run_number = 0

    for testcase_name, schedule in testcases.items():
        for A_name, A in A_sets.items():
            for B_name, B in B_sets.items():
                for M_name, ratio_map in M_sets.items():
                    run_number += 1
                    metrics = run_single_case(
                        A=A,
                        B=B,
                        ratio_map=ratio_map,
                        schedule=schedule,
                        secret_message=secret_message,
                        chunk_size=chunk_size,
                    )
                    result = {
                        "testcase": testcase_name,
                        "transition": A_name,
                        "emission": B_name,
                        "strategy": M_name,
                        **{k: v for k, v in metrics.items() if k not in {
                            "observations", "true_states", "inferred_states", "ratios_used"
                        }},
                        "observations": json.dumps(metrics["observations"]),
                        "true_states": json.dumps(metrics["true_states"]),
                        "inferred_states": json.dumps(metrics["inferred_states"]),
                        "ratios_used": json.dumps(metrics["ratios_used"]),
                    }
                    results.append(result)
                    print(
                        f"[{run_number:03d}/{total_runs}] "
                        f"{testcase_name} | {A_name}-{B_name}-{M_name} | "
                        f"BER={result['ber']:.4f} | "
                        f"Goodput={result['goodput_bits_per_epoch']:.2f}"
                    )

    return results


def write_csv(results, output_path="sweep_results.csv"):
    if not results:
        return
    fieldnames = list(results[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_rankings(results):
    print("\n=== BEST CONFIGURATIONS BY BER ===")
    for row in sorted(results, key=lambda item: item["ber"])[:10]:
        print(
            f"{row['testcase']} | {row['transition']}-{row['emission']}-{row['strategy']} | "
            f"BER={row['ber']:.4f}, "
            f"goodput={row['goodput_bits_per_epoch']:.2f}, "
            f"accuracy={row['state_accuracy']:.2%}"
        )

    print("\n=== BEST CONFIGURATIONS BY GOODPUT ===")
    for row in sorted(
        results,
        key=lambda item: item["goodput_bits_per_epoch"],
        reverse=True,
    )[:10]:
        print(
            f"{row['testcase']} | {row['transition']}-{row['emission']}-{row['strategy']} | "
            f"goodput={row['goodput_bits_per_epoch']:.2f}, "
            f"BER={row['ber']:.4f}, "
            f"accuracy={row['state_accuracy']:.2%}"
        )


def main():
    output_dir = Path("sweep_output")
    output_dir.mkdir(exist_ok=True)
    output_csv = output_dir / "sweep_results.csv"

    results = run_sweep(seed=42, chunk_size=64)
    write_csv(results, output_csv)
    print_rankings(results)
    print(f"\nSaved {len(results)} experiment rows to {output_csv}")


if __name__ == "__main__":
    main()