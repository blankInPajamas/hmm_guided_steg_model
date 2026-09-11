"""
Baum-Welch learned HMM experiment for the hybrid network steganography model.

Expected files in the same directory:
    splitter.py
    channels.py

This script is self-contained for the learned-HMM experiment. It trains a
three-state discrete HMM from unlabeled observation sequences, then evaluates
continuous ratio allocation across the five standard attack scenarios.

Run:
    python baum_welch_experiment.py

Outputs:
    learned_hmm_output/learned_hmm_metrics.csv
    learned_hmm_output/learned_hmm_model.json
"""

import csv
import json
import random
from pathlib import Path
from typing import Iterable, List, Sequence

import numpy as np

from channels import StorageChannel, TimingChannel
from splitter import PayloadSplitter


N_STATES = 3
N_OBSERVATIONS = 3
EPSILON = 1e-4
DEFAULT_CHUNK_SIZE = 64
DEFAULT_SEED = 42


class BaumWelchHMM:
    """Three-state discrete HMM trained with scaled Baum-Welch EM."""

    def __init__(
        self,
        n_states: int = N_STATES,
        n_observations: int = N_OBSERVATIONS,
        seed: int = DEFAULT_SEED,
        epsilon: float = EPSILON,
    ):
        self.n_states = n_states
        self.n_observations = n_observations
        self.epsilon = epsilon
        self.rng = np.random.default_rng(seed)
        self.A, self.B, self.pi = self._random_model()
        self.last_log_likelihood = None
        self.training_history = []

    def _normalize_vector(self, vector):
        vector = np.asarray(vector, dtype=float)
        vector = np.maximum(vector, self.epsilon)
        return vector / vector.sum()

    def _normalize_rows(self, matrix):
        matrix = np.asarray(matrix, dtype=float)
        matrix = np.maximum(matrix, self.epsilon)
        return matrix / matrix.sum(axis=1, keepdims=True)

    def _random_model(self):
        A = self.rng.uniform(0.95, 1.05, (self.n_states, self.n_states))
        B = self.rng.uniform(0.95, 1.05, (self.n_states, self.n_observations))
        pi = self.rng.uniform(0.95, 1.05, self.n_states)
        return self._normalize_rows(A), self._normalize_rows(B), self._normalize_vector(pi)

    def _validate_observations(self, observations: Sequence[int]) -> np.ndarray:
        values = np.asarray(list(observations), dtype=int)
        if values.ndim != 1 or len(values) == 0:
            raise ValueError("Observations must be a non-empty one-dimensional sequence")
        if np.any(values < 0) or np.any(values >= self.n_observations):
            raise ValueError("Each observation must be one of 0, 1, or 2")
        return values

    def scaled_forward(self, observations: Sequence[int]):
        observations = self._validate_observations(observations)
        T = len(observations)
        alpha = np.zeros((T, self.n_states), dtype=float)
        scales = np.zeros(T, dtype=float)

        alpha[0] = self.pi * self.B[:, observations[0]]
        scales[0] = max(alpha[0].sum(), self.epsilon)
        alpha[0] /= scales[0]

        for t in range(1, T):
            alpha[t] = (alpha[t - 1] @ self.A) * self.B[:, observations[t]]
            scales[t] = max(alpha[t].sum(), self.epsilon)
            alpha[t] /= scales[t]

        log_likelihood = float(np.sum(np.log(scales)))
        return alpha, scales, log_likelihood

    def scaled_backward(self, observations: Sequence[int], scales: np.ndarray):
        observations = self._validate_observations(observations)
        T = len(observations)
        beta = np.zeros((T, self.n_states), dtype=float)
        beta[-1] = 1.0

        for t in range(T - 2, -1, -1):
            beta[t] = self.A @ (self.B[:, observations[t + 1]] * beta[t + 1])
            beta[t] /= max(scales[t + 1], self.epsilon)

        return beta

    def expectation_step(self, observations: Sequence[int]):
        observations = self._validate_observations(observations)
        alpha, scales, log_likelihood = self.scaled_forward(observations)
        beta = self.scaled_backward(observations, scales)
        T = len(observations)

        gamma = alpha * beta
        gamma /= np.maximum(gamma.sum(axis=1, keepdims=True), self.epsilon)

        xi = np.zeros((max(T - 1, 0), self.n_states, self.n_states), dtype=float)
        for t in range(T - 1):
            xi_t = (
                alpha[t, :, None]
                * self.A
                * self.B[None, :, observations[t + 1]]
                * beta[t + 1, None, :]
            )
            denominator = max(xi_t.sum(), self.epsilon)
            xi[t] = xi_t / denominator

        return gamma, xi, log_likelihood

    def maximization_step(self, observations, gamma, xi):
        observations = self._validate_observations(observations)
        T = len(observations)

        self.pi = self._normalize_vector(gamma[0])

        if T > 1:
            transition_denominators = np.maximum(gamma[:-1].sum(axis=0), self.epsilon)
            self.A = xi.sum(axis=0) / transition_denominators[:, None]
            self.A = self._normalize_rows(self.A)

        B_new = np.zeros((self.n_states, self.n_observations), dtype=float)
        for state in range(self.n_states):
            for observation in range(self.n_observations):
                B_new[state, observation] = gamma[observations == observation, state].sum()
            denominator = max(gamma[:, state].sum(), self.epsilon)
            B_new[state] /= denominator

        self.B = self._normalize_rows(B_new)

    def fit(
        self,
        observations: Sequence[int],
        max_iter: int = 100,
        tolerance: float = 1e-5,
        verbose: bool = True,
    ):
        observations = self._validate_observations(observations)
        self.training_history = []
        previous_log_likelihood = None

        for iteration in range(1, max_iter + 1):
            gamma, xi, log_likelihood = self.expectation_step(observations)
            self.maximization_step(observations, gamma, xi)
            self.training_history.append({
                "iteration": iteration,
                "log_likelihood": log_likelihood,
            })

            if verbose and (iteration == 1 or iteration % 10 == 0):
                print(f"[TRAIN] iteration={iteration:03d}, log_likelihood={log_likelihood:.6f}")

            if (
                previous_log_likelihood is not None
                and abs(log_likelihood - previous_log_likelihood) < tolerance
            ):
                break
            previous_log_likelihood = log_likelihood

        self.last_log_likelihood = self.training_history[-1]["log_likelihood"]
        return self

    def filter_observation(self, observation: int, belief=None):
        """Online Bayesian filtering update for one new feedback observation."""
        if observation < 0 or observation >= self.n_observations:
            raise ValueError("Observation must be 0, 1, or 2")
        if belief is None:
            belief = self.pi.copy()
        prior = np.asarray(belief) @ self.A
        posterior = prior * self.B[:, observation]
        return self._normalize_vector(posterior)

    def continuous_ratio(self, belief=None):
        """Return continuous storage/timing allocation from state posterior."""
        if belief is None:
            belief = self.pi
        belief = self._normalize_vector(belief)
        storage_bases = np.array([0.90, 0.50, 0.10])
        alpha = float(np.dot(belief, storage_bases))
        alpha = min(max(alpha, 0.0), 1.0)
        return alpha, 1.0 - alpha


class SimulatedWarden:
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

        noise_scale = {0: 0.002, 1: 0.015, 2: 0.040}[self.true_state]
        for delay in timing_delays:
            received_delays.append(max(0.01, delay + random.normalvariate(0.0, noise_scale)))

        storage_count = len(storage_packets)
        scrub_ratio = scrubbed_count / storage_count if storage_count else 0.0
        if scrub_ratio > 0.40 or self.true_state == 2:
            observation = 2
        elif scrub_ratio > 0.10 or self.true_state == 1:
            observation = 1
        else:
            observation = 0

        return received_packets, received_delays, observation


def make_standard_scenarios():
    return {
        "baseline_multistage": [0] * 10 + [2] * 10 + [1] * 10,
        "sudden_attack": [0] * 15 + [2] * 15,
        "bursty_attack": [state for _ in range(5) for state in ([0] * 3 + [2] * 3)],
        "prolonged_high_recovery": [2] * 20 + [0] * 10,
        "medium_dominated": [1] * 5 + [0] * 3 + [1] * 5 + [2] * 3 + [1] * 5,
    }


def make_training_sequences(scenarios, repeats: int = 20):
    """Create observation sequences from the simulator without using labels."""
    sequences = []
    for schedule in scenarios.values():
        for _ in range(repeats):
            observations = []
            for state in schedule:
                _, _, observation = SimulatedWarden(state).process_traffic([], [])
                observations.append(observation)
            sequences.append(observations)
    return sequences


def train_from_sequences(sequences, seed=DEFAULT_SEED):
    """Train on concatenated observation sequences."""
    flattened = [observation for sequence in sequences for observation in sequence]
    model = BaumWelchHMM(seed=seed)
    model.fit(flattened, max_iter=100, tolerance=1e-5, verbose=True)
    return model


def make_secret_message():
    return (
        "CONFIDENTIAL_PAYLOAD_HMM_GUIDED_HYBRID_STEGANOGRAPHY_PROTOCOL_TEST_DATA_"
        "EVADING_SOTA_ACTIVE_WARDEN_VIA_DYNAMIC_STORAGE_TIMING_RATIO_ALLOCATION"
    )


def run_scenario(model, schedule, secret_message, chunk_size=DEFAULT_CHUNK_SIZE):
    splitter = PayloadSplitter(secret_message)
    storage_channel = StorageChannel()
    timing_channel = TimingChannel()
    belief = model.pi.copy()

    total_bits = 0
    total_errors = 0
    storage_errors = 0
    timing_errors = 0
    storage_bits = 0
    timing_bits = 0
    inferred_states = []
    true_states = []
    ratios = []

    for true_state in schedule:
        if splitter.is_complete():
            break

        alpha, beta = model.continuous_ratio(belief)
        inferred_state = int(np.argmax(belief))
        storage_chunk, timing_chunk = splitter.fetch_next_chunk(chunk_size, alpha, beta)
        storage_bits += len(storage_chunk)
        timing_bits += len(timing_chunk)
        total_bits += len(storage_chunk) + len(timing_chunk)

        packets = storage_channel.embed_in_ip_id(storage_chunk)
        delays = timing_channel.encode_ipds(timing_chunk)
        received_packets, received_delays, observation = SimulatedWarden(true_state).process_traffic(
            packets, delays
        )

        received_storage = storage_channel.extract_from_ip_id(received_packets)
        received_timing = timing_channel.decode_ipds(received_delays)
        storage_epoch_errors = sum(a != b for a, b in zip(storage_chunk, received_storage))
        timing_epoch_errors = sum(a != b for a, b in zip(timing_chunk, received_timing))
        storage_errors += storage_epoch_errors
        timing_errors += timing_epoch_errors
        total_errors += storage_epoch_errors + timing_epoch_errors

        true_states.append(true_state)
        inferred_states.append(inferred_state)
        ratios.append((alpha, beta))
        belief = model.filter_observation(observation, belief)

    epochs = len(true_states)
    return {
        "epochs_run": epochs,
        "total_bits": total_bits,
        "storage_bits": storage_bits,
        "timing_bits": timing_bits,
        "total_errors": total_errors,
        "storage_errors": storage_errors,
        "timing_errors": timing_errors,
        "ber": total_errors / total_bits if total_bits else 0.0,
        "goodput_bits_per_epoch": (total_bits - total_errors) / epochs if epochs else 0.0,
        "state_accuracy": (
            sum(a == b for a, b in zip(true_states, inferred_states)) / epochs
            if epochs else 0.0
        ),
        "mean_storage_ratio": float(np.mean([x[0] for x in ratios])) if ratios else 0.0,
        "mean_timing_ratio": float(np.mean([x[1] for x in ratios])) if ratios else 0.0,
    }


def save_metrics(metrics, path):
    if not metrics:
        return
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(metrics[0].keys()))
        writer.writeheader()
        writer.writerows(metrics)


def save_model(model, path):
    payload = {
        "A": model.A.tolist(),
        "B": model.B.tolist(),
        "pi": model.pi.tolist(),
        "last_log_likelihood": model.last_log_likelihood,
        "training_history": model.training_history,
    }
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def main():
    random.seed(DEFAULT_SEED)
    np.random.seed(DEFAULT_SEED)

    output_dir = Path("learned_hmm_output")
    output_dir.mkdir(exist_ok=True)

    scenarios = make_standard_scenarios()
    training_sequences = make_training_sequences(scenarios, repeats=20)
    model = train_from_sequences(training_sequences, seed=DEFAULT_SEED)

    print("\n=== LEARNED MODEL ===")
    print("A =\n", np.array2string(model.A, precision=6))
    print("B =\n", np.array2string(model.B, precision=6))
    print("pi =", np.array2string(model.pi, precision=6))

    results = []
    for scenario_name, schedule in scenarios.items():
        metrics = run_scenario(model, schedule, make_secret_message())
        results.append({"scenario": scenario_name, **metrics})
        print(
            f"[EVAL] {scenario_name} | BER={metrics['ber']:.4f} | "
            f"goodput={metrics['goodput_bits_per_epoch']:.2f} | "
            f"accuracy={metrics['state_accuracy']:.2%} | "
            f"storage_errors={metrics['storage_errors']} | "
            f"timing_errors={metrics['timing_errors']}"
        )

    save_metrics(results, output_dir / "learned_hmm_metrics.csv")
    save_model(model, output_dir / "learned_hmm_model.json")
    print(f"\nSaved results to {output_dir}")


if __name__ == "__main__":
    main()