"""
aligned_baum_welch.py — Baum-Welch EM with state re-alignment.

Trains an HMM on observations produced by the fixed simulator pipeline
(`src/hmm_model/simulator.py`), whose observation signal is derived ONLY
from receiver-measurable sync-bit error statistics. Ground truth
(warden.true_state) never leaks into the observation.

Outputs (overwrites):
    results/aligned_hmm_output/learned_hmm_model.json
    results/aligned_hmm_output/learned_hmm_metrics.csv

Run:
    make train
    # or
    python experiments/aligned_baum_welch.py
"""

import os
import sys
import csv
import json
import random
from collections import Counter

import numpy as np

# ---------------------------------------------------------------------------
# Path bootstrap — MUST come before any `from src...` import
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if not os.path.isdir(os.path.join(PROJECT_ROOT, "src")):
    raise RuntimeError(
        f"src/ not found under PROJECT_ROOT={PROJECT_ROOT!r}. "
        f"Run this script from the project root.")

# ---------------------------------------------------------------------------
# Project imports (now safe)
# ---------------------------------------------------------------------------
from src.hmm_model import simulator as sim
from src.hmm_model.channels import StorageChannel, TimingChannel

# ---------------------------------------------------------------------------
# Bind simulator exports
# ---------------------------------------------------------------------------
print(f"[IMPORT] simulator loaded from: {sim.__file__}")
for _name in ("SYNC_PATTERN", "SYNC_LEN", "SimulatedWarden",
              "StorageChannel", "TimingChannel", "measure_observation"):
    if not hasattr(sim, _name):
        raise ImportError(
            f"simulator module at {sim.__file__!r} lacks attribute "
            f"{_name!r}.")

SYNC_PATTERN        = sim.SYNC_PATTERN
SYNC_LEN            = sim.SYNC_LEN
SimulatedWarden     = sim.SimulatedWarden
measure_observation = sim.measure_observation

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
N_STATES           = 3
N_OBSERVATIONS     = 3
EPSILON            = 1e-4
DEFAULT_CHUNK_SIZE = 64
DEFAULT_SEED       = 42

OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "results", "aligned_hmm_output")
MODEL_PATH   = os.path.join(OUTPUT_DIR, "learned_hmm_model.json")
METRICS_PATH = os.path.join(OUTPUT_DIR, "learned_hmm_metrics.csv")


# ---------------------------------------------------------------------------
# Baum-Welch EM (scaled forward/backward)
# ---------------------------------------------------------------------------

class BaumWelchHMM:
    def __init__(self, n_states=N_STATES, n_observations=N_OBSERVATIONS,
                 seed=DEFAULT_SEED, epsilon=EPSILON):
        self.n_states = n_states
        self.n_observations = n_observations
        self.epsilon = epsilon
        self.rng = np.random.default_rng(seed)

        self.A  = self.rng.dirichlet([2] * n_states, size=n_states)
        self.B  = self.rng.dirichlet([2] * n_observations, size=n_states)
        self.pi = self.rng.dirichlet([2] * n_states)

    def _validate_observations(self, observations):
        values = np.asarray(list(observations), dtype=int)
        if np.any(values < 0) or np.any(values >= self.n_observations):
            raise ValueError(
                f"Each observation must be in [0, {self.n_observations})")
        return values

    def scaled_forward(self, observations):
        observations = self._validate_observations(observations)
        T = len(observations)
        alpha = np.zeros((T, self.n_states))
        scales = np.zeros(T)

        alpha[0] = self.pi * self.B[:, observations[0]]
        c = alpha[0].sum()
        if c <= 0:
            raise RuntimeError("Forward pass: zero normalization at t=0")
        alpha[0] /= c
        scales[0] = c

        for t in range(1, T):
            alpha[t] = (alpha[t - 1] @ self.A) * self.B[:, observations[t]]
            c = alpha[t].sum()
            if c <= 0:
                raise RuntimeError(f"Forward pass: zero normalization at t={t}")
            alpha[t] /= c
            scales[t] = c

        log_likelihood = float(np.sum(np.log(scales)))
        return alpha, scales, log_likelihood

    def scaled_backward(self, observations, scales):
        observations = self._validate_observations(observations)
        T = len(observations)
        beta = np.zeros((T, self.n_states))
        beta[-1] = 1.0

        for t in range(T - 2, -1, -1):
            beta[t] = (self.A @ (self.B[:, observations[t + 1]] * beta[t + 1]))
            beta[t] /= scales[t + 1]

        return beta

    def expectation_step(self, observations):
        observations = self._validate_observations(observations)
        alpha, scales, log_likelihood = self.scaled_forward(observations)
        beta = self.scaled_backward(observations, scales)
        T = len(observations)

        gamma = alpha * beta
        row_sums = gamma.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        gamma = gamma / row_sums

        xi = np.zeros((T - 1, self.n_states, self.n_states))
        for t in range(T - 1):
            num = (alpha[t][:, None]
                   * self.A
                   * (self.B[:, observations[t + 1]] * beta[t + 1])[None, :])
            denom = num.sum()
            if denom > 0:
                xi[t] = num / denom

        return gamma, xi, log_likelihood

    def maximization_step(self, observations, gamma, xi):
        observations = self._validate_observations(observations)

        self.pi = gamma[0] / max(gamma[0].sum(), self.epsilon)

        A_new = xi.sum(axis=0) + self.epsilon
        A_new /= A_new.sum(axis=1, keepdims=True)
        self.A = A_new

        B_new = np.zeros((self.n_states, self.n_observations))
        for state in range(self.n_states):
            for observation in range(self.n_observations):
                mask = (observations == observation)
                B_new[state, observation] = gamma[mask, state].sum()
        B_new += self.epsilon
        B_new /= B_new.sum(axis=1, keepdims=True)
        self.B = B_new

    def fit(self, observations, max_iter=100, tolerance=1e-5, verbose=True):
        observations = self._validate_observations(observations)
        history = []
        prev_ll = -np.inf

        for it in range(1, max_iter + 1):
            gamma, xi, log_likelihood = self.expectation_step(observations)
            self.maximization_step(observations, gamma, xi)
            history.append({"iteration": it,
                            "log_likelihood": float(log_likelihood)})

            if verbose and (it <= 10 or it % 10 == 0 or it == max_iter):
                print(f"[TRAIN] iteration={it:03d}, "
                      f"log_likelihood={log_likelihood:.6f}")

            if abs(log_likelihood - prev_ll) < tolerance:
                if verbose:
                    print(f"[TRAIN] converged at iteration {it}")
                break
            prev_ll = log_likelihood

        return history


# ---------------------------------------------------------------------------
# Observation generation — HONEST version
# ---------------------------------------------------------------------------

def generate_observation_sequence(schedule, seed=DEFAULT_SEED):
    """
    Produce a sequence of observations v_t using the fixed simulator.
    The observation is derived ONLY from sync-bit BER at the receiver.
    """
    rng = random.Random(seed)
    storage_ch = StorageChannel()
    timing_ch = TimingChannel()
    dummy_payload = "0" * DEFAULT_CHUNK_SIZE

    observations = []
    for true_state in schedule:
        tx_storage = SYNC_PATTERN + dummy_payload
        tx_timing  = SYNC_PATTERN + dummy_payload

        storage_pkts  = storage_ch.embed_in_ip_id(tx_storage)
        timing_delays = timing_ch.encode_ipds(tx_timing)

        warden = SimulatedWarden(true_state=true_state)
        rx_pkts, rx_delays = warden.process_traffic(
            storage_pkts, timing_delays, rng=rng)

        rx_storage = storage_ch.extract_from_ip_id(rx_pkts)
        rx_timing  = timing_ch.decode_ipds(rx_delays)

        obs, _ = measure_observation(
            tx_storage[:SYNC_LEN], rx_storage[:SYNC_LEN],
            tx_timing[:SYNC_LEN],  rx_timing[:SYNC_LEN])
        observations.append(int(obs))

    return observations


def build_training_schedule(n_epochs=2000, seed=DEFAULT_SEED):
    """Warden schedule with realistic state persistence (70% stickiness)."""
    rng = random.Random(seed)
    schedule = [0]
    for _ in range(n_epochs - 1):
        if rng.random() < 0.70:
            schedule.append(schedule[-1])
        else:
            choices = [0, 1, 2]
            choices.remove(schedule[-1])
            schedule.append(rng.choice(choices))
    return schedule


# ---------------------------------------------------------------------------
# State alignment
# ---------------------------------------------------------------------------

def align_states(model_A, model_B, model_pi):
    """Sort states by expected observation index (0 lowest, 2 highest)."""
    expected_v = model_B @ np.array([0, 1, 2])
    order = np.argsort(expected_v)
    return (model_A[np.ix_(order, order)],
            model_B[order],
            model_pi[order])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print(" BAUM-WELCH TRAINING WITH HONEST OBSERVATIONS")
    print("=" * 72)

    # 1. Build a long, transition-rich warden schedule
    schedule = build_training_schedule(n_epochs=2000, seed=DEFAULT_SEED)
    state_counts = Counter(schedule)
    print(f"[DATA] schedule length = {len(schedule)}")
    print(f"[DATA] state distribution = {dict(state_counts)}")

    # 2. Generate honest observations using the fixed simulator
    observations = generate_observation_sequence(schedule, seed=DEFAULT_SEED)
    obs_counts = Counter(observations)
    print(f"[DATA] observation distribution = {dict(obs_counts)}")

    # 3. Report empirical emission matrix B_hat
    emp_B = np.zeros((N_STATES, N_OBSERVATIONS))
    for s, v in zip(schedule, observations):
        emp_B[s, v] += 1
    emp_B /= emp_B.sum(axis=1, keepdims=True)
    print("[DATA] empirical emission B_hat (rows = true state):")
    for s in range(N_STATES):
        print(f"       S{s}: " + "  ".join(f"{x:.3f}" for x in emp_B[s]))

    # 4. Train Baum-Welch
    print("\n[TRAIN] starting Baum-Welch EM ...")
    hmm = BaumWelchHMM(seed=DEFAULT_SEED)
    history = hmm.fit(observations, max_iter=200, tolerance=1e-6)

    # 5. Align states
    A_aligned, B_aligned, pi_aligned = align_states(hmm.A, hmm.B, hmm.pi)

    print("\n=== ALIGNED LEARNED MODEL ===")
    print("A =")
    print(np.round(A_aligned, 6))
    print("B =")
    print(np.round(B_aligned, 6))
    print("pi =", np.round(pi_aligned, 6))

    # 6. Persist artifacts
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    model = {
        "A": A_aligned.tolist(),
        "B": B_aligned.tolist(),
        "pi": pi_aligned.tolist(),
        "last_log_likelihood": history[-1]["log_likelihood"],
        "training_history": history,
        "training_data_summary": {
            "schedule_length": len(schedule),
            "state_distribution": dict(state_counts),
            "observation_distribution": dict(obs_counts),
            "empirical_B": emp_B.tolist(),
        },
        "state_alignment": {
            "state_0": "clean / observation 0",
            "state_1": "degraded / observation 1",
            "state_2": "scrubbing / observation 2",
        },
    }

    with open(MODEL_PATH, "w") as f:
        json.dump(model, f, indent=2)
    print(f"\n[SAVE] wrote model to {MODEL_PATH}")

    with open(METRICS_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["iteration", "log_likelihood"])
        for row in history:
            writer.writerow([row["iteration"], row["log_likelihood"]])
    print(f"[SAVE] wrote training history to {METRICS_PATH}")


if __name__ == "__main__":
    main()