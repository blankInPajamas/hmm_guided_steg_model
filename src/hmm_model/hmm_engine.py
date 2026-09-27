"""
hmm_engine.py — Bayesian Forward belief filter for the HMM-guided
hybrid steganography controller.

States:
    0: Low vigilance (clean)
    1: Medium vigilance (degraded)
    2: High vigilance (scrubbing)

Observations:
    0: Clean network
    1: Degraded traffic
    2: Active interference
"""

import os
import json
import numpy as np


# Default path to the trained model, relative to project root.
# Override via HMMEngine(model_path=...) if you need a different one.
DEFAULT_MODEL_PATH = os.path.join(
    "results", "aligned_hmm_output", "learned_hmm_model.json")


# State -> (alpha_storage, beta_timing) allocation ratios.
# This mapping encodes the policy: state 0 => storage-heavy,
# state 2 => timing-heavy. Kept here so it is a single source of truth.
RATIO_MAP = {
    0: (0.80, 0.20),
    1: (0.50, 0.50),
    2: (0.20, 0.80),
}


class HMMEngine:
    def __init__(self, A=None, B=None, pi=None, model_path=None, use_uniform_prior=False):
        """
        Priority of sources:
          1. Explicit A/B/pi passed as arguments.
          2. A JSON model on disk at `model_path` (or DEFAULT_MODEL_PATH).
          3. Hard-coded defaults (with a warning).
        """
        self.ratio_map = dict(RATIO_MAP)


        if A is not None and B is not None and pi is not None:
            self.A = np.asarray(A, dtype=float)
            self.B = np.asarray(B, dtype=float)
            self.pi = np.asarray(pi, dtype=float)
            self.model_source = "explicit"
        else:
            path = model_path or DEFAULT_MODEL_PATH
            if os.path.exists(path):
                self._load_from_json(path)
                self.model_source = path
            else:
                print(f"[HMMEngine] WARNING: no model at {path!r}; "
                      f"using hard-coded defaults. Results will not reflect "
                      f"the trained controller.")
                self.A = np.array([
                    [0.85, 0.10, 0.05],
                    [0.15, 0.70, 0.15],
                    [0.05, 0.25, 0.70],
                ])
                self.B = np.array([
                    [0.90, 0.08, 0.02],
                    [0.20, 0.60, 0.20],
                    [0.05, 0.25, 0.70],
                ])
                self.pi = np.array([0.80, 0.15, 0.05])
                self.model_source = "hard-coded default"

        self.num_states = len(self.pi)
        self.num_obs = self.B.shape[1]
        
        if use_uniform_prior:
            self.current_belief = np.ones(self.num_states) / self.num_states
        else:
            self.current_belief = self.pi.copy()

        self.current_belief = self.pi.copy()

        print(f"[HMMEngine] loaded model from: {self.model_source}")
        print(f"[HMMEngine] pi = {np.round(self.pi, 4).tolist()}")
        print(f"[HMMEngine] B  = {np.round(self.B, 4).tolist()}")

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def _load_from_json(self, path):
        with open(path, "r") as f:
            data = json.load(f)
        self.A = np.array(data["A"], dtype=float)
        self.B = np.array(data["B"], dtype=float)
        self.pi = np.array(data["pi"], dtype=float)
        # Basic sanity checks so a broken JSON fails loudly.
        assert self.A.shape == (3, 3), f"A shape is {self.A.shape}, expected (3,3)"
        assert self.B.shape == (3, 3), f"B shape is {self.B.shape}, expected (3,3)"
        assert self.pi.shape == (3,), f"pi shape is {self.pi.shape}, expected (3,)"
        assert np.allclose(self.A.sum(axis=1), 1.0, atol=1e-6), \
            f"A rows must sum to 1; got {self.A.sum(axis=1)}"
        assert np.allclose(self.B.sum(axis=1), 1.0, atol=1e-6), \
            f"B rows must sum to 1; got {self.B.sum(axis=1)}"
        assert np.isclose(self.pi.sum(), 1.0, atol=1e-6), \
            f"pi must sum to 1; got {self.pi.sum()}"

    # ------------------------------------------------------------------
    # Belief update
    # ------------------------------------------------------------------
    def update_belief(self, obs: int):
        """
        Bayesian forward step:
            gamma_t(j) proportional to B[j, obs] * (gamma_{t-1} @ A)[j]
        """
        if not (0 <= obs < self.num_obs):
            raise ValueError(f"obs={obs} out of range [0, {self.num_obs})")

        prior = self.current_belief @ self.A
        likelihood = self.B[:, obs]
        unnormalized = prior * likelihood

        total = unnormalized.sum()
        if total > 0:
            self.current_belief = unnormalized / total
        else:
            # Degenerate case: fall back to the prior (uniform-ish).
            self.current_belief = prior / max(prior.sum(), 1e-12)

        return self.current_belief

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get_allocation_ratio(self):
        alpha = sum(self.current_belief[s] * self.ratio_map[s][0]
                    for s in range(self.num_states))
        beta = sum(self.current_belief[s] * self.ratio_map[s][1]
                   for s in range(self.num_states))
        total = alpha + beta
        return alpha / total, beta / total

    def get_most_likely_state(self):
        return int(np.argmax(self.current_belief))

    # Alias: some code refers to `hmm.gamma`; keep it in sync.
    @property
    def gamma(self):
        return self.current_belief

    @gamma.setter
    def gamma(self, value):
        self.current_belief = np.asarray(value, dtype=float)