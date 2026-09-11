import numpy as np

class HMMEngine:
    '''
    States:
        0: Low Vigilance
        1: Medium Vigilance
        2: High Vigilance

    Observations:
        0: Clean Network
        1: Degraded Traffic
        2: Active Interference
    '''

    def __init__(self, A=None, B=None, pi=None):
        self.A = A if A is not None else np.array([
            [0.85, 0.10, 0.05],
            [0.15, 0.70, 0.15],
            [0.05, 0.25, 0.70]
        ])

        self.B = B if B is not None else np.array([
            [0.90, 0.08, 0.02],
            [0.20, 0.60, 0.20],
            [0.05, 0.25, 0.70]
        ])

        self.pi = pi if pi is not None else np.array([0.80, 0.15, 0.05])
        self.current_belief = self.pi.copy()

        self.ratio_map = {
            0: (0.85, 0.15),
            1: (0.50, 0.50),
            2: (0.10, 0.95)
        }

    def update_belief(self, obs: int):
        """
        Bayesian Forward Algorithm update for real-time belief state:
        alpha_t(j) = P(v_t | s_j) * sum_i ( alpha_{t-1}(i) * A_{ij} )
        """
        prior = np.dot(self.current_belief, self.A)
        likelihood = self.B[:, obs]
        unnormalized_posterior = prior * likelihood
        
        # Normalize to form probability distribution
        total = np.sum(unnormalized_posterior)
        if total > 0:
            self.current_belief = unnormalized_posterior / total
        else:
            self.current_belief = prior / np.sum(prior)
            
        return self.current_belief

    def get_allocation_ratio(self):
        """
        Computes expected allocation ratio (alpha_storage, beta_timing)
        weighted by the current state belief probabilities.
        """
        alpha_expected = sum(self.current_belief[s] * self.ratio_map[s][0] for s in range(3))
        beta_expected = sum(self.current_belief[s] * self.ratio_map[s][1] for s in range(3))
        
        total = alpha_expected + beta_expected
        return alpha_expected / total, beta_expected / total

    def get_most_likely_state(self):
        return int(np.argmax(self.current_belief))