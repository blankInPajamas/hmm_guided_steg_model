import os
import json
import glob
import numpy as np
import matplotlib.pyplot as plt
from scipy import stats
from sklearn.mixture import GaussianMixture
from scapy.all import PcapReader, IP, TCP, UDP


class Calibrator:
    def __init__(self, pcap_dir=None):
        """
        :param pcap_dir: Path to directory containing .pcap files or a single .pcap file
        """
        if isinstance(pcap_dir, str):
            if os.path.isdir(pcap_dir):
                self.pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap")) + glob.glob(os.path.join(pcap_dir, "*.pcap.gz"))
            elif os.path.isfile(pcap_dir):
                self.pcap_files = [pcap_dir]
            else:
                self.pcap_files = []
        elif isinstance(pcap_dir, list):
            self.pcap_files = pcap_dir
        else:
            self.pcap_files = []

        self.timestamps = []
        self.ipds = np.array([])
        self.gmm = None
        self.stats = {}

    def extraction(self):
        """Extracts arrival timestamps for IP/TCP and IP/UDP transport flows."""
        if not self.pcap_files:
            print("No valid PCAP files provided.")
            return

        print(f"Extracting packet timestamps from {len(self.pcap_files)} file(s)...")

        for pcap_path in self.pcap_files:
            try:
                # Use PcapReader to stream packets without consuming excess RAM
                with PcapReader(pcap_path) as reader:
                    for pkt in reader:
                        # Filter active transport flows (IP/TCP or IP/UDP)
                        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                            self.timestamps.append(float(pkt.time))
            except Exception as e:
                print(f"Error processing {pcap_path}: {e}")

        # Ensure timestamps are sorted chronologically
        self.timestamps.sort()
        print(f"Extracted {len(self.timestamps)} transport flow packets.")

    def compute_ipd(self, max_idle_gap=2.0):
        """
        Computes Inter-Packet Delays (IPD) and filters non-operational long idle gaps.
        :param max_idle_gap: Maximum threshold in seconds to consider active transmission jitter.
        """
        if len(self.timestamps) < 2:
            print("Insufficient packets to calculate IPDs.")
            return

        ts_array = np.array(self.timestamps)
        # Delta t_i = t_i - t_{i-1}
        raw_ipds = np.diff(ts_array)

        # Filter out negative delta (out of order timestamps) and idle gaps > max_idle_gap
        valid_mask = (raw_ipds > 0) & (raw_ipds <= max_idle_gap)
        self.ipds = raw_ipds[valid_mask]

        print(f"Calculated {len(self.ipds)} valid IPDs after filtering idle gaps > {max_idle_gap}s.")

    def distribution_fitting(self, n_components=3):
        """Fits a 3-component Gaussian Mixture Model (GMM) and calculates summary statistics."""
        if len(self.ipds) == 0:
            print("No IPD data available for fitting.")
            return

        # Scikit-learn expects 2D array input shape (n_samples, n_features)
        ipd_data = self.ipds.reshape(-1, 1)

        # Fit Gaussian Mixture Model
        self.gmm = GaussianMixture(n_components=n_components, random_state=42)
        self.gmm.fit(ipd_data)

        # Calculate summary statistics
        self.stats = {
            "mean": float(np.mean(self.ipds)),
            "std_dev": float(np.std(self.ipds)),
            "median": float(np.median(self.ipds)),
            "p95_delay": float(np.percentile(self.ipds, 95)),
            "count": int(len(self.ipds))
        }

    def generate_artifacts(self, json_path="results/mawi_ipd/mawi_ipd_profile.json", plot_path="results/mawi_ipd/mawi_ipd_distribution.png"):
        """Generates mawi_ipd_profile.json and mawi_ipd_distribution.png."""
        if self.gmm is None or len(self.ipds) == 0:
            print("Fit distribution before generating output artifacts.")
            return

        # Ensure destination directory exists before writing files
        output_dir = os.path.dirname(json_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        plot_dir = os.path.dirname(plot_path)
        if plot_dir:
            os.makedirs(plot_dir, exist_ok=True)

        # Calculate empirical histogram bin edges
        counts, bin_edges = np.histogram(self.ipds, bins=50, density=True)

        # 1. Output Artifact: mawi_ipd_profile.json
        profile_data = {
            "summary_statistics": self.stats,
            "gmm_profile": {
                "n_components": int(self.gmm.n_components),
                "weights": self.gmm.weights_.tolist(),
                "means": self.gmm.means_.flatten().tolist(),
                "covariances": self.gmm.covariances_.flatten().tolist()
            },
            "empirical_bin_edges": bin_edges.tolist()
        }

        with open(json_path, "w") as f:
            json.dump(profile_data, f, indent=4)
        print(f"Profile saved to {json_path}")

        # 2. Output Artifact: mawi_ipd_distribution.png
        plt.figure(figsize=(10, 6))

        # Empirical histogram
        plt.hist(self.ipds, bins=50, density=True, alpha=0.6, color="skyblue", edgecolor="black", label="Empirical IPD")

        # Fitted GMM curve grid
        x_grid = np.linspace(min(self.ipds), max(self.ipds), 1000).reshape(-1, 1)
        # Log probability converted to density via exp
        log_prob = self.gmm.score_samples(x_grid)
        pdf = np.exp(log_prob)

        plt.plot(x_grid, pdf, "r-", linewidth=2, label="Fitted GMM Curve")

        plt.title("MAWI Inter-Packet Delay (IPD) Distribution & GMM Fit")
        plt.xlabel("Inter-Packet Delay (seconds)")
        plt.ylabel("Density")
        plt.grid(True, linestyle="--", alpha=0.5)
        plt.legend()

        plt.savefig(plot_path, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"Distribution plot saved to {plot_path}")


# --- Execution Example ---
if __name__ == "__main__":
    # Point this to your directory containing MAWI .pcap files
    pcap_dir_path = "./dataset/mawi/"

    calibrator = Calibrator(pcap_dir=pcap_dir_path)
    calibrator.extraction()
    calibrator.compute_ipd(max_idle_gap=2.0)
    calibrator.distribution_fitting(n_components=3)
    calibrator.generate_artifacts()