import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set clean publication theme
sns.set_theme(style="whitegrid", palette="colorblind")

# Handle directory paths (Fallback to hmm_scapy_bridge if mininet folder doesn't exist)
csv_dir = "results/mininet" if os.path.exists("results/mininet") else "results/hmm_scapy_bridge"
out_dir = "results/plots"
os.makedirs(out_dir, exist_ok=True)

scheme_files = {
    "HMM Adaptive Hybrid (Proposed)": "scapy_hmm_results.csv",
    "Static Pure Storage (alpha=1.0)": "pure_alpha.csv",
    "Static Pure Timing (alpha=0.0)": "pure_beta.csv",
    "Fixed 50/50 Hybrid (alpha=0.5)": "split_alpha_beta.csv"
}

summary_rows = []

# 1. Process each CSV file and compute metrics
for scheme, filename in scheme_files.items():
    filepath = os.path.join(csv_dir, filename)
    if not os.path.exists(filepath):
        print(f"[!] Warning: File {filepath} not found. Skipping...")
        continue
    
    df = pd.read_csv(filepath)
    
    total_sent = df["epoch_sent_bits"].sum()
    total_errors = df["storage_errors"].sum() + df["timing_errors"].sum()
    overall_ber = (total_errors / total_sent) * 100 if total_sent > 0 else 0.0
    
    # State 2 (Active Scrubbing) metrics
    df_state2 = df[df["true_warden_state"] == 2]
    s2_sent = df_state2["epoch_sent_bits"].sum()
    s2_errors = df_state2["storage_errors"].sum() + df_state2["timing_errors"].sum()
    s2_ber = (s2_errors / s2_sent) * 100 if s2_sent > 0 else 0.0
    
    avg_goodput = df["epoch_goodput_bits"].mean()
    
    summary_rows.append({
        "scheme": scheme,
        "overall_ber_pct": round(overall_ber, 2),
        "state2_ber_pct": round(s2_ber, 2),
        "avg_goodput_bits_epoch": round(avg_goodput, 2)
    })

df_summary = pd.DataFrame(summary_rows)
summary_csv = os.path.join(csv_dir, "baseline_comparison_summary.csv")
df_summary.to_csv(summary_csv, index=False)
print(f"[+] Computed baseline summary and saved to {summary_csv}")

# 2. Plot Figure 1: Epoch Adaptation Trace (from scapy_hmm_results.csv)
hmm_path = os.path.join(csv_dir, "scapy_hmm_results.csv")
if os.path.exists(hmm_path):
    df_hmm = pd.read_csv(hmm_path)
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
    
    # Subplot 1: Warden Threat vs Inferred State (Fixed raw strings r"...")
    ax1.plot(df_hmm["epoch"], df_hmm["true_warden_state"], "k--", linewidth=2, label=r"True Warden Threat ($S_t$)")
    ax1.plot(df_hmm["epoch"], df_hmm["inferred_state"], "b-o", linewidth=2, markersize=8, label=r"HMM Inferred State ($\hat{S}_t$)")
    ax1.set_ylabel("Threat State Level", fontsize=12)
    ax1.set_title("HMM Closed-Loop Warden Threat State Inference Across Epochs", fontsize=14, fontweight="bold")
    ax1.legend(loc="upper right", frameon=True)
    ax1.set_yticks([0, 1, 2])
    
    # Subplot 2: Dynamic Allocation Ratio (Fixed raw strings r"...")
    ax2.plot(df_hmm["epoch"], df_hmm["alpha_storage_ratio"], "r-s", linewidth=2, markersize=8, label=r"Storage Ratio ($\alpha_t$)")
    ax2.plot(df_hmm["epoch"], df_hmm["beta_timing_ratio"], "g-^", linewidth=2, markersize=8, label=r"Timing Ratio ($\beta_t$)")
    ax2.set_xlabel("Epoch", fontsize=12)
    ax2.set_ylabel("Allocation Ratio", fontsize=12)
    ax2.set_title(r"Dynamic Payload Allocation Ratio Adaptation ($\alpha_t$ vs $\beta_t$)", fontsize=14, fontweight="bold")
    ax2.legend(loc="center right", frameon=True)
    ax2.set_xticks(range(1, 13))
    
    sns.despine(fig=fig)
    plt.tight_layout(pad=1.5)
    plot1_path = os.path.join(out_dir, "epoch_adaptation_trace.png")
    plt.savefig(plot1_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved Figure 1: {plot1_path}")

# 3. Plot Figure 2: Comparative BER Across Schemes
if not df_summary.empty:
    fig, (ax_ber1, ax_ber2) = plt.subplots(1, 2, figsize=(14, 6))
    
    schemes_short = df_summary["scheme"].tolist()
    colors = sns.color_palette("colorblind", n_colors=len(schemes_short))
    
    # Overall BER
    bars1 = ax_ber1.bar(schemes_short, df_summary["overall_ber_pct"], color=colors)
    ax_ber1.set_title("Overall 12-Epoch Schedule BER (%)", fontsize=13, fontweight="bold")
    ax_ber1.set_ylabel("Bit Error Rate (%)", fontsize=12)
    ax_ber1.set_xticklabels(schemes_short, rotation=15, ha="right")
    ax_ber1.bar_label(bars1, fmt="%.2f%%", padding=3, fontweight="bold")
    
    # Active Scrubbing Phase BER (State 2)
    bars2 = ax_ber2.bar(schemes_short, df_summary["state2_ber_pct"], color=colors)
    ax_ber2.set_title("Active Scrubbing Phase BER (State 2)", fontsize=13, fontweight="bold")
    ax_ber2.set_ylabel("Bit Error Rate (%)", fontsize=12)
    ax_ber2.set_xticklabels(schemes_short, rotation=15, ha="right")
    ax_ber2.bar_label(bars2, fmt="%.2f%%", padding=3, fontweight="bold")
    
    sns.despine(fig=fig)
    plt.tight_layout(pad=1.5)
    plot2_path = os.path.join(out_dir, "ber_goodput_comparison.png")
    plt.savefig(plot2_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved Figure 2: {plot2_path}")