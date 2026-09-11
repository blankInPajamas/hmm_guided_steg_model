# HMM-Guided Hybrid Network Steganography

## Overview
**HMM-Guided Hybrid Network Steganography** is an adaptive, closed-loop covert communication framework designed to outmaneuver active network wardens in real time. By combining high-bandwidth **Layer 3/4 storage channels** (e.g., IPv4 IP ID field parity) with high-resilience **Layer 4 timing channels** (Inter-Packet Delay modulation), the protocol dynamically balances transmission capacity and active attack resilience.

At the core of the system is a **Hidden Markov Model (HMM)** decision controller. Driven by the Bayesian Forward Algorithm, the sender infers the unobservable threat state of an active network warden ($S_0$: Low Vigilance, $S_1$: Inspection, $S_2$: Active Scrubbing) using real-time feedback signals ($v_0, v_1, v_2$). It then continuously adjusts its payload allocation ratio ($\alpha$ storage / $\beta$ timing) to maximize throughput during low-threat windows while shielding secret data inside timing delays during active field-scrubbing attacks.

---

## Key Features

* **Hybrid Carrier Architecture**: Blends Layer 3/4 header field embedding for speed with Layer 4 Inter-Packet Delay (IPD) modulation for active attack resistance.
* **Cognitive Warden Evasion**: Uses a closed-loop Bayesian controller to infer hidden warden vigilance states and adapt payload splits dynamically without hardcoded rules.
* **Robust Feedback Mechanism**: Operates effectively even under noisy or lossy reverse feedback channels, maintaining low Bit Error Rates (BER) across fluctuating network environments.
* **Factorial Simulation & Benchmark Suite**: Includes a $3 \times 3 \times 3$ factorial parameter sweep framework evaluating controller stability across diverse warden transition dynamics ($A$), feedback noise profiles ($B$), and ratio mapping curves ($M$).

---

## Project Roadmap
1. **Algorithmic Verification (Completed)**: Functional prototype and 27-permutation factorial parameter sweep validation in Python.
2. **Autonomous Parameter Learning (In Progress)**: Unsupervised Expectation-Maximization (Baum-Welch algorithm) to train HMM transition and emission matrices directly from network observation logs.
3. **Empirical Testbed & Packet Engineering (Next Phase)**: `Scapy`-based packet crafting, real `.pcap` cover traffic trace parsing, and virtual network topology execution in `Mininet`.
4. **Stegananalysis & Benchmarking**: Statistical evaluation against passive detectors using Shannon Entropy, Kullback-Leibler (KL) divergence, and Kolmogorov-Smirnov (KS) tests.

---