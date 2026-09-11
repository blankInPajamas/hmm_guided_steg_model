# Context & Progress Report: HMM-Guided Hybrid Network Steganography

## 1. Project Overview & Research Objective
This research project focuses on the design, mathematical formalization, and empirical evaluation of an **HMM-Guided Hybrid Network Steganography Model**. The primary goal is to build an adaptive, cognitive covert communication system that dynamically balances payload allocation between a **Layer 3/4 Storage Channel** (high capacity, vulnerable to active packet scrubbing) and a **Layer 4 Timing Channel** (lower bandwidth, highly resilient against field scrubbing) based on real-time feedback regarding the network warden's active threat level.

---

## 2. Literature Background & Research Gap

### Core Literature Insights
- **Hybrid Network Covert Channels**: Combining storage and timing channels has been established as an effective method to increase overall capacity while complicating single-channel detection mechanisms.
- **Passive HMM Timing Mimicry**: Existing steganographic literature (e.g., *Protocol Proxy*) utilizes Hidden Markov Models (HMMs) primarily in a passive role—modeling benign inter-packet delay (IPD) distributions so that timing channels mimic natural traffic patterns to evade side-channel analysis.
- **AI/Cognitive Evolution**: Modern state-of-the-art frameworks explore proactive, knowledge-driven multi-agent coordination across storage and timing channels to adapt to network dynamics.

### Identified Research Gap & Novelty
- **The Gap**: Previous hybrid steganography implementations either relied on static split ratios, basic deterministic threshold rules for feedback adaptation, or complex multi-agent architectures with significant computational overhead. Furthermore, HMMs were traditionally restricted to passive traffic shaping rather than active decision-making.
- **Our Novel Approach**: This project introduces an **HMM as an active cognitive decision controller**. The sender models the *hidden vigilance or threat states of an active warden* using an HMM, continuously updating its posterior belief distribution via real-time feedback signals from the receiver. The controller then dynamically adjusts the payload allocation ratio ($\alpha$ storage / $\beta$ timing) using the Bayesian Forward algorithm to outmaneuver active wardens while maximizing clean-window throughput.

---

## 3. System Architecture & Model Formalization

### Protocol Stack Selection
- **Layer 3 (Network Layer - IPv4/IPv6)**: Utilized for the **Storage Channel** by embedding secret bits into protocol fields such as IPv4 Identification (IP ID) headers using parity/modulus mapping schemes.
- **Layer 4 (Transport Layer - TCP/UDP)**: Utilized for the **Timing Channel** by modulating Inter-Packet Delays (IPDs) between outgoing packets ($t_0$ for bit `0`, $t_0 + \Delta t$ for bit `1`).

### Mathematical Formalization of the HMM Controller
The controller is formalized by the tuple $\lambda = (A, B, \pi)$:
1. **Hidden States ($S$) — Warden Threat Levels**:
   - $S_0$: Low Vigilance / Passive Warden (routine routing, minimal inspection).
   - $S_1$: Medium Vigilance / Statistical Inspection (entropy or timing distribution checks).
   - $S_2$: High Vigilance / Active Scrubbing (active header field corruption or delay jitter).
2. **Observations ($V$) — Feedback Signals**:
   - $v_0$: Clean Network (low loss, intact header fields).
   - $v_1$: Degraded Traffic (minor retransmissions, slight timing jitter).
   - $v_2$: Active Interference (heavy field scrubbing, high error feedback).
3. **Transition Matrix ($A$) & Emission Matrix ($B$)**:
   - $A_{ij} = P(S_t = s_j \mid S_{t-1} = s_i)$: Probabilities governing warden vigilance state shifts.
   - $B_{jk} = P(v_t = v_k \mid S_t = s_j)$: Likelihood of observing feedback signal $v_k$ given hidden threat state $s_j$.
4. **Closed-Loop Forward Update**:
   - Updates state belief probabilities in real-time upon receiving observation $v_t$:
     $$\alpha_t(j) = P(v_t \mid s_j) \sum_i \alpha_{t-1}(i) A_{ij}$$
5. **State-to-Ratio Mapping**:
   - Maps state posteriors to expected allocation ratios $(\alpha, \beta)$ where $\alpha$ represents storage percentage and $\beta$ represents timing percentage.

---

## 4. Implementation Phases & Algorithmic Proof-of-Concept

### Core Software Architecture
The Python prototype consists of four modular components:
1. `hmm_engine.py`: Implements the Bayesian Forward algorithm to maintain belief states and calculate expected split ratios.
2. `splitter.py`: Converts text payloads to binary streams and divides bits into storage and timing queues based on allocated ratios.
3. `channels.py`: Implements L3/L4 header storage embedding (IP ID parity) and L4 timing modulation (IPD intervals).
4. `simulator.py`: Manages the transmission loop, simulates active warden behaviors (scrubbing/jitter), and returns observation feedback.

### Preliminary Closed-Loop Verification
- **Initial 2-Epoch Test**: Verified the core closed-loop feedback mechanism. Upon encountering active inspection in Epoch 1, the receiver's feedback observation ($v_1$) prompted the HMM to update its belief state and shift payload weight into the timing channel in Epoch 2, successfully stabilizing transmission.
- **10-Epoch Dynamic Schedule Run**: Evaluated the system under a multi-stage attack schedule (Low Threat $\rightarrow$ Active Scrubbing $\rightarrow$ De-escalation). Confirmed that the controller experiences a brief transient spike upon an unannounced attack, rapidly adapts within 1–2 epochs by shifting up to 84% of payload to timing delays, and automatically recovers storage throughput once the threat subsides.

---

## 5. Overview of the Factorial Parameter Sweep Experiment
To rigorously evaluate the HMM controller prior to live packet-level deployment, a **$3 \times 3 \times 3$ Factorial Parameter Sweep Experiment** (`sweep_experiment.py`) was designed.

### Objectives & Design
The sweep framework systematically tests all 27 permutations across three critical dimension variables:
1. **Transition Matrices ($A_1, A_2, A_3$)**: Evaluates controller performance across diverse warden behavior profiles, ranging from slow-switching (inertial) wardens to rapidly switching, bursty, and uniform random threat environments.
2. **Emission Matrices ($B_1, B_2, B_3$)**: Assesses sensitivity and robustness against varying levels of feedback channel noise (from clean, high-fidelity feedback to highly lossy/noisy feedback signals).
3. **Ratio Allocation Strategies ($M_1, M_2, M_3$)**: Compares different state-to-ratio mapping curves, including aggressive fallback (resilience priority), standard linear transitions, and throughput-priority mappings.

The sweep harness runs each parameter combination over extended multi-epoch dynamic attack schedules to evaluate Bit Error Rate (BER), overall goodput, and adaptation sensitivity under diverse environmental conditions.
