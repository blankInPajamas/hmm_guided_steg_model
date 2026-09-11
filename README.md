# HMM-Guided Hybrid Network Steganography

An adaptive, closed-loop covert communication research prototype that combines Layer 3/4 storage channels with Layer 4 timing channels and uses a Hidden Markov Model (HMM) to adapt payload allocation in response to inferred network-warden activity.

> **Research and simulation notice:** This repository is intended for authorized laboratory experimentation, simulation, and defensive network research. Do not deploy covert channels on networks or systems without explicit permission.

## Overview

The protocol combines two complementary carriers:

- **Storage channel:** Embeds bits in a Layer 3/4 header field such as the IPv4 Identification field using parity or modulus mapping.
- **Timing channel:** Encodes bits by modulating inter-packet delays (IPDs).

The HMM controller models the active warden's hidden vigilance state and updates its belief from feedback observations:

| Hidden state | Meaning | Observation signal |
|---|---|---|
| `S0` | Low vigilance / clean traffic | `v0` — clean |
| `S1` | Inspection / degraded traffic | `v1` — degraded or jittered |
| `S2` | Active scrubbing | `v2` — active interference |

The controller allocates the payload using:

\[
\alpha_t = \sum_i \gamma_t(i)\alpha_i,
\qquad
\beta_t = 1 - \alpha_t
\]

where \(\alpha_t\) is the storage allocation, \(\beta_t\) is the timing allocation, and \(\gamma_t(i)\) is the current posterior probability of state \(i\).

## Key Features

- **Hybrid carrier architecture:** Combines high-capacity header storage with timing-based resilience.
- **Closed-loop Bayesian control:** Uses online HMM filtering to infer changing warden conditions.
- **Autonomous parameter learning:** Uses Baum-Welch expectation-maximization to estimate transition and emission probabilities from unlabeled observations.
- **Continuous ratio allocation:** Converts posterior state beliefs into smooth storage/timing ratios rather than discrete strategy jumps.
- **Noisy-feedback evaluation:** Tests performance under degraded or lossy observation conditions.
- **Factorial benchmark suite:** Evaluates three transition profiles, three emission profiles, and three ratio strategies across five dynamic attack scenarios.

## Repository Structure

```text
.
├── hmm_engine.py          # Online HMM controller and Bayesian forward filtering
├── splitter.py            # Adaptive binary payload partitioner
├── channels.py            # Storage and timing channel encoders/decoders
├── simulator.py           # Simulated active-warden test harness
├── sweep_exp.py           # 3 x 3 x 3 factorial sweep over 135 runs
├── sweep_results.csv      # Sweep output dataset, when generated
├── baum_welch.py          # Baum-Welch trainer and continuous-ratio evaluator
├── baum_welch_02.py       # Aligned/optimized Baum-Welch evaluation pipeline
├── context.md             # System formalization and research background
├── README.md              # Project documentation
└── requirements.txt       # Python dependencies
```

## System Architecture

### 1. Payload preparation

`splitter.py` converts a text payload to a binary stream and partitions each epoch's bits according to the controller's storage/timing allocation.

### 2. Channel encoding

`channels.py` provides two carriers:

- `StorageChannel`: Encodes bits in the parity of an IP Identification-like field.
- `TimingChannel`: Encodes `0` and `1` using a base IPD and an extended IPD, then decodes received delays using a threshold.

### 3. Warden simulation

`simulator.py` models three threat states:

- Low vigilance: minimal storage corruption and low timing jitter.
- Medium vigilance: moderate storage corruption and jitter.
- High vigilance: aggressive storage-field scrubbing and high timing jitter.

The simulator returns an observation code that closes the feedback loop.

### 4. HMM control

`hmm_engine.py` maintains \(A\), \(B\), and \(\pi\), updates the state belief using the Bayesian forward algorithm, and computes an expected storage/timing allocation.

### 5. Autonomous learning

`baum_welch.py` and `baum_welch_02.py` learn HMM parameters from observation sequences using scaled forward/backward passes, Baum-Welch EM, emission floors, convergence checks, and state-label alignment.

## Experimental Design

### Factorial sweep

The baseline sweep evaluates:

- `A1`–`A3`: Warden transition dynamics, from inertial to rapidly switching.
- `B1`–`B3`: Feedback-emission profiles, from high-fidelity to noisy.
- `M1`–`M3`: State-to-ratio strategies, from resilience-priority to throughput-priority.

Each combination is evaluated across five scenarios:

1. `baseline_multistage`: Low vigilance → active scrubbing → medium recovery.
2. `sudden_attack`: Extended clean period followed by abrupt high scrubbing.
3. `bursty_attack`: Repeated low/high vigilance bursts.
4. `prolonged_high_recovery`: Sustained high scrubbing followed by recovery.
5. `medium_dominated`: Mostly medium vigilance with low/high spikes.

This produces:

\[
5\text{ scenarios} \times 3\text{ transition profiles} \times 3\text{ emission profiles} \times 3\text{ strategies} = 135\text{ runs}
\]

### Metrics

The experiments record:

- Overall bit error rate (BER).
- Goodput in bits per epoch.
- State inference accuracy.
- Storage-channel errors.
- Timing-channel errors.
- Mean storage/timing allocation.
- Adaptation error and inferred-state traces where supported.

## Reported Results

### Phase 1: Factorial sweep baseline

The reported baseline findings are:

- Linear (`M2`) and aggressive fallback (`M1`) strategies produced the strongest BER results under active scrubbing by shifting most payload into timing delays.
- Throughput-priority (`M3`) produced higher BER because it retained more traffic in the vulnerable storage channel during active scrubbing.
- Increasing feedback noise from `B1` to `B3` caused only a modest BER increase in the reported simulation.
- Warden-transition volatility had limited effect on aggregate state-inference accuracy in the reported runs.

Exact values should be regenerated from the committed output CSV rather than treated as universal performance guarantees.

### Phase 2: Baum-Welch learning

The learned-HMM pipeline:

1. Collects unlabeled observation sequences.
2. Initializes a non-zero three-state HMM.
3. Runs scaled forward and backward algorithms.
4. Performs Baum-Welch E/M iterations.
5. Applies an emission probability floor.
6. Re-aligns state labels so that the dominant emissions correspond to clean, degraded, and scrubbing states.
7. Evaluates continuous ratio allocation across the five scenarios.

The reported aligned evaluation achieved high state-inference accuracy on the primary profiles and improved resilience in the prolonged-scrubbing scenario. These figures are simulation-specific and should be verified against `learned_hmm_output_02/learned_hmm_metrics.csv`.

## Installation

Use Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate the environment:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

A minimal `requirements.txt` is:

```text
numpy>=1.24
```

If packet-level experiments are added later, Scapy and the selected testbed tools should be listed separately and installed only for authorized lab use.

## Quick Start

### Run the factorial sweep

```bash
python sweep_exp.py
```

Expected output includes per-run BER and goodput logs. The sweep results are written to the configured CSV output path, commonly:

```text
sweep_results.csv
```

### Run Baum-Welch training

```bash
python baum_welch_02.py
```

Expected outputs:

```text
learned_hmm_output_02/
├── learned_hmm_metrics.csv
└── learned_hmm_model.json
```

The JSON file stores the learned matrices, initial distribution, training history, and alignment metadata.

## Interpreting Results

When comparing configurations, use BER and goodput together:

- A lower BER indicates stronger payload integrity.
- Higher goodput indicates more correctly delivered bits per epoch.
- State accuracy measures whether the inferred HMM state matches the simulator's hidden state.
- Storage and timing error counts reveal which carrier dominates failures.
- Mean allocation ratios show whether the controller actually moves traffic toward timing during scrubbing.

Avoid comparing results across runs unless the random seed, payload, schedule, chunk size, and simulator parameters are held constant.

## Limitations

- The current prototype uses synthetic simulator behavior rather than real packet traces.
- Header parity and IPD modulation are simplified abstractions, not production packet implementations.
- Baum-Welch states are statistically identifiable only up to permutation; alignment is required before semantic interpretation.
- Randomized scrubbing and jitter require fixed seeds for reproducible comparisons.
- Simulated BER and goodput do not establish performance on real networks.
- Timing-channel results depend strongly on the delay gap, receiver threshold, scheduler behavior, and network noise.

## Roadmap

- [x] Algorithmic verification and factorial sweeps.
- [x] Baum-Welch parameter learning and continuous allocation.
- [x] State-permutation alignment and post-alignment evaluation.
- [ ] Authorized packet-engineering testbed using Scapy.
- [ ] Real cover-traffic and PCAP parsing.
- [ ] Mininet or equivalent virtual topology experiments.
- [ ] Steganalysis using entropy, KL divergence, and KS tests.
- [ ] Statistical confidence intervals and repeated-seed evaluation.
- [ ] Comparison against static-ratio and non-adaptive baselines.

