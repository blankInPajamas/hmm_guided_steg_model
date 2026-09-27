# HMM-Guided Hybrid Network Steganography

An adaptive, closed-loop covert communication protocol that combines Layer 3/4
storage channels with Layer 4 timing channels, driven by an unsupervised
Hidden Markov Model (HMM) decision controller to evade active network wardens
in real time.

---

## Executive Overview

**HMM-Guided Hybrid Network Steganography** dynamically balances transmission
throughput and active-attack resilience. By pairing high-bandwidth **Layer 3/4
header storage channels** (IPv4 IP ID parity, TCP Sequence modulo, TCP
Timestamp LSB) with high-resilience **Layer 4 timing channels** (Inter-Packet
Delay modulation), the protocol adapts its payload split ratio
($\alpha_t$ storage / $\beta_t$ timing) according to real-time feedback
observations of warden vigilance
($v_0$: Low Threat, $v_1$: Degraded, $v_2$: Active Scrubbing).

---

## Current Status

This repository has just completed a **major correctness pass** followed by
**P0 (runtime prior override)**. Several critical bugs were found and fixed in
the physical-channel layer, the HMM controller, and the training pipeline.

**⚠️ All benchmark numbers in this README's "Result Benchmarks" section were
produced before the correctness pass and are now obsolete.** They are retained
only for diffing against regenerated results and should not be cited.

### Two silent bugs that invalidated prior results

1. **Ground-truth leakage in the observation signal.** The warden's hidden
   state was being injected into the observation `v_t`, making the HMM's
   inference task trivially easy and inflating reported accuracy to 94.44%.

2. **Type-mismatch in the sync-BER computation.** Comparing `int` sync bits
   against `str` extracted bits made the sync-BER evaluate to 1.0
   unconditionally, which in turn made every observation read as `v=2`.

Both bugs are fixed. The retrained HMM has a realistic (non-one-hot) emission
matrix. The simulated controller now genuinely has to infer warden state from
noisy evidence.

### What works now

- **`src/hmm_model/channels.py`** — storage and timing channels round-trip
  cleanly for both `str` and `list[int]` bit sequences. Type coercion is
  centralized in `_normalize_bits`.
- **`src/hmm_model/simulator.py`** — honest observation derivation via
  sync-bit BER (`measure_observation`). Ground-truth `warden.true_state` no
  longer leaks into the observation. One-epoch control lag is documented and
  intentional. Module-level `_HERE` bootstrap so bare imports resolve when
  imported as a package submodule.
- **`src/hmm_model/hmm_engine.py`** — loads the trained model from JSON at
  `results/aligned_hmm_output/learned_hmm_model.json`, with shape and row-sum
  validation. Supports a `use_uniform_prior` flag (P0) so the runtime belief
  vector does not inherit the training-set initial bias.
- **`experiments/aligned_baum_welch.py`** — retrains on honest observations
  using the fixed simulator. Prints the empirical emission matrix `B_hat`
  before training so the data can be verified as not leaked. Removed the
  legacy local `SimulatedWarden` class.
- **Retrained model** — the current
  `results/aligned_hmm_output/learned_hmm_model.json` has realistic
  off-diagonal emission probabilities instead of the previous one-hot matrix.
- **Makefile** — detects `Windows_NT` and uses `venv/Scripts/python.exe`.
- **P0 (runtime prior override)** — `HMMEngine(use_uniform_prior=True)`
  gives a uniform initial belief vector, decoupling the controller from the
  training-set state distribution.

### What is still broken or unverified

- **`src/phase3/hmm_scapy_bridge.py` still leaks ground truth.** Its
  `adapt_warden_for_scapy` computes `obs` from `warden.true_state`. It also
  does not actually transmit packets — it builds Scapy packet objects, passes
  them to an in-process warden, then extracts. No socket, no `send()`, no
  `sniff()`. This is the largest remaining piece of work (P1).
- **`src/mininet/live_warden.py` bypasses `netem`.** It uses `sendp` to write
  frames directly to the interface, which skips the kernel's qdisc. The
  `tc netem` delay/jitter claimed in the testbed description is not actually
  applied to forwarded packets (P2).
- **Timing channel SNR under state-2 jitter.** With `delta_t = 0.10` and
  warden jitter `σ = 0.04`, the effective z-score is roughly 1.25, giving a
  per-bit timing BER of ~10%. Workable but not impressive (P3).
- **One-epoch control lag on sudden state transitions.** When the warden
  jumps from state 0 to state 2 between epochs, the controller's allocation
  for the new epoch is decided using the previous epoch's belief. The first
  epoch of a sudden attack incurs a BER spike. This is a **protocol property,
  not a bug** — it is bounded and characterized (P6 discusses mitigation).
- **All benchmark numbers in this README are pre-fix.** They will be
  regenerated after P1–P3 (see P4).

### Current simulator result (with P0)

`make simulate` on the 12-epoch schedule produces **9.11% overall BER**. This
is the honest number for a schedule with 8 state transitions across 12 epochs,
given the one-epoch control lag. Per-epoch behavior:

- Clean epochs (1, 2, 9, 10, 12): BER 0.00%.
- First epoch after a state change: elevated BER (10–31%) due to lag.
- Steady-state scrubbing epochs (5, 6): 15–17% BER (residual timing-channel
  errors).

This is a genuine property of the protocol, not a measurement artifact.
Longer schedules will amortize the transition cost over more steady-state
epochs, reducing the overall number.

### Reproducing the current state

```bash
# 1. Set up environment
make requirement

# 2. Clear stale bytecode caches (important after recent fixes)
find src experiments -type d -name __pycache__ -exec rm -rf {} +

# 3. Retrain the HMM on honest observations
make train

# 4. Run the in-process simulator
make simulate
```

Expected output of `make train`:

```
[IMPORT] simulator loaded from: .../src/hmm_model/simulator.py
========================================================================
 BAUM-WELCH TRAINING WITH HONEST OBSERVATIONS
========================================================================
[DATA] schedule length = 2000
[DATA] state distribution = {0: 709, 1: 665, 2: 626}
[DATA] observation distribution = {0: 725, 1: 649, 2: 626}
[DATA] empirical emission B_hat (rows = true state):
       S0: 1.000  0.000  0.000
       S1: 0.024  0.976  0.000
       S2: 0.000  0.000  1.000
[TRAIN] starting Baum-Welch EM ...
[TRAIN] iteration=200, log_likelihood=-1653.405023
```

Expected output of `make simulate`:

```
[HMMEngine] loaded model from: results\aligned_hmm_output\learned_hmm_model.json
[HMMEngine] pi = [1.0, 0.0, 0.0]
[HMMEngine] B  = [[0.9708, 0.0224, 0.0068], [0.0305, 0.9567, 0.0127], [0.0015, 0.0, 0.9985]]

[+] Payload size: 1136 bits (142 chars)
[+] Warden schedule: [0, 0, 1, 2, 2, 2, 1, 1, 0, 0, 2, 0]
[+] Sync length per channel per epoch: 128 bits

Ep   | True  | Infer  | alpha  | beta   | v   | stErr  | tmErr  | BER
...
[+] Overall BER: 9.11%
```

---

## Repository & Project Architecture

```text
.
├── context.md
├── docs
│   └── dataset.md
├── experiments
│   ├── aligned_baum_welch.py     # active training script (post-fix)
│   ├── baum_welch.py             # legacy; superseded by aligned_*
│   └── sweep_exp.py              # Phase 1 factorial sweeps
├── Makefile
├── publication_figure.py
├── README.md
├── requirements.txt
├── results
│   ├── aligned_hmm_output        # active trained model (post-fix)
│   │   ├── learned_hmm_metrics.csv
│   │   └── learned_hmm_model.json
│   ├── hmm_scapy_bridge          # bridge outputs (pre-fix; regenerate at P4)
│   ├── learned_hmm_output        # legacy (pre-fix; do not use)
│   ├── mawi_ipd                  # MAWI IPD profile (Phase 4)
│   ├── mininet                   # testbed logs (pre-fix)
│   ├── plots
│   ├── simulator_results
│   │   ├── res001.log            # SYNC_LEN=64 (pre-fix)
│   │   ├── res002.log            # SYNC_LEN=128 (pre-fix)
│   │   └── res003.log            # SYNC_LEN=256 (pre-fix)
│   ├── steganalysis_report
│   └── sweep_output
└── src
    ├── hmm_model
    │   ├── channels.py           # storage + timing channels (fixed)
    │   ├── hmm_engine.py         # Bayesian forward filter (fixed + P0)
    │   ├── simulator.py          # in-process closed-loop sim (fixed + P0)
    │   └── splitter.py           # payload splitter
    ├── mininet
    │   ├── live_warden.py        # active warden (P2: netem bypass)
    │   └── mininet_topo.py       # 3-node routed topology
    └── phase3
        ├── hmm_scapy_bridge.py   # HMM-driven Scapy transmission (P1: rewrite)
        ├── pcap_calibrator.py    # MAWI IPD → GMM fitting (Phase 4)
        ├── scapy_carrier.py      # physical Scapy channels (P3: SNR tuning)
        └── steganalysis_eval.py  # KL/KS/entropy evaluation (P4: regenerate)
```

---

## Correctness Pass: What Was Fixed

### 1. Physical channel type coercion (`channels.py`)

The original `StorageChannel.embed_in_ip_id` iterated over bits and did
`int(bit)`, which silently worked for `str` bits but produced unpredictable
behavior when mixed with `int` bits. Both channels now normalize inputs via
`_normalize_bits`, which accepts any iterable of `0`/`1` (int, str, or bytes)
and raises on invalid characters.

### 2. Sync pattern type (`simulator.py`)

`SYNC_PATTERN` was previously a list of ints (`[0, 1, 0, 1, ...]`). When
compared against the channel-native `str` extracted bits, every comparison
returned `True`, which made the sync-BER equal to 1.0 unconditionally.
`SYNC_PATTERN` is now a `str`, and the `_ber` helper in `measure_observation`
normalizes both arguments to `str` before comparing.

### 3. Ground-truth leak removal (`simulator.py`)

`SimulatedWarden.process_traffic` no longer returns an observation. It
returns only corrupted packets and delayed IPDs. The observation is computed
separately in `measure_observation`, which reads sync-bit BER from the
received packets and IPDs. The warden's `true_state` is used only to drive
its own behavior, never to inform the receiver.

### 4. Windows Makefile (`Makefile`)

The Makefile now detects `Windows_NT` and uses `venv/Scripts/python.exe`
instead of `venv/bin/python`, so `make` targets work on Windows + Git Bash.

### 5. Baum-Welch retraining on honest observations
(`experiments/aligned_baum_welch.py`)

Removed the legacy local `SimulatedWarden` class (which had its own
ground-truth leak). The training script now imports `SimulatedWarden`,
`StorageChannel`, `TimingChannel`, `SYNC_PATTERN`, `SYNC_LEN`, and
`measure_observation` from `src.hmm_model.simulator`. The training schedule
is 2000 epochs with 70% state persistence, giving enough transitions for EM
to learn realistic emission probabilities.

### 6. HMM engine model loading (`hmm_engine.py`)

`HMMEngine` now loads the trained model from
`results/aligned_hmm_output/learned_hmm_model.json` by default, with explicit
shape and row-sum validation. The default fallback matrices are retained but
produce a loud warning when used.

### 7. Runtime prior override — P0 (`hmm_engine.py`, `simulator.py`)

The retrained model has `pi = [1.0, 0.0, 0.0]`, which is a training-set
artifact — the training schedule always starts in state 0. A `use_uniform_prior`
flag was added to `HMMEngine.__init__` to override this at runtime. The
simulator instantiates with `HMMEngine(use_uniform_prior=True)`.

Result: the runtime belief starts at `[1/3, 1/3, 1/3]` instead of `[1, 0, 0]`.
Marginal improvement to early-epoch behavior. Does not fix the one-epoch
control lag, which is a separate protocol property.

---

## Result Benchmarks

**⚠️ ALL NUMBERS BELOW ARE PRE-FIX AND OBSOLETE. They are retained only for
diffing against the regenerated results. Do not cite them.**

### Pre-fix Benchmark 1: Unaligned vs. Aligned Learned HMM

| Scenario | Unaligned BER | Aligned BER | Unaligned Acc | Aligned Acc | β̄ |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `baseline_multistage` | 13.29% | 6.43% | 5.55% | 94.44% | 41.11% |
| `sudden_attack` | 3.79% | 3.79% | 5.55% | 94.44% | 18.90% |
| `bursty_attack` | 12.94% | 9.07% | 27.78% | 72.22% | 45.56% |
| `prolonged_high_recovery` | 31.25% | 13.47% | 5.55% | 94.44% | 85.54% |
| `medium_dominated` | 6.60% | 5.72% | 50.00% | 66.67% | 49.99% |

### Pre-fix Benchmark 2: Scapy Bridge Transmission Log

*(See `results/hmm_scapy_bridge/scapy_hmm_results.csv`. To be regenerated
after P1.)*

### Pre-fix Benchmark 3: Steganalysis & Imperceptibility

| Metric | Unmodulated Baseline | HMM-Modulated | Note |
| :--- | :--- | :--- | :--- |
| KL divergence | 13.8587 bits | 13.0822 bits | 5.60% reduction |
| KS statistic | 0.4975 | 0.4145 | (both still very high) |
| IP.id parity entropy | 1.0000 bits | 0.9996 bits | $C/E = 2406.53$ |

**Interpretation caveat:** the reported 5.60% KL reduction still leaves
$D_{KL} \approx 13$ bits, which is enormous for a covert channel claiming
imperceptibility. This suggests the covert IPD distribution is far from the
MAWI cover. Fixing the timing SNR (P3) will change these numbers substantially.

---

## Next Steps: Prioritized Action List

### P0 — Runtime prior override ✅ DONE

See "Correctness Pass #7" above.

**Commit message:**

```
feat(hmm): add use_uniform_prior flag for runtime prior override

The retrained model has pi = [1, 0, 0] from training-set bias. Adding
use_uniform_prior=True overrides this at runtime. Marginal improvement
to early-epoch behavior; one-epoch control lag remains and is
documented as a protocol property.
```

### P1 — Rewrite `hmm_scapy_bridge.py` to actually transmit

**Why:** The current bridge is a simulation of a simulation — no socket, no
`send()`, no `sniff()`. It also leaks ground truth via `adapt_warden_for_scapy`.

**Changes needed:**

1. Remove `adapt_warden_for_scapy`. Use `measure_observation` from
   `simulator.py`.
2. Actually transmit: `send()` (Layer 3) or raw socket bound to `h1-eth0`.
3. Actually apply timing delays: `time.sleep(delay)` between sends.
4. Actually receive: `sniff()` on `h3-eth0` or listening UDP socket.
5. Measure real inter-arrival times at the receiver with `time.perf_counter()`.
6. Compute observation from measured sync BER at the receiver.
7. Log everything per epoch.

**Steps to do them in order:**

- Step 1: Clean socket round-trip on Mininet, no stealth.
- Step 2: Add IP ID storage channel.
- Step 3: Add timing channel.
- Step 4: Add warden.
- Step 5: Add HMM observation + belief update.
- Step 6: Run full 12-epoch schedule, compare to simulator.

**Estimated time:** 1.5–2.5 weeks.

### P2 — Fix `live_warden.py` to work with `netem`

**Why:** `sendp` bypasses the kernel's qdisc. The `tc netem` claim in the
testbed description is not actually applied.

**Options:**

- A: Use `iptables -j NFQUEUE` to route forwarded packets through a userspace
  queue, modify them, and re-inject. Preserves the kernel path.
- B: Drop the `netem` claim from the README and document userspace jitter.

**Estimated time:** 3–5 days (Option A), 0.5 day (Option B).

### P3 — Timing channel SNR tuning

**Why:** `delta_t = 0.10, σ_state2 = 0.04` gives ~10% timing BER. Workable
but not impressive. Sweep for a regime where timing BER ≤ 5%.

**Estimated time:** 2–3 days.

### P4 — Regenerate all benchmarks

Once P0–P3 are complete, re-run:

1. `make train` — retrain on final channel parameters.
2. `make simulate` — regenerate the in-process trace.
3. `make carrier` — verify the physical Scapy channels.
4. `make bridge` — regenerate the live transmission trace.
5. `make eval` — regenerate the steganalysis report.

**Estimated time:** 3–5 days.

### P5 — Extended evaluation

- Scale the Mininet evaluation from 12 epochs to 50–100 epochs across a
  6-phase threat profile.
- Evaluate long-term steady-state BER and goodput (kbps) to establish tight
  statistical confidence intervals.
- Cross-domain profiling: UNSW-MG24 (5G) and CIC-IoT-2023 (IoT) PCAPs.

**Estimated time:** 1–2 weeks.

### P6 — Fast-path belief override

**Why:** Sudden state transitions (e.g., Epoch 11: 0 → 2) incur a BER spike
because the controller's belief is one epoch behind.

**Important caveat:** The naive fast-path override in `update_belief` **does
not solve this**, because the controller reads its belief *before* the
current epoch's update. Fixing this properly requires either:

- Sub-epoch feedback (a protocol change), or
- A predictive belief update (using `A` to forecast ahead).

**Estimated time:** 1–3 weeks (depends on approach).

---

## Quick Start & Execution Commands

```bash
# 1. Environment & dependency setup
make requirement

# 2. Clear stale bytecode caches (important after recent fixes)
find src experiments -type d -name __pycache__ -exec rm -rf {} +

# 3. Retrain the HMM on honest observations
make train

# 4. Run the in-process simulator
make simulate

# 5. (After P3) extract MAWI IPD profile
make calibrate

# 6. (After P1–P3) verify Scapy carrier
make carrier

# 7. (After P1) run the live Scapy bridge
make bridge

# 8. (After P3) regenerate steganalysis report
make eval
```

---

## Appendix: P0 Code Changes

For reference, the exact edits made in P0.

**`src/hmm_model/hmm_engine.py`** — added `use_uniform_prior` flag to
`__init__`:

```python
def __init__(self, A=None, B=None, pi=None, model_path=None,
             use_uniform_prior=False):
    # ... existing loading logic ...
    if use_uniform_prior:
        self.current_belief = np.ones(self.num_states) / self.num_states
    else:
        self.current_belief = self.pi.copy()
```

**`src/hmm_model/simulator.py`** — instantiated with the flag:

```python
hmm = HMMEngine(use_uniform_prior=True)
```

---

## Future Work

1. **Fast-path anomaly trigger & HMM hysteresis reduction** — See P6.
2. **Extended multi-phase evaluation (50–100 epochs)** — See P5.
3. **Multi-environment cross-domain profiling** — UNSW-MG24 (5G), CIC-IoT-2023
   (IoT). Construct a 3-tier cross-domain imperceptibility matrix comparing
   $D_{KL}$, KS statistics, and throughput across Backbone, 5G, and IoT cover
   environments.
4. **Adaptive sync length** — shorter sync during clean epochs, longer during
   ambiguous epochs.
5. **Non-Gaussian jitter models** — replace the warden's Gaussian jitter with
   a fitted MAWI GMM for greater realism.

