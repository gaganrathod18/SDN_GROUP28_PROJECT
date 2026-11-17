# SDN-Based Network Traffic Monitor and Anomaly Detection
### Initiation-Aware Sequential Detection with Graded OpenFlow Mitigation

**Group SDN_28 · IIIT Dharwad · Software Defined Networking**

| Name | Roll no. |
|---|---|
| Gagan Rathod | 23bcs106 |
| Atulesh Sahoo | 23bcs022 |
| Ganesh Daware | 23bcs038 |
| Bhagya Vishwakarma | 23bcs029 |
| Dudlewar Adinath | 23bcs046 |
| Harshit | 23bcs037 |

An SDN campus network that **detects port scans and connection floods and blocks the attacker automatically, step by
step, on every OpenFlow switch**.

- **[PAPER.pdf](PAPER.pdf)**: research paper (IEEE conference format, 8 pages). LaTeX source in `PROJECT/report_ieee/`.
- **[DEMO.pdf](DEMO.pdf)**: live demo guide, with every command, screenshots and what to say.

## Idea

Window-and-threshold detectors ("more than 15 ports in 10 s") flag busy servers and health checkers, miss slow scans
and block the whole host at once. **AIS-SPRT** (Adaptive Initiation-aware Sequential Probability Ratio Test) instead
scores every host by the **outcome of the connections it starts**. Legitimate clients mostly reach services that
exist, so their attempts succeed. Scanners probe services that do not exist, so theirs fail.

- each failure adds evidence and each success removes it (Wald's SPRT); a host is decided a scanner at
  `ln(0.99/0.01) = 4.6`;
- each service is scored once per host (first contact), so retries do not count;
- failures on services that many hosts use count less (**novelty weight**), so a server outage is not an attack;
- evidence **decays** (τ = 600 s), so a benign host's old failures fade;
- a **CUSUM** test on connections per second catches floods, whose connections succeed.

Its decisions drive a **graded** OpenFlow response in POX:
1. **path block** (attacker → victim) at suspicion;
2. **host block** at decision;
3. **exponential back-off** for repeat offenders (B·2^k);
4. a **packet-in guard** that closes the rule-installation race.

**PacMan**, our C++ htop-style terminal monitor, shows the operator the same traffic and every block.

```
Application plane   AIS-SPRT engine (detector/live.py) ──"ip time reason scope"──▶ results/blocklist.txt
                    PacMan dashboard (frontend, read-only view of the same traffic)
Control plane       POX: l2_learning + pacman_ips (validate, graded block, back-off, packet-in guard, flow stats 5 s)
Data plane          s1 core ── s2 (h1 web 10.0.0.1, h2 files 10.0.0.2)
                            └─ s3 (h3 user 10.0.0.3, h4 attacker 10.0.0.4)     s1 mirrors all ports → mon0
```

## Results (details in PAPER.pdf)

**Emulated labelled dataset:** 24 recordings, 8 scenarios × 3 seeds, 44,855 connection attempts, included in
`PROJECT/results/dataset/`. Scenarios: benign, server outage, fast, slow (0.5/s and 0.2/s), horizontal, distributed
and flood attacks. Test seeds:

| Method | TPR | FPR | F1 |
|---|---|---|---|
| **AIS-SPRT (ours)** | **1.000** | **0.000** | **1.000** |
| Threshold Random Walk | 0.875 | 0.006 | 0.903 |
| Entropy | 0.875 | 0.193 | 0.438 |
| Random Forest | 0.750 | 0.182 | 0.400 |
| IA-Window / Naive-Window | 0.125 | 0.000 | 0.222 |

**Public CIC-IDS2017 (Friday, 9.9 M packets of real office traffic), scan test not re-tuned:**
- AIS-SPRT is the only detector besides the Random Forest that catches **both** the port scan (after 45 s) and the
  DDoS (after 32 s).
- It flags 2 of 8 benign hosts, against 5 of 8 for the Random Forest.
- At α = 10⁻³ its F1 is 0.80, and at α = 3·10⁻⁴ it is 1.00. TRW stays at or below 0.50.

**Live closed loop (Mininet + POX):**
- Fast scans: the attacker was blocked on all switches 0.68–1.39 s after the scan started.
- Slow scan (0.5 probes/s): blocked after 20.2 s.
- Repeat offences: block times of 15 → 30 → 60 → 120 s.

## What is in this folder

```
SDN_GROUP28_PROJECT/
├── PAPER.pdf, DEMO.pdf, README.md
├── PROJECT/
│   ├── detector/
│   │   ├── detectors.py        AIS-SPRT and the baselines (TRW, IA-Window, Naive-Window, Entropy)
│   │   ├── pcapio.py           pcap/pcapng reader, turns packets into initiated attempts (success / failure)
│   │   └── live.py             live AIS-SPRT engine on mon0, writes block requests
│   ├── controller/pacman_ips.py  POX component: graded blocking, back-off, packet-in guard, flow statistics
│   ├── topology/campus_topo.py   Mininet network with the s1 → mon0 mirror
│   ├── config/                   PacMan settings (frontend mode used in the demo)
│   ├── test.py                   demo console for terminal T4
│   ├── scripts/
│   │   ├── run_pox.sh, run_pacman.sh, on_host.sh, setup_env.sh, check_env.sh
│   │   ├── attacks/             portscan.py (vertical), hscan.py (horizontal), synflood.py
│   │   ├── bench/               benign servers and clients used for the dataset
│   │   ├── exp_dataset.py       records the labelled dataset (sudo, Mininet)
│   │   ├── eval_detectors.py    evaluation on the dataset → results/eval, paper figures
│   │   ├── eval_cicids.py       cross-dataset test on CIC-IDS2017 → results/eval_cicids, Fig. 8
│   │   ├── gen_results_tex.py   numbers for the paper (report_ieee/generated/results.tex)
│   │   ├── test_aisprt_live.py  live closed-loop test (9 checks)
│   │   └── test_phase2-4.py, run_all_tests.sh, labkit.py   earlier progress-review test suites
│   ├── report_ieee/             paper source: main.tex, refs.bib, figures/, generated/
│   └── results/                 dataset/, eval/, eval_cicids/, live-test results
└── pacman/                      PacMan terminal monitor (C++17, libpcap, FTXUI)
```

## Requirements and setup

Linux (tested on Fedora 43) with Mininet, Open vSwitch, Podman, tcpdump, cmake, g++, libpcap, Python 3 with
`scikit-learn` and `matplotlib` (for the evaluation only), and sudo. POX runs in a `python:2.7` Podman container.

```bash
git clone https://github.com/gaganrathod18/SDN_GROUP28_PROJECT.git
cd SDN_GROUP28_PROJECT/PROJECT
scripts/setup_env.sh        # packages, POX in ../pox, python:2.7 image, builds ../pacman/build/pacman
scripts/check_env.sh        # every line must say [ OK ]
```

## Run the live demo (4 terminals, all in `PROJECT/`)

| Terminal | Command | What it is |
|---|---|---|
| T1 | `BLOCK_SECONDS=30 scripts/run_pox.sh` | POX controller (l2_learning + pacman_ips) |
| T2 | `sudo python3 topology/campus_topo.py` | the network, `mininet>` prompt |
| T3 | `scripts/run_pacman.sh frontend` | PacMan dashboard on mon0 |
| T4 | `python3 test.py` | demo console. It starts the AIS-SPRT engine and runs each step |

Steps in `test.py`: `check`, `status`, `services`, `normal` (no alarm), `slow` (slow scan caught), `attack` (fast scan →
blocked on every switch), `proof` (drop rules on every switch), `cut` (attacker 100 % loss, user 0 %), `events`,
`repeat` (back-off doubles), `results`, `log`. DEMO.pdf walks through all of them.

Clean start: `sudo mn -c; podman rm -f pacman-pox; rm -f results/blocklist.txt results/block_events.csv`.

## Reproduce the paper

```bash
cd PROJECT
python3 scripts/eval_detectors.py      # emulated dataset (included): tables, ROC, per-scenario, delay, ablation, graded
python3 scripts/gen_results_tex.py     # numbers used in the paper
python3 scripts/eval_cicids.py         # needs the CIC-IDS2017 Friday capture, see below
sudo python3 scripts/test_aisprt_live.py   # live closed-loop test
cd report_ieee && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

CIC-IDS2017 is not included (8.8 GB). Download `Friday-WorkingHours.pcap` from the
[Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) into
`../datasets/cicids2017/` next to `PROJECT/`, or set `CICIDS_DIR`. The first run extracts the connection attempts into
a small cache; after that the pcap can be deleted.

## Troubleshooting

| Problem | Fix |
|---|---|
| `address already in use` when starting POX | `podman rm -f pacman-pox` |
| Mininet `Error creating interface pair` | `sudo mn -c` |
| `Interface mon0 does not exist` | start the network (T2) before PacMan |
| h4 blocked right after POX starts | an old request is still valid: remove `results/blocklist.txt` and `results/block_events.csv` |
