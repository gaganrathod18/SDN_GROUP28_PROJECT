# SDN-Based Network Traffic Monitor & Anomaly Detection

**Group SDN_28 · IIIT Dharwad · Software Defined Networking**

| Name | Roll no. |
|---|---|
| Gagan Rathod | 23bcs106 |
| Atulesh Sahoo | 23bcs022 |
| Ganesh Daware | 23bcs038 |
| Bhagya Vishwakarma | 23bcs029 |
| Dudlewar Adinath | 23bcs046 |
| Harshit | 23bcs037 |

A small SDN campus network that **detects port scans and blocks the attacker automatically**.
The core switch copies all traffic to our packet monitor **PacMan**. When PacMan sees a port scan it writes the
attacker's IP to a file; our **POX** controller program reads it and installs a **drop rule on every switch** for
120 seconds. Median time from scan start to block: **1.28 s**. Normal users are not affected. 54/54 automated tests pass.

- **REPORT.pdf**: the project report (IEEE format)
- **DEMO.pdf**: step-by-step live demo with every command, screenshots and what to say

## What is in this folder

```
SDN_GROUP28_PROJECT/
├── README.md
├── REPORT.pdf                    project report
├── DEMO.pdf                      live demo guide
├── PROJECT/                      the SDN project
│   ├── controller/pacman_ips.py  POX component: flow statistics + automatic blocking
│   ├── topology/campus_topo.py   Mininet network (s1 core, s2 servers, s3 users) + mirror to mon0
│   ├── config/pacman-sdn.conf    PacMan settings (thresholds, SDN mode, blocklist file)
│   ├── test.py                   demo console for terminal T4 (menu of tests + live Mininet commands)
│   └── scripts/
│       ├── setup_env.sh          one-time install (packages, POX, controller image, PacMan build)
│       ├── check_env.sh          checks that everything is installed
│       ├── run_pox.sh            starts the POX controller (in Podman, Python 2.7)
│       ├── run_pacman.sh         starts PacMan on the mirror port mon0
│       ├── on_host.sh            runs a command inside a Mininet host (e.g. h4)
│       ├── attacks/portscan.py   the attack: TCP port scan (lab addresses only)
│       ├── labkit.py             helpers for the automated tests
│       ├── test_phase2.py        tests: network + monitoring       (21 checks)
│       ├── test_phase3.py        tests: detection + blocking       (25 checks)
│       ├── test_phase4.py        tests: under heavy traffic        (8 checks)
│       └── run_all_tests.sh      runs all three test suites
└── pacman/                       PacMan packet monitor (C++17, libpcap, FTXUI)
    ├── CMakeLists.txt, LICENSE, config/pacman.conf
    ├── include/                  headers
    └── src/                      source (detector: threat_detector.cpp, engine: pacman_engine.cpp,
                                  block requests: firewall_manager.cpp)
```

## How it works

```
Application plane   PacMan ──(HIGH alert)──▶ appends "ip  time  reason" to PROJECT/results/blocklist.txt
Control plane       POX: l2_learning (forwarding) + pacman_ips (reads blocklist every 1 s, flow stats every 5 s)
Data plane          s1 core ── s2 (h1 web 10.0.0.1, h2 files 10.0.0.2)
                            └─ s3 (h3 user 10.0.0.3, h4 attacker 10.0.0.4)        s1 mirrors all ports → mon0 → PacMan
```

1. h4 scans h1. PacMan counts only connections a host **starts** (TCP SYN without ACK), so busy servers are never
   flagged. More than 15 different ports in 10 s gives PORT_SCAN (HIGH).
2. PacMan writes one line to `blocklist.txt`.
3. The controller reads it within 1 s, **deletes** h4's existing flow rules and **adds** a drop rule
   (`ip, nw_src=10.0.0.4`, priority 65000, no actions, hard timeout 120 s) on s1, s2 and s3.
4. h4 is cut off; h3 keeps working. After 120 s the rule expires by itself.

## Requirements

Linux (tested on Fedora 43) with: Mininet, Open vSwitch, Podman, tcpdump, iperf, tshark (optional), cmake, g++,
make, libpcap-devel, libcurl-devel, git. Internet access for the one-time setup (POX, the `python:2.7` image, and the
FTXUI library downloaded by CMake). sudo access.

Fedora / RHEL:
```bash
sudo dnf install -y mininet openvswitch podman tcpdump iperf wireshark-cli cmake gcc-c++ make libpcap-devel libcurl-devel git
sudo systemctl enable --now openvswitch
```
Ubuntu / Debian:
```bash
sudo apt-get install -y mininet openvswitch-switch podman tcpdump iperf tshark cmake g++ make libpcap-dev libcurl4-openssl-dev git
sudo systemctl enable --now openvswitch-switch
```

## Setup (once)

The scripts expect `PROJECT/`, `pacman/` and `pox/` side by side (the repository has the first two; `setup_env.sh`
clones POX next to them).

```bash
git clone https://github.com/gaganrathod18/SDN_GROUP28_PROJECT.git
cd SDN_GROUP28_PROJECT/PROJECT
scripts/setup_env.sh        # installs packages, clones POX into ../pox, pulls python:2.7, builds ../pacman/build/pacman
scripts/check_env.sh        # every line must say [ OK ]
```

Manual alternative to `setup_env.sh`:
```bash
cd SDN_GROUP28_PROJECT
git clone https://github.com/noxrepo/pox
podman pull docker.io/library/python:2.7
cmake -S pacman -B pacman/build -DCMAKE_BUILD_TYPE=Release && make -C pacman/build -j4
```

## Run the demo (4 terminals, all in `SDN_GROUP28_PROJECT/PROJECT`)

| Terminal | Command | What it is |
|---|---|---|
| T1 | `scripts/run_pox.sh` | controller (POX + l2_learning + pacman_ips) |
| T2 | `sudo python3 topology/campus_topo.py` | the network, `mininet>` prompt |
| T3 | `scripts/run_pacman.sh` | PacMan live dashboard on mon0 (←/→ tabs, q quits) |
| T4 | `python3 test.py` | demo console: type a test number |

In T2 start the web servers:
```
h1 python3 -m http.server 80 --directory /tmp &
h2 python3 -m http.server 8080 --directory /tmp &
```
Then, in T4 (`test.py`): `6` normal traffic (no alert) → in T2 `h4 ping -i 0.5 10.0.0.2` → `7` attack →
`8` proof (drop rules) → `9` attacker cut / user fine → `10` drop counter → `11` mirror silent → `12` events →
`13` wait for expiry. `live` lists more Mininet commands to try. DEMO.pdf has every step with screenshots.

Without test.py, the attack is:
```bash
scripts/on_host.sh h4 python3 scripts/attacks/portscan.py 10.0.0.1 --ports 1-100 --timeout 0.2
scripts/on_host.sh h4 ping -c 3 -W 1 10.0.0.2      # attacker: 100% loss
scripts/on_host.sh h3 ping -c 3 -W 1 10.0.0.1      # normal user: 0% loss
for s in s1 s2 s3; do sudo ovs-ofctl dump-flows $s "ip,nw_src=10.0.0.4"; done
```

Stop: `q` in T3, `exit` in T2, `Ctrl+C` in T1, then `sudo mn -c`.

Controller options (environment variables for `run_pox.sh`): `BLOCK_SECONDS` (default 120), `PROTECT` (never blocked,
default 10.0.0.1), `STATS_INTERVAL` (default 5). Example: `BLOCK_SECONDS=60 scripts/run_pox.sh`.

## Automated tests (stop the demo first)

```bash
scripts/run_all_tests.sh                 # all suites, about 8 minutes
sudo python3 scripts/test_phase2.py      # network + monitoring      21 checks
sudo python3 scripts/test_phase3.py      # detection + blocking      25 checks
sudo python3 scripts/test_phase4.py      # heavy traffic              8 checks
```
Each suite starts its own controller, network and PacMan, and writes its PASS/FAIL list to `PROJECT/results/`.

## Files written while running (`PROJECT/results/`)

| File | Written by | Content |
|---|---|---|
| `blocklist.txt` | PacMan | one block request per line: `ip  unix-time  reason` |
| `block_events.csv` | controller | BLOCK, EXPIRE, REFRESH, REAPPLY, SKIP_PROTECTED, INVALID, STALE |
| `flow_stats.csv` | controller | flow counters of every switch, every 5 s |
| `pacman.log` | PacMan | alerts, block requests, capture statistics |

## Troubleshooting

| Problem | Fix |
|---|---|
| `address already in use` when starting POX | `podman rm -f pacman-pox` |
| Mininet `Error creating interface pair` | `sudo mn -c` |
| `Interface mon0 does not exist` | start the network (T2) before PacMan |
| `host h4 not found` from on_host.sh | the network in T2 is not running |
| h4 blocked right after POX starts | an old request is still valid: `rm -f results/blocklist.txt results/block_events.csv` before `run_pox.sh` |
| PacMan shows no traffic for h1 ↔ h2 | expected: only traffic through the core switch s1 is mirrored |
