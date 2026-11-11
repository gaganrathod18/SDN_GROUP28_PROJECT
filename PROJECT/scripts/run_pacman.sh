#!/usr/bin/env bash
# Run the PacMan dashboard on the core-switch mirror port (needs the topology running).
#   scripts/run_pacman.sh             -> live dashboard on mon0
#   scripts/run_pacman.sh <iface>     -> another interface
# Env: PACMAN_BIN (default ../pacman/build/pacman)
set -euo pipefail

PROJECT=$(cd "$(dirname "$0")/.." && pwd)
PACMAN_BIN=${PACMAN_BIN:-$(cd "$PROJECT/../pacman" && pwd)/build/pacman}
IFACE=${1:-mon0}

[ -x "$PACMAN_BIN" ] || { echo "PacMan binary not found: $PACMAN_BIN (build it, or set PACMAN_BIN)"; exit 1; }
ip link show "$IFACE" >/dev/null 2>&1 || { echo "Interface $IFACE does not exist. Start the topology first: sudo python3 topology/campus_topo.py"; exit 1; }

cd "$PROJECT"
mkdir -p results/pacman-reports
touch results/pacman.log results/blocklist.txt      # created as you, so root only appends to them
exec sudo "$PACMAN_BIN" live config/pacman-sdn.conf --iface "$IFACE"
