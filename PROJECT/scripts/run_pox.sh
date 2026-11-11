#!/usr/bin/env bash
# Start the POX controller (Python 2.7 in Podman) with forwarding + our monitoring component.
#   scripts/run_pox.sh            -> foreground, log on the terminal
#   scripts/run_pox.sh -d         -> background (used by the tests); log: podman logs pacman-pox
# Env: POX_DIR (default ../pox next to PROJECT), STATS_INTERVAL (default 5), LOG_LEVEL (default INFO),
#      BLOCK_SECONDS (default 120), PROTECT (comma-separated IPs that are never blocked, default 10.0.0.1)
set -euo pipefail

PROJECT=$(cd "$(dirname "$0")/.." && pwd)
POX_DIR=${POX_DIR:-$(cd "$PROJECT/../pox" && pwd)}
STATS_INTERVAL=${STATS_INTERVAL:-5}
LOG_LEVEL=${LOG_LEVEL:-INFO}
BLOCK_SECONDS=${BLOCK_SECONDS:-120}
PROTECT=${PROTECT-10.0.0.1}
NAME=pacman-pox

[ -f "$POX_DIR/pox.py" ] || { echo "POX not found in $POX_DIR (set POX_DIR)"; exit 1; }
mkdir -p "$PROJECT/results"

MODE=(-it)
[ "${1:-}" = "-d" ] && MODE=(-d)

podman rm -f -t 0 "$NAME" >/dev/null 2>&1 || true
# label=disable: no SELinux relabelling of the mounts, so files created by other users
# (e.g. PacMan running as root) can never stop the controller from starting.
exec podman run --rm --init "${MODE[@]}" --name "$NAME" --network host --security-opt label=disable \
  -v "$POX_DIR:/pox" -v "$PROJECT/controller:/project/controller:ro" -v "$PROJECT/results:/project/results" \
  -v /etc/localtime:/etc/localtime:ro -e PYTHONPATH=/project/controller -e PYTHONDONTWRITEBYTECODE=1 \
  python:2.7 bash -c "cd /pox && exec python ./pox.py log.level --$LOG_LEVEL \
    forwarding.l2_learning \
    pacman_ips --interval=$STATS_INTERVAL --stats_file=/project/results/flow_stats.csv \
      --blocklist=/project/results/blocklist.txt --block_seconds=$BLOCK_SECONDS --protect=$PROTECT \
      --events_file=/project/results/block_events.csv"
