#!/usr/bin/env bash
# Run a command inside a Mininet host from any terminal (the topology must be running).
#   scripts/on_host.sh h4 python3 scripts/attacks/portscan.py 10.0.0.1
#   scripts/on_host.sh h3 curl -s http://10.0.0.1/
set -euo pipefail
host=${1:?usage: on_host.sh <h1|h2|h3|h4> <command...>}; shift
[ $# -gt 0 ] || { echo "usage: on_host.sh <host> <command...>"; exit 1; }
pid=$(pgrep -f "^bash --norc --noediting -is mininet:${host}\$" | head -1 || true)
[ -n "$pid" ] || { echo "host $host not found - is topology/campus_topo.py running?"; exit 1; }
exec sudo mnexec -a "$pid" "$@"
