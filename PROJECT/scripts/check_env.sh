#!/usr/bin/env bash
# Pre-flight check: is everything the project needs installed and in place?
#   scripts/check_env.sh        -> prints OK / MISSING per item, exit 1 if anything required is missing
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
POX_DIR=${POX_DIR:-$PROJECT/../pox}
PACMAN_BIN=${PACMAN_BIN:-$PROJECT/../pacman/build/pacman}
missing=0

ok()   { printf '  [ OK ]      %s\n' "$1"; }
bad()  { printf '  [MISSING]   %s  ->  %s\n' "$1" "$2"; missing=1; }
warn() { printf '  [optional]  %s  ->  %s\n' "$1" "$2"; }

echo "Checking the PacMan SDN project environment"
for cmd in mn ovs-vsctl ovs-ofctl podman tcpdump python3; do
  command -v "$cmd" >/dev/null && ok "$cmd" || bad "$cmd" "install it (see README.md)"
done
sudo -n true 2>/dev/null && ok "sudo without password prompt (needed by the tests)" \
  || warn "sudo asks for a password" "fine for manual runs; run_all_tests.sh will ask for it once"
sudo python3 -c "import mininet" 2>/dev/null && ok "Mininet Python API (as root)" || bad "Mininet Python API" "install mininet's Python package for root's python3"
systemctl is-active --quiet openvswitch 2>/dev/null || systemctl is-active --quiet openvswitch-switch 2>/dev/null \
  && ok "Open vSwitch service running" || bad "Open vSwitch service" "sudo systemctl enable --now openvswitch"
podman image exists python:2.7 2>/dev/null && ok "Podman image python:2.7" || bad "Podman image python:2.7" "podman pull docker.io/library/python:2.7"
[ -f "$POX_DIR/pox.py" ] && ok "POX in $POX_DIR" || bad "POX" "git clone https://github.com/noxrepo/pox $POX_DIR"
[ -x "$PACMAN_BIN" ] && ok "PacMan binary $PACMAN_BIN" || bad "PacMan binary" "build it: cmake -S ../pacman -B ../pacman/build && make -C ../pacman/build -j4"
command -v iperf >/dev/null && ok "iperf (load test)" || warn "iperf" "only needed for scripts/test_phase4.py"
command -v tshark >/dev/null && ok "tshark (OpenFlow decoding)" || warn "tshark" "only needed to decode results/*.pcap"
ss -ltn 2>/dev/null | grep -q ':6633 ' && warn "port 6633 already in use" "another controller is running; stop it before scripts/run_pox.sh" \
  || ok "OpenFlow port 6633 free"

[ $missing -eq 0 ] && echo "All required components found." || echo "Some required components are missing (see above)."
exit $missing
