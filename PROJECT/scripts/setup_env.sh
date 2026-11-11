#!/usr/bin/env bash
# One-time setup on a fresh machine (Fedora/RHEL or Ubuntu/Debian).
# Installs the system packages, fetches POX and the Python 2.7 controller image, builds PacMan.
#   scripts/setup_env.sh            run from PROJECT/; needs sudo and internet access
# Expected layout afterwards:  SDN/PROJECT  SDN/pacman  SDN/pox
set -euo pipefail

PROJECT=$(cd "$(dirname "$0")/.." && pwd)
SDN=$(dirname "$PROJECT")

echo "== 1/4 system packages"
if command -v dnf >/dev/null; then
  sudo dnf install -y mininet openvswitch podman tcpdump iperf wireshark-cli \
                      cmake gcc-c++ make libpcap-devel libcurl-devel git
  sudo systemctl enable --now openvswitch
elif command -v apt-get >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y mininet openvswitch-switch podman tcpdump iperf tshark \
                          cmake g++ make libpcap-dev libcurl4-openssl-dev git
  sudo systemctl enable --now openvswitch-switch
else
  echo "Unsupported package manager: install the packages listed in README.md by hand." >&2
  exit 1
fi

echo "== 2/4 POX controller"
if [ -f "$SDN/pox/pox.py" ]; then
  echo "POX already present in $SDN/pox"
else
  git clone https://github.com/noxrepo/pox "$SDN/pox"
fi

echo "== 3/4 controller image (POX 0.2.0 needs Python 2.7)"
podman image exists python:2.7 || podman pull docker.io/library/python:2.7

echo "== 4/4 PacMan"
[ -f "$SDN/pacman/CMakeLists.txt" ] || { echo "PacMan source not found in $SDN/pacman" >&2; exit 1; }
cmake -S "$SDN/pacman" -B "$SDN/pacman/build" -DCMAKE_BUILD_TYPE=Release
make -C "$SDN/pacman/build" -j"$(nproc)"

echo
"$PROJECT/scripts/check_env.sh"
