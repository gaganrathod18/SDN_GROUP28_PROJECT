#!/usr/bin/env python3
"""
Campus tree topology for the PacMan SDN project.

    s1 (core) ── s2 (server zone: h1 web, h2 files)
              └─ s3 (user zone:   h3 user, h4 attacker)

s1 mirrors every packet of every port to the OVS internal port `mon0` on the host,
where PacMan captures. All switches are controlled by a remote POX controller.

Run (POX must be reachable, see scripts/run_pox.sh):
    sudo python3 topology/campus_topo.py                 # network + mirror + Mininet CLI
    sudo python3 topology/campus_topo.py --no-mirror     # without the monitoring port
Or with mn:  sudo mn --custom topology/campus_topo.py --topo campus --mac \
                 --controller remote,ip=127.0.0.1,port=6633 --switch ovsk
"""
import argparse
import subprocess
import sys

sys.dont_write_bytecode = True        # run with sudo: never leave root-owned __pycache__ behind

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

MIRROR_PORT = "mon0"
MIRROR_NAME = "pacman"

HOSTS = {          # name: (ip, switch, role)
    "h1": ("10.0.0.1", "s2", "web server"),
    "h2": ("10.0.0.2", "s2", "file server"),
    "h3": ("10.0.0.3", "s3", "normal user"),
    "h4": ("10.0.0.4", "s3", "attacker"),
}


class CampusTopo(Topo):
    def build(self):
        core = self.addSwitch("s1")
        servers = self.addSwitch("s2")
        users = self.addSwitch("s3")
        self.addLink(core, servers)                    # s1-eth1 <-> s2-eth1 (uplink)
        self.addLink(core, users)                      # s1-eth2 <-> s3-eth1 (uplink)
        for i, (name, (ip, sw, _role)) in enumerate(sorted(HOSTS.items()), start=1):
            self.addHost(name, ip=ip + "/24", mac="00:00:00:00:00:%02x" % i)
            self.addLink(name, sw)


topos = {"campus": CampusTopo}


def sh(cmd):
    """Run a host command; raise with its output if it fails."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError("%s\n%s%s" % (cmd, result.stdout, result.stderr))
    return result.stdout


def quiet_host_interface(name):
    """No IPv6, no NetworkManager on a host-side interface, so it never sends packets of its own."""
    sh("sysctl -qw net.ipv6.conf.%s.disable_ipv6=1" % name)
    subprocess.run("nmcli device set %s managed no" % name, shell=True, capture_output=True)


def add_mirror(switch="s1", port=MIRROR_PORT):
    """Create mon0 on the switch and mirror every port of it there (idempotent)."""
    sh("ovs-vsctl --may-exist add-port %s %s -- set interface %s type=internal" % (switch, port, port))
    quiet_host_interface(port)                   # no IPv6 autoconf, no NetworkManager DHCP
    sh("ip addr flush dev %s" % port)
    sh("ip link set %s up" % port)
    sh("ovs-vsctl -- --if-exists clear bridge %s mirrors" % switch)
    sh("ovs-vsctl -- --id=@p get port %s "
       "-- --id=@m create mirror name=%s select-all=true output-port=@p "
       "-- set bridge %s mirrors=@m" % (port, MIRROR_NAME, switch))
    # Don't let the controller's floods reach mon0 too, or PacMan would see those packets twice.
    sh("ovs-ofctl mod-port %s %s no-flood" % (switch, port))
    info("*** Mirror: all traffic on %s is copied to %s\n" % (switch, port))


def build_net(controller_ip="127.0.0.1", controller_port=6633, mirror=True):
    net = Mininet(topo=CampusTopo(), switch=OVSSwitch, controller=None,
                  autoSetMacs=False, autoStaticArp=False, waitConnected=False)
    net.addController("c0", controller=RemoteController, ip=controller_ip, port=controller_port)
    net.start()
    for host in net.hosts:                       # IPv4 only: keeps captures readable
        host.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
    for switch in net.switches:                  # the switch ports live in the host's namespace:
        for intf in switch.intfList():           # stop the host's own IPv6/mDNS chatter leaking in
            if intf.name != "lo":
                quiet_host_interface(intf.name)
    if mirror:
        add_mirror()
    return net


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--controller", default="127.0.0.1", help="POX address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=6633, help="POX OpenFlow port (default 6633)")
    parser.add_argument("--no-mirror", action="store_true", help="do not create the mon0 mirror port")
    args = parser.parse_args()

    setLogLevel("info")
    net = build_net(args.controller, args.port, mirror=not args.no_mirror)
    if not net.waitConnected(timeout=15):
        info("*** WARNING: not all switches reached the controller at %s:%d\n" % (args.controller, args.port))
    info("*** Hosts: %s\n" % ", ".join("%s=%s (%s)" % (n, ip, role) for n, (ip, _s, role) in sorted(HOSTS.items())))
    try:
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    if sys.version_info < (3, 6):
        sys.exit("needs Python 3.6+")
    main()
