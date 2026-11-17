#!/usr/bin/env python3
"""
Generate the labelled evaluation dataset: realistic benign traffic plus five attack types, recorded on the core mirror.

    sudo python3 scripts/exp_dataset.py [--seeds 3] [--only scenario,...]

Topology: core s1; s2 = 4 servers (10.0.0.11-14, 5 TCP services each); s3, s4, s5 = 12 clients (10.0.0.21-32).
s1 mirrors every port to mon0. Switches run in OVS standalone (learning) mode, so the dataset is independent of the
controller. Benign: 11 clients make Poisson requests (0.3-3 req/s) to Zipf-popular servers, 8% of requests go to a
stale service and are retried 3 times; client 10.0.0.21 is a health checker that polls all 20 services every 5 s.
Attackers also run benign traffic. Writes results/dataset/<scenario>_s<seed>.pcap and .json (labels).
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time
import zlib
from functools import partial

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(PROJECT, "topology"))

from mininet.log import setLogLevel          # noqa: E402
from mininet.net import Mininet              # noqa: E402
from mininet.node import OVSSwitch           # noqa: E402
from mininet.topo import Topo                # noqa: E402
from campus_topo import add_mirror, quiet_host_interface  # noqa: E402

OUT = os.path.join(PROJECT, "results", "dataset")
SERVERS = json.load(open(os.path.join(HERE, "bench", "servers.json")))
SRV = sorted(SERVERS)
CLIENTS = ["10.0.0.%d" % i for i in range(21, 33)]
DURATION, ATTACK_AT = 80, 20
BENCH, ATK = os.path.join(HERE, "bench"), os.path.join(HERE, "attacks")
ALL_HOSTS = SRV + CLIENTS

SCENARIOS = {
    "benign":   {"attackers": []},
    "vfast":    {"attackers": ["10.0.0.32"], "cmd": {"10.0.0.32": "python3 %s/portscan.py 10.0.0.11 --ports 1-200 --timeout 0.3" % ATK}},
    "vslow05":  {"attackers": ["10.0.0.32"], "cmd": {"10.0.0.32": "python3 %s/portscan.py 10.0.0.12 --ports 1-30 --timeout 0.3 --delay 2.0" % ATK}},
    "vslow02":  {"attackers": ["10.0.0.32"], "cmd": {"10.0.0.32": "python3 %s/portscan.py 10.0.0.13 --ports 1-12 --timeout 0.3 --delay 5.0" % ATK}},
    "horiz":    {"attackers": ["10.0.0.32"], "cmd": {"10.0.0.32": "python3 %s/hscan.py %s 21,23,135,139,445,3389,5900,1433 --delay 0.3"
                                                     % (ATK, ",".join(SRV + CLIENTS[:6]))}},
    "dist":     {"attackers": ["10.0.0.30", "10.0.0.31", "10.0.0.32"],
                 "cmd": {"10.0.0.30": "python3 %s/portscan.py 10.0.0.14 --ports 1-40 --timeout 0.3 --delay 1.0" % ATK,
                         "10.0.0.31": "python3 %s/portscan.py 10.0.0.14 --ports 41-80 --timeout 0.3 --delay 1.0" % ATK,
                         "10.0.0.32": "python3 %s/portscan.py 10.0.0.14 --ports 81-120 --timeout 0.3 --delay 1.0" % ATK}},
    "flood":    {"attackers": ["10.0.0.32"], "cmd": {"10.0.0.32": "python3 %s/synflood.py 10.0.0.11 80 --rate 300 --duration 10" % ATK}},
    # no attacker: the most popular server crashes for 30 s, so every client sees failures on its services
    "outage":   {"attackers": [], "outage": "10.0.0.11"},
}


class Lab(Topo):
    def build(self):
        core = self.addSwitch("s1")
        edges = [self.addSwitch("s%d" % i) for i in range(2, 6)]
        for e in edges:
            self.addLink(core, e)
        for i, ip in enumerate(SRV):
            self.addHost("srv%d" % (i + 1), ip=ip + "/24")
            self.addLink("srv%d" % (i + 1), edges[0])
        for i, ip in enumerate(CLIENTS):
            self.addHost("c%d" % (i + 1), ip=ip + "/24")
            self.addLink("c%d" % (i + 1), edges[1 + i // 4])


def host_by_ip(net, ip):
    return next(h for h in net.hosts if h.IP() == ip)


def restart_services(net):
    for ip in SRV:
        ports = ",".join(map(str, SERVERS[ip]["open"]))
        h = host_by_ip(net, ip)
        h.cmd("pkill -f 'services.py %s'" % ports)
        h.cmd("python3 %s/services.py %s >/dev/null 2>&1 &" % (BENCH, ports))
    time.sleep(1.5)


def run(net, name, seed):
    sc = SCENARIOS[name]
    rnd = random.Random(seed * 1000 + zlib.crc32(name.encode()) % 997)
    restart_services(net)                    # every run starts with fresh, idle servers
    pcap = os.path.join(OUT, "%s_s%d.pcap" % (name, seed))
    cap = subprocess.Popen(["tcpdump", "-nn", "-i", "mon0", "-s", "128", "-w", pcap, "ip"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    t_start = time.time()
    procs = []
    for ip in CLIENTS:
        h = host_by_ip(net, ip)
        if ip == "10.0.0.21":
            procs.append(h.popen(["python3", BENCH + "/client.py", "health", str(seed), "5", str(DURATION)]))
        else:
            rate = round(rnd.uniform(0.3, 3.0), 2)
            procs.append(h.popen(["python3", BENCH + "/client.py", "benign", str(rnd.randint(1, 10 ** 6)), str(rate),
                                  str(DURATION), "0.08"]))
    attack_t = None
    if sc.get("outage"):
        time.sleep(ATTACK_AT)
        srv = host_by_ip(net, sc["outage"])
        srv.cmd("pkill -f 'services.py %s'" % ",".join(map(str, SERVERS[sc["outage"]]["open"])))
        time.sleep(30)
        srv.cmd("python3 %s/services.py %s >/dev/null 2>&1 &" % (BENCH, ",".join(map(str, SERVERS[sc["outage"]]["open"]))))
    if sc.get("cmd"):
        time.sleep(ATTACK_AT)
        attack_t = time.time()
        for ip, cmd in sc["cmd"].items():
            procs.append(host_by_ip(net, ip).popen(cmd, shell=True))
    for p in procs:
        p.wait()
    time.sleep(4)
    cap.terminate()
    cap.wait()
    meta = {"scenario": name, "seed": seed, "attackers": sc["attackers"], "t_start": t_start, "attack_t": attack_t,
            "hosts": ALL_HOSTS, "duration": DURATION}
    with open(pcap.replace(".pcap", ".json"), "w") as f:
        json.dump(meta, f, indent=1)
    print("  %-8s seed %d  %.0f s  %s" % (name, seed, time.time() - t_start, os.path.getsize(pcap)), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--only", default="")
    ap.add_argument("--seed-list", default="", help="e.g. 2,3 (default: 1..seeds)")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    setLogLevel("error")
    subprocess.run("mn -c", shell=True, capture_output=True)
    os.makedirs(OUT, exist_ok=True)
    net = Mininet(topo=Lab(), switch=partial(OVSSwitch, failMode="standalone"), controller=None,
                  autoSetMacs=True, waitConnected=False)
    net.start()
    try:
        for h in net.hosts:
            h.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
        for sw in net.switches:
            for intf in sw.intfList():
                if intf.name != "lo":
                    quiet_host_interface(intf.name)
        add_mirror()
        for i, ip in enumerate(SRV):
            host_by_ip(net, ip).cmd("python3 %s/services.py %s >/dev/null 2>&1 &"
                                    % (BENCH, ",".join(map(str, SERVERS[ip]["open"]))))
        time.sleep(2)
        print("pingall loss: %s%%" % net.pingAll(timeout=1), flush=True)
        names = [n for n in SCENARIOS if not a.only or n in a.only.split(",")]
        seeds = [int(x) for x in a.seed_list.split(",")] if a.seed_list else range(1, a.seeds + 1)
        for seed in seeds:
            for n in names:
                run(net, n, seed)
    finally:
        net.stop()
        subprocess.run("chown -R %s:%s %s" % (os.environ.get("SUDO_UID", "0"), os.environ.get("SUDO_GID", "0"), OUT),
                       shell=True)


if __name__ == "__main__":
    main()
