#!/usr/bin/env python3
"""
Live closed-loop test of AIS-SPRT + graded mitigation on the campus network.

    sudo python3 scripts/test_aisprt_live.py [--runs 5]

POX (l2_learning + pacman_ips with graded blocks) and the live AIS-SPRT engine on mon0. For each run h4 scans h1
(fast, ports 1-100); we record when the path block (nw_dst=h1) and the host block appear on all three switches, check
that h4's running ping stops, that h3 is unaffected, and that a second offence gets a doubled block time. Then one slow
scan (0.5 probes/s). Writes results/aisprt_live.csv and results/aisprt_live_tests.txt.
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labkit as K                          # noqa: E402
from labkit import sh, wait_for             # noqa: E402

from mininet.log import setLogLevel         # noqa: E402
from campus_topo import build_net           # noqa: E402

SW = ("s1", "s2", "s3")
ATK, VIC, USER, SRV2 = "10.0.0.4", "10.0.0.1", "10.0.0.3", "10.0.0.2"
BLOCK = 15


def rules(sw):
    return sh("ovs-ofctl dump-flows %s 'ip,nw_src=%s'" % (sw, ATK))[1]


def path_rule(sw):
    return any("actions=drop" in l and "nw_dst=%s" % VIC in l for l in rules(sw).splitlines())


def host_rule(sw):
    return next((l for l in rules(sw).splitlines() if "actions=drop" in l and "nw_dst" not in l), "")


def clear_blocks():
    for s in SW:
        sh("ovs-ofctl del-flows %s 'ip,nw_src=%s'" % (s, ATK))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    a = ap.parse_args()
    K.require_sudo("test_aisprt_live.py")
    setLogLevel("error")
    sh("mn -c")
    K.remove("blocklist.txt", "block_events.csv", "aisprt.log")
    open(os.path.join(K.RESULTS, "blocklist.txt"), "w").close()
    R = K.Report("AIS-SPRT live closed-loop tests")
    K.pox_start(STATS_INTERVAL=30, BLOCK_SECONDS=BLOCK, PROTECT=VIC)
    wait_for(lambda: "Blocker ready" in K.pox_logs(), 20)
    net = build_net()
    eng = None
    rows = []
    try:
        h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
        R.check("T1", "network up", wait_for(K.all_connected, 20) and net.pingAll(timeout=2) == 0)
        h1.cmd("cd /tmp && python3 -m http.server 80 >/dev/null 2>&1 &")
        eng = subprocess.Popen([sys.executable, os.path.join(K.PROJECT, "detector", "live.py"), "--cooldown", "5"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        R.check("T2", "live AIS-SPRT engine running on mon0", eng.poll() is None and "AIS-SPRT live" in K.read("aisprt.log"))

        # benign: user browsing must not trigger anything
        for _ in range(10):
            h3.cmd("curl -s -o /dev/null http://%s/" % VIC)
            time.sleep(0.5)
        R.check("T3", "normal browsing: no block request", K.read("blocklist.txt") == "")

        for i in range(a.runs):
            wait_for(lambda: not any(path_rule(s) or host_rule(s) for s in SW), BLOCK * 8 + 20)
            time.sleep(3)                        # the controller logs EXPIRE within 1 s of the switch timeout
            h4.cmd("ping -D -i 0.2 %s > /tmp/aisprt_ping.txt 2>&1 &" % SRV2)
            time.sleep(1.5)
            t0 = time.time()
            scan = h4.popen(["python3", K.PROJECT + "/scripts/attacks/portscan.py", VIC, "--ports", "1-100", "--timeout", "0.2"])
            t_path = t_host = None
            while time.time() < t0 + 20 and (t_path is None or t_host is None):
                if t_path is None and all(path_rule(s) for s in SW):
                    t_path = time.time()
                if t_host is None and all(host_rule(s) for s in SW):
                    t_host = time.time()
                time.sleep(0.05)
            hard = re.search(r"hard_timeout=(\d+)", host_rule("s3"))
            user_ok = K.no_loss(h3.cmd("ping -c 2 -W 1 %s" % VIC))
            cut = K.full_loss(h4.cmd("ping -c 2 -W 1 %s" % SRV2))
            scan.terminate()
            scan.wait()
            h4.cmd("pkill -f 'ping -D -i 0.2'")
            text = open("/tmp/aisprt_ping.txt").read()
            replies = [float(x) for x in re.findall(r"^\[(\d+\.\d+)\] \d+ bytes from", text, re.M)]
            stop_gap = (max(replies) - t_host) if (replies and t_host) else None
            rows.append(dict(run=i + 1, kind="fast", path_s="%.2f" % (t_path - t0) if t_path else "",
                             host_s="%.2f" % (t_host - t0) if t_host else "", hard_timeout=hard.group(1) if hard else "",
                             user_ok=user_ok, attacker_cut=cut,
                             ping_stop_after_host_s="%.2f" % stop_gap if stop_gap is not None else ""))
            R.say("  run %d: path block %s s, host block %s s, hard_timeout %s, user ok %s, attacker cut %s"
                  % (i + 1, rows[-1]["path_s"], rows[-1]["host_s"], rows[-1]["hard_timeout"], user_ok, cut))

        fast = [r for r in rows if r["kind"] == "fast"]
        R.check("T4", "every fast scan: host block on all switches",
                all(r["host_s"] for r in fast), ", ".join(r["host_s"] or "-" for r in fast))
        R.check("T5", "path block lands no later than the host block",
                all(r["path_s"] and float(r["path_s"]) <= float(r["host_s"]) + 0.05 for r in fast if r["host_s"]))
        R.check("T6", "normal user unaffected and attacker cut in every run",
                all(r["user_ok"] and r["attacker_cut"] for r in fast))
        hts = [int(r["hard_timeout"]) for r in fast if r["hard_timeout"]]
        R.check("T7", "repeat offender: block time doubles (back-off)", len(hts) >= 2 and max(hts) >= 2 * min(hts) - 2,
                "hard timeouts: %s" % hts)

        # slow scan, 0.5 probes per second
        wait_for(lambda: not any(path_rule(s) or host_rule(s) for s in SW), BLOCK * 8 + 20)
        time.sleep(3)
        t0 = time.time()
        scan = h4.popen(["python3", K.PROJECT + "/scripts/attacks/portscan.py", VIC, "--ports", "200-260",
                         "--timeout", "0.2", "--delay", "2.0"])
        t_host = None
        while time.time() < t0 + 90 and t_host is None:
            if all(host_rule(s) for s in SW):
                t_host = time.time()
            time.sleep(0.2)
        scan.terminate()
        scan.wait()
        rows.append(dict(run=a.runs + 1, kind="slow 0.5/s", path_s="", host_s="%.2f" % (t_host - t0) if t_host else "",
                         hard_timeout="", user_ok="", attacker_cut="", ping_stop_after_host_s=""))
        R.check("T8", "slow scan (0.5 probes/s, below the window detector's 1.5/s floor) is blocked",
                t_host is not None, "%.1f s after start" % (t_host - t0) if t_host else "not blocked in 90 s")
        logs = K.pox_logs()
        R.check("T9", "controller logs contain no Python traceback", "Traceback" not in logs)
        with open(os.path.join(K.RESULTS, "aisprt_live-pox.log"), "w") as f:
            f.write(logs)
    finally:
        if eng:
            eng.terminate()
        net.stop()
        K.pox_stop()
    with open(os.path.join(K.RESULTS, "aisprt_live.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    ok = R.finish("aisprt_live_tests.txt")
    K.give_results_to_user()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
