#!/usr/bin/env python3
"""
Phase 4 evaluation: detection and blocking under background load.

    sudo python3 scripts/test_phase4.py

For each load level h3 sends an iperf TCP stream (plus a web request every second) to h1 through the core,
and after 6 s h4 scans 100 ports of h1. Measured per level: was the attacker detected and blocked, how fast,
false alarms for other hosts, PacMan's capture losses (kernel and queue) and CPU, and h3's throughput.
Writes results/phase4_load.csv, results/phase4_tests.txt. Exit code 0 only if every check passes.
"""
import csv
import io
import os
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labkit as K                          # noqa: E402
from labkit import sh, wait_for, drop_rule  # noqa: E402

from mininet.log import setLogLevel         # noqa: E402
from campus_topo import build_net           # noqa: E402

BLOCK_SECONDS = 15
ATTACKER, VICTIM = "10.0.0.4", "10.0.0.1"
SWITCHES = ("s1", "s2", "s3")
LEVELS = [("none", None), ("20 Mbit/s", "20M"), ("100 Mbit/s", "100M"), ("500 Mbit/s", "500M"), ("unlimited", "max")]
CHECKED = {"none", "20 Mbit/s", "100 Mbit/s", "500 Mbit/s"}     # "unlimited" is measured, not required
STATS = re.compile(r"^\[INFO\] (\S+ \S+) Capture stats: received (\d+), kernel dropped (\d+), queue dropped (\d+)")


def capture_stats():
    """Latest cumulative capture counters PacMan logged (received, kernel dropped, queue dropped)."""
    last = (0, 0, 0)
    for line in K.read("pacman.log").splitlines():
        m = STATS.match(line)
        if m:
            last = tuple(int(x) for x in m.groups()[1:])
    return last


def wait_next_stats(after_count):
    """Wait until PacMan logs a new stats line (they come every ~5 s)."""
    return wait_for(lambda: K.read("pacman.log").count("Capture stats:") > after_count, 12)


def events(kind, ip):
    rows = csv.DictReader(io.StringIO(K.read("block_events.csv")))
    return [r for r in rows if r["event"] == kind and r["ip"] == ip]


def cpu_seconds(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except OSError:
        return 0.0


def pacman_pid():
    _, out = sh("pgrep -f 'build/pacman live config/pacman-sdn.conf'")
    pids = [int(p) for p in out.split()]
    return max(pids) if pids else None


def main():
    K.require_sudo("test_phase4.py")
    setLogLevel("error")
    sh("mn -c")
    K.remove("blocklist.txt", "block_events.csv", "pacman.log", "flow_stats.csv")
    open(os.path.join(K.RESULTS, "blocklist.txt"), "w").close()
    R = K.Report("Phase 4 tests (load)")
    rows = []

    K.pox_start(STATS_INTERVAL=5, BLOCK_SECONDS=BLOCK_SECONDS, PROTECT=VICTIM)
    wait_for(lambda: "Blocker ready" in K.pox_logs(), 20)
    net = build_net()
    pacman = None
    try:
        h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
        R.check("T1", "network up: 3 switches connected, pingall ok",
                wait_for(K.all_connected, 20) and net.pingAll(timeout=2) == 0)
        h1.cmd("cd /tmp && python3 -m http.server 80 >/dev/null 2>&1 &")
        h1.cmd("iperf -s -p 5001 >/dev/null 2>&1 &")
        pacman = K.PacManLive()
        R.check("T2", "PacMan running live on mon0, logging capture statistics",
                wait_for(lambda: "Capture stats:" in K.read("pacman.log"), 15) and pacman.running())
        pid = pacman_pid()

        for name, rate in LEVELS:
            # quiet start: no block active, counters settled
            wait_for(lambda: not any(drop_rule(s, ATTACKER) for s in SWITCHES), BLOCK_SECONDS + 10)
            time.sleep(2)
            n_stats = K.read("pacman.log").count("Capture stats:")
            wait_next_stats(n_stats)
            recv0, kdrop0, qdrop0 = capture_stats()
            cpu0, wall0 = cpu_seconds(pid), time.time()
            n_blocks0 = len(events("BLOCK", ATTACKER))
            log0 = len(K.read("pacman.log").splitlines())

            iperf = None
            if rate:
                bw = "" if rate == "max" else "-b %s" % rate
                iperf = h3.popen("iperf -c %s -p 5001 -t 22 -i 22 %s -f m" % (VICTIM, bw), shell=True)
            web = h3.popen("for i in $(seq 1 20); do curl -s -o /dev/null http://%s/; sleep 1; done" % VICTIM, shell=True)
            time.sleep(6)

            t0 = time.time()
            scan = h4.popen(["python3", K.PROJECT + "/scripts/attacks/portscan.py", VICTIM,
                             "--ports", "1-100", "--timeout", "0.2"])
            t_rules = None
            while time.time() < t0 + 15 and t_rules is None:
                if all(drop_rule(s, ATTACKER) for s in SWITCHES):
                    t_rules = time.time()
                time.sleep(0.05)
            # Check reachability now, while the block is certainly active: once blocked, the scan's
            # remaining probes time out one by one and can outlast a 15 s block.
            blocked_ok = t_rules is not None and len(events("BLOCK", ATTACKER)) > n_blocks0
            user_ok = K.no_loss(h3.cmd("ping -c 2 -W 1 %s" % VICTIM)) if blocked_ok else False
            atk_cut = K.full_loss(h4.cmd("ping -c 2 -W 1 %s" % VICTIM)) if blocked_ok else False
            scan.wait()

            mbps = ""
            if iperf:
                out = iperf.communicate()[0]
                out = out.decode() if isinstance(out, bytes) else out
                m = re.findall(r"([\d.]+) Mbits/sec", out)
                mbps = m[-1] if m else "?"
            web.wait()

            n_stats = K.read("pacman.log").count("Capture stats:")
            wait_next_stats(n_stats)
            recv1, kdrop1, qdrop1 = capture_stats()
            cpu1, wall1 = cpu_seconds(pid), time.time()
            new_lines = K.read("pacman.log").splitlines()[log0:]
            false_high = [l for l in new_lines if ("port scan" in l or "SYN flood" in l) and "source=%s" % ATTACKER not in l]

            recv, kdrop, qdrop = recv1 - recv0, kdrop1 - kdrop0, qdrop1 - qdrop0
            loss = 100.0 * (kdrop + qdrop) / recv if recv else 0.0
            cpu = 100.0 * (cpu1 - cpu0) / (wall1 - wall0)
            secs = "%.2f" % (t_rules - t0) if t_rules else "not blocked"
            rows.append({"load": name, "h3_throughput_mbps": mbps or "-", "packets_seen": recv,
                         "kernel_dropped": kdrop, "queue_dropped": qdrop, "capture_loss_pct": "%.1f" % loss,
                         "pacman_cpu_pct": "%.0f" % cpu, "scan_to_block_s": secs,
                         "attacker_cut": "yes" if atk_cut else "no", "user_ok": "yes" if user_ok else "no",
                         "false_high_alerts": len(false_high)})
            detail = "block %s s, h3 %s Mbit/s, %d pkts, loss %.1f%%, PacMan CPU %.0f%%" % (
                secs, mbps or "-", recv, loss, cpu)
            ok = blocked_ok and atk_cut and user_ok and not false_high
            if name in CHECKED:
                R.check("L%d" % (len(rows)), "load %-10s: attacker detected and blocked, user unaffected, no false alarm"
                        % name, ok, detail)
            else:
                R.say("[INFO] L%d   load %-10s (measured only): %s%s" % (len(rows), name, detail,
                      "" if ok else "  -> attacker NOT blocked in 15 s"))

        logs = K.pox_logs()
        R.check("E1", "controller logs contain no Python traceback", "Traceback" not in logs)
        R.check("E2", "PacMan still running after all load levels", pacman.running())
    finally:
        if pacman:
            pacman.stop()
        net.stop()
        K.pox_stop()

    with open(os.path.join(K.RESULTS, "phase4_load.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    R.say("")
    R.say("%-11s %8s %9s %9s %7s %5s %9s" % ("load", "h3 Mb/s", "packets", "loss %", "CPU %", "cut", "block s"))
    for r in rows:
        R.say("%-11s %8s %9s %9s %7s %5s %9s" % (r["load"], r["h3_throughput_mbps"], r["packets_seen"],
              r["capture_loss_pct"], r["pacman_cpu_pct"], r["attacker_cut"], r["scan_to_block_s"]))
    ok = R.finish("phase4_tests.txt")
    K.give_results_to_user()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
