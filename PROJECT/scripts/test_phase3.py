#!/usr/bin/env python3
"""
Phase 3 automated checks: anomaly detection + SDN mitigation.

    sudo python3 scripts/test_phase3.py

Starts POX (20 s blocks, 10.0.0.1 protected), the campus network and PacMan in SDN mode, then checks:
no false alarms on normal traffic, scan -> alert -> blocklist -> drop rules on every switch, attacker cut
off while other hosts keep working, block expiry and re-blocking, plus edge cases for the blocklist
(protected, invalid, stale, half-written, truncated) and controller/switch restarts.
Writes results/phase3_tests.txt and results/phase3_timing.txt. Exit code 0 only if every check passes.
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

BLOCK_SECONDS = 20
ATTACKER, VICTIM, USER, SERVER2 = "10.0.0.4", "10.0.0.1", "10.0.0.3", "10.0.0.2"
SWITCHES = ("s1", "s2", "s3")
BLOCKLIST = os.path.join(K.RESULTS, "blocklist.txt")
TEST_CONF = "/tmp/pacman-sdn-test.conf"


def events(kind=None, ip=None):
    rows = list(csv.DictReader(io.StringIO(K.read("block_events.csv"))))
    return [r for r in rows if (kind is None or r["event"] == kind) and (ip is None or r["ip"] == ip)]


def append_blocklist(text):
    with open(BLOCKLIST, "a") as f:
        f.write(text)


def pacman_alerts(kind_text, ip):
    return [l for l in K.read("pacman.log").splitlines() if kind_text in l and "source=%s" % ip in l]


def main():
    K.require_sudo("test_phase3.py")
    setLogLevel("error")
    sh("mn -c")
    K.remove("blocklist.txt", "block_events.csv", "pacman.log", "flow_stats.csv")
    open(BLOCKLIST, "w").close()                    # owned by root here, like after a careless sudo run
    os.chmod(BLOCKLIST, 0o644)
    R = K.Report("Phase 3 tests")
    timing = []

    K.pox_start(STATS_INTERVAL=5, BLOCK_SECONDS=BLOCK_SECONDS, PROTECT=VICTIM)
    wait_for(lambda: "Blocker ready" in K.pox_logs(), 20)
    net = build_net()
    pacman = None
    try:
        h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
        R.check("T1", "network up: 3 switches connected, pingall ok",
                wait_for(K.all_connected, 20) and net.pingAll(timeout=2) == 0)
        h1.cmd("cd /tmp && python3 -m http.server 80 >/dev/null 2>&1 &")
        h2.cmd("cd /tmp && python3 -m http.server 8080 >/dev/null 2>&1 &")
        # Test copy of the config: 10 s cooldown, so it stays shorter than the 20 s test block
        # (the cooldown must always be shorter than the block time, or re-blocking is delayed).
        with open(os.path.join(K.PROJECT, "config", "pacman-sdn.conf")) as f:
            conf = f.read().replace("block_cooldown_s=30", "block_cooldown_s=10")
        with open(TEST_CONF, "w") as f:
            f.write(conf)
        pacman = K.PacManLive(config=TEST_CONF)
        R.check("T2", "PacMan running live on mon0 in SDN mode",
                wait_for(lambda: "Firewall mode: sdn" in K.read("pacman.log"), 10) and pacman.running())

        # ---------------------------------------------- normal traffic must not trigger anything
        for _ in range(15):
            h3.cmd("curl -s -o /dev/null http://10.0.0.1/")
            h4.cmd("curl -s -o /dev/null http://10.0.0.1/")
            h3.cmd("curl -s -o /dev/null http://10.0.0.2:8080/")
            time.sleep(1)
        h3.cmd("ping -c 5 -i 0.2 10.0.0.2")
        high = [l for l in K.read("pacman.log").splitlines() if "port scan" in l or "SYN flood" in l]
        R.check("T3", "normal traffic for 15 s (2 clients, 2 web servers): no HIGH alert, no block request",
                not high and K.read("blocklist.txt") == "", "%d HIGH alerts" % len(high))

        time.sleep(11)                                  # let h3's earlier connections leave the 10 s window
        sweep = h3.cmd("python3 %s/scripts/attacks/portscan.py 10.0.0.2 --ports 1-15 --timeout 0.2" % K.PROJECT)
        time.sleep(2)
        R.check("E1", "boundary: 15 distinct ports (= threshold) is not reported",
                not pacman_alerts("port scan", USER) and "scanned 15" in sweep)

        # ---------------------------------------------- the attack
        cap = subprocess.Popen("exec tcpdump -nn -i mon0 -w /tmp/phase3_scan.pcap 'host %s'" % ATTACKER,
                               shell=True, stderr=subprocess.DEVNULL)
        h4.cmd("ping -D -i 0.2 %s > /tmp/h4_ping.txt 2>&1 &" % SERVER2)   # an existing flow of the attacker
        time.sleep(2)
        t0 = time.time()
        scan = h4.popen(["python3", K.PROJECT + "/scripts/attacks/portscan.py", VICTIM,
                         "--ports", "1-100", "--timeout", "0.2"])
        t_req = t_rules = None
        end = t0 + 15
        while time.time() < end and (t_req is None or t_rules is None):
            if t_req is None and os.path.exists(BLOCKLIST) and ATTACKER in K.read("blocklist.txt"):
                t_req = time.time()
            if t_rules is None and all(drop_rule(s, ATTACKER) for s in SWITCHES):
                t_rules = time.time()
            time.sleep(0.05)
        scan.terminate()
        scan.wait()
        time.sleep(1)
        cap.terminate()
        cap.wait()
        h4.cmd("pkill -f 'ping -D -i 0.2'")

        R.check("T4", "scan detected: PacMan raises PORT_SCAN (HIGH) for the attacker",
                pacman_alerts("Possible port scan detected", ATTACKER))
        line = next((l for l in K.read("blocklist.txt").splitlines() if l.startswith(ATTACKER)), "")
        fields = line.split("\t")
        R.check("T5", "block request written: '<ip>\\t<unix time>\\t<reason>'",
                len(fields) == 3 and fields[1].isdigit() and "port scan" in fields[2],
                "%.2f s after scan start" % (t_req - t0) if t_req else "not written")
        blocks = events("BLOCK", ATTACKER)
        R.check("T6", "controller blocks the attacker on all 3 switches",
                blocks and blocks[0]["switches"] == "3" and t_rules is not None,
                "drop rules on s1, s2, s3 %.2f s after scan start" % (t_rules - t0) if t_rules else "rules missing")
        rule = drop_rule("s3", ATTACKER)
        hard = re.search(r"hard_timeout=(\d+)", rule)
        R.check("T7", "drop rule: ip, nw_src=attacker, actions=drop, priority 65000, hard_timeout ≈ block time",
                "priority=65000" in rule and hard and BLOCK_SECONDS - 3 <= int(hard.group(1)) <= BLOCK_SECONDS,
                rule[rule.find("hard_timeout"):][:80])
        timing.append("scan start -> block request (PacMan)      : %.2f s" % (t_req - t0) if t_req else "no request")
        timing.append("scan start -> drop rules on all switches  : %.2f s" % (t_rules - t0) if t_rules else "no rules")

        a2 = h4.cmd("ping -c 3 -W 1 %s" % SERVER2)
        a1 = h4.cmd("ping -c 3 -W 1 %s" % VICTIM)
        R.check("T8", "attacker cut off from both servers", K.full_loss(a1) and K.full_loss(a2))

        # existing flow h4 -> h2 must stop at once (its exact-match entries were deleted)
        replies = [float(m) for m in re.findall(r"^\[(\d+\.\d+)\] \d+ bytes from", open("/tmp/h4_ping.txt").read(), re.M)]
        last = max(replies) if replies else 0
        gap = (last - t_rules) if t_rules else 99
        R.check("T9", "attacker's already-running flow stops when the block lands (not after idle timeout)",
                replies and gap < 1.0, "last reply %.2f s after rules installed" % gap)
        timing.append("drop rules -> attacker's running ping stops : %.2f s" % max(gap, 0))

        u1 = h3.cmd("ping -c 3 -W 1 %s" % VICTIM)
        u2 = h3.cmd("ping -c 3 -W 1 %s" % SERVER2)
        web = h3.cmd("curl -s -o /dev/null -w '%%{http_code}' http://%s/" % VICTIM)
        R.check("T10", "normal user h3 unaffected (both servers, HTTP)", K.no_loss(u1) and K.no_loss(u2) and "200" in web)
        _, s3_rule = sh("ovs-ofctl dump-flows s3 'ip,nw_src=%s'" % ATTACKER)
        dropped = re.search(r"n_packets=(\d+)", s3_rule)
        R.check("T11", "attacker's packets are discarded at its edge switch s3",
                dropped and int(dropped.group(1)) > 0, "n_packets=%s on s3" % (dropped.group(1) if dropped else "?"))

        # ---------------------------------------------- expiry and re-block
        expired = wait_for(lambda: events("EXPIRE", ATTACKER), BLOCK_SECONDS + 10)
        gone = wait_for(lambda: not any(drop_rule(s, ATTACKER) for s in SWITCHES), 5)
        back = wait_for(lambda: K.no_loss(h4.cmd("ping -c 2 -W 1 %s" % SERVER2)), 10, step=1)
        R.check("T12", "block expires after %d s: rules gone, attacker reachable again" % BLOCK_SECONDS,
                expired and gone and back)

        time.sleep(1)
        n_lines = len([l for l in K.read("blocklist.txt").splitlines() if l.startswith(ATTACKER)])
        h4.cmd("python3 %s/scripts/attacks/portscan.py %s --ports 1-60 --timeout 0.2" % (K.PROJECT, VICTIM))
        reblocked = wait_for(lambda: len(events("BLOCK", ATTACKER)) >= 2, 10)
        R.check("T13", "attacker scans again after expiry: detected and blocked again", reblocked,
                "%d BLOCK events" % len(events("BLOCK", ATTACKER)))
        n_after = len([l for l in K.read("blocklist.txt").splitlines() if l.startswith(ATTACKER)])
        R.check("E2", "PacMan cooldown: one blocklist line per detection, not one per alert",
                n_lines == 1 and n_after == 2, "%d line(s) after first scan, %d after second" % (n_lines, n_after))

        # ---------------------------------------------- blocklist edge cases (written by hand)
        now = int(time.time())
        append_blocklist("%s\t%d\tmanual: try to block the protected web server\n" % (VICTIM, now))
        ok = wait_for(lambda: events("SKIP_PROTECTED", VICTIM), 5)
        R.check("E3", "protected IP (web server) is never blocked",
                ok and not drop_rule("s2", VICTIM) and K.no_loss(h3.cmd("ping -c 2 -W 1 %s" % VICTIM)))

        append_blocklist("# a comment line\n\ngarbage line\n999.1.1.1\t%d\tbad octet\n224.0.0.5\t%d\tmulticast\n" % (now, now))
        ok = wait_for(lambda: len(events("INVALID")) >= 3, 5)
        R.check("E4", "invalid entries ignored (text, bad octet, multicast); comments and blank lines skipped",
                ok and len(events("INVALID")) == 3 and not drop_rule("s1", "224.0.0.5"),
                "%d INVALID events" % len(events("INVALID")))

        append_blocklist("%s\t%d\tvery old request\n" % (USER, now - 1000))
        ok = wait_for(lambda: events("STALE", USER), 5)
        R.check("E5", "stale request (older than the block time) is not applied",
                ok and not drop_rule("s3", USER) and K.no_loss(h3.cmd("ping -c 2 -W 1 %s" % SERVER2)))

        append_blocklist("10.0.0.99")                       # half-written line
        time.sleep(2.5)
        early = events(ip="10.0.0.99")
        append_blocklist("\t%d\thalf-written line test\n" % int(time.time()))
        ok = wait_for(lambda: events("BLOCK", "10.0.0.99"), 5)
        R.check("E6", "half-written line is waited for, then applied once complete", not early and ok)

        with open(BLOCKLIST, "w") as f:                     # truncated in place (same inode, shorter)
            f.write("10.0.0.98\t%d\ttruncate test\n" % int(time.time()))
        ok = wait_for(lambda: events("BLOCK", "10.0.0.98"), 5)
        R.check("E7", "blocklist truncated: controller starts reading it from the top again",
                ok and all(drop_rule(s, "10.0.0.98") for s in SWITCHES))

        # ---------------------------------------------- restarts
        first_logs = K.pox_logs()
        K.pox_stop()
        wait_for(lambda: not K.all_connected(), 15)
        for s in SWITCHES:
            sh("ovs-ofctl del-flows %s" % s)                # switches lose every rule
        rc, out = K.pox_start(STATS_INTERVAL=5, BLOCK_SECONDS=120, PROTECT=VICTIM)   # outlasts the restart
        ok = wait_for(lambda: K.all_connected() and all(drop_rule(s, "10.0.0.98") for s in SWITCHES), 30)
        restart_diag = "restart rc=%s out=%s\n%s\n%s" % (rc, out.strip(), K.as_user("podman ps -a")[1], K.pox_logs())
        R.check("E8", "controller restart: still-running blocks are re-read and re-installed on every switch",
                ok and len(events("REAPPLY", "10.0.0.98")) >= 3)

        n_reapply = len(events("REAPPLY", "10.0.0.98"))
        sh("ovs-vsctl del-controller s3")
        wait_for(lambda: "00-00-00-00-00-03 disconnected" in K.pox_logs(), 15)
        sh("ovs-ofctl del-flows s3")
        sh("ovs-vsctl set-controller s3 tcp:127.0.0.1:6633")
        ok = wait_for(lambda: drop_rule("s3", "10.0.0.98"), 20)
        R.check("E9", "switch reconnects: it gets the running blocks again", ok and len(events("REAPPLY", "10.0.0.98")) > n_reapply)

        logs = first_logs + "\n----- after restart -----\n" + restart_diag + "\n----- end -----\n" + K.pox_logs()
        with open(os.path.join(K.RESULTS, "phase3-pox.log"), "w") as f:
            f.write(logs)
        R.check("E10", "controller logs contain no Python traceback", "Traceback" not in logs)
    finally:
        if pacman:
            pacman.stop()
        net.stop()
        K.pox_stop()

    # ---------------------------------------------- offline: passive vs SDN mode on the recorded scan
    passive = "/tmp/pacman-passive.conf"
    with open(os.path.join(K.PROJECT, "config", "pacman-sdn.conf")) as f:
        conf = f.read()
    with open(passive, "w") as f:
        f.write(conf.replace("firewall_mode=sdn", "firewall_mode=passive")
                    .replace("blocklist_file=results/blocklist.txt", "blocklist_file=/tmp/passive-blocklist.txt")
                    .replace("log_file=results/pacman.log", "log_file=/tmp/passive.log"))
    for p in ("/tmp/passive-blocklist.txt",):
        if os.path.exists(p):
            os.remove(p)
    rc, out = sh("cd %s && %s analyze /tmp/phase3_scan.pcap %s" % (K.PROJECT, K.PACMAN, passive))
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    with open(os.path.join(K.RESULTS, "phase3-scan-pcap-analysis.txt"), "w") as f:
        f.write(out)
    R.check("E11", "passive mode: the recorded scan is still detected offline, but nothing is written",
            rc == 0 and "[HIGH] %s - Possible port scan detected" % ATTACKER in out
            and not os.path.exists("/tmp/passive-blocklist.txt"))

    before = K.read("blocklist.txt")
    rc, out = sh("cd %s && %s analyze /tmp/phase3_scan.pcap config/pacman-sdn.conf" % (K.PROJECT, K.PACMAN))
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    R.check("E12", "offline analysis with the SDN config never writes block requests (recordings are history)",
            rc == 0 and "[HIGH] %s" % ATTACKER in out and K.read("blocklist.txt") == before)

    with open(os.path.join(K.RESULTS, "phase3_timing.txt"), "w") as f:
        f.write("\n".join(timing) + "\n")
    for t in timing:
        R.say("  timing: " + t)
    ok = R.finish("phase3_tests.txt")
    K.give_results_to_user()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
