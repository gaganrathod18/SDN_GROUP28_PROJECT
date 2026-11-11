#!/usr/bin/env python3
"""
Phase 2 automated checks: SDN network + monitoring.

    sudo python3 scripts/test_phase2.py

Starts POX itself (as the normal user, rootless Podman), builds the campus topology and checks
forwarding, the core mirror, PacMan on mon0, the controller's flow statistics and the edge cases
(controller restart, uplink failure, bad arguments). Prints PASS/FAIL per check and writes
results/phase2_tests.txt. Exit code 0 only if every check passes.
"""
import csv
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

sys.dont_write_bytecode = True
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, "topology"))

from mininet.log import setLogLevel  # noqa: E402
from campus_topo import build_net    # noqa: E402

RESULTS = os.path.join(PROJECT, "results")
STATS = os.path.join(RESULTS, "flow_stats.csv")
PACMAN = os.environ.get("PACMAN_BIN", os.path.join(os.path.dirname(PROJECT), "pacman", "build", "pacman"))
USER = os.environ.get("SUDO_USER")
INTERVAL = 2                                 # faster polling for the test run

lines = []
results = []


def say(text=""):
    print(text)
    lines.append(text)


def check(cid, name, ok, detail=""):
    results.append((cid, ok))
    say("[%s] %-4s %s%s" % ("PASS" if ok else "FAIL", cid, name, ("  -> " + detail) if detail else ""))
    return ok


def sh(cmd, timeout=60):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def as_user(cmd, timeout=60):
    """Run a command as the invoking user (rootless Podman lives there, not under root)."""
    uid = int(os.environ.get("SUDO_UID", "0"))
    return sh("runuser -u %s -- env XDG_RUNTIME_DIR=/run/user/%d %s" % (USER, uid, cmd), timeout)


def pox_start():
    return as_user("env STATS_INTERVAL=%d %s/scripts/run_pox.sh -d" % (INTERVAL, PROJECT))


def pox_stop():
    as_user("podman rm -f -t 0 pacman-pox")


def pox_logs():
    return as_user("podman logs pacman-pox")[1]


def no_loss(ping_output):
    return re.search(r"(?<!\d)0% packet loss", ping_output) is not None


def run_tty(cmd, seconds):
    """Run cmd on a pseudo-terminal (PacMan's dashboard needs one) for up to `seconds`.
    Returns (exit_code or None if still running, output)."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 170, 0, 0))
    p = subprocess.Popen(cmd, shell=True, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    out = b""
    end = time.time() + seconds
    while time.time() < end and p.poll() is None:
        if select.select([master], [], [], 0.2)[0]:
            try:
                out += os.read(master, 65536)
            except OSError:
                break
    try:                                     # the terminal closes as the process exits: reap it
        code = p.wait(1 if time.time() < end else 0.1)
    except subprocess.TimeoutExpired:
        code = None
    if code is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
    os.close(master)
    return code, re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out.decode(errors="replace"))


def wait_for(fn, timeout, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(step)
    return False


def all_connected():
    rc, out = sh("ovs-vsctl --columns=is_connected list controller")
    vals = re.findall(r"is_connected\s*:\s*(\w+)", out)
    return len(vals) == 3 and all(v == "true" for v in vals)


def capture(seconds, action, iface="mon0"):
    """tcpdump on iface while `action` runs; returns the decoded lines."""
    p = subprocess.Popen("timeout %d tcpdump -l -nn -i %s 2>/dev/null" % (seconds, iface),
                         shell=True, stdout=subprocess.PIPE, text=True)
    time.sleep(1)
    action()
    out, _ = p.communicate()
    return [l for l in out.splitlines() if l.strip()]


def stats_rows():
    if not os.path.exists(STATS):
        return []
    with open(STATS) as f:
        return list(csv.DictReader(f))


def main():
    if os.geteuid() != 0 or not USER:
        sys.exit("run with sudo from your normal user:  sudo python3 scripts/test_phase2.py")
    if not os.access(PACMAN, os.X_OK):
        sys.exit("PacMan binary not found: %s" % PACMAN)

    setLogLevel("error")
    sh("mn -c")
    for path in (STATS, os.path.join(RESULTS, "blocklist.txt"), os.path.join(RESULTS, "block_events.csv")):
        if os.path.exists(path):      # a fresh block request left by another run would be re-applied
            os.remove(path)
    say("Phase 2 tests  ·  %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    say("=" * 60)

    # ------------------------------------------------ edge: bad controller arguments
    rc, out = as_user("podman run --rm --network none -v %s/../pox:/pox:Z -v %s/controller:/c:ro,Z "
                      "-e PYTHONPATH=/c -e PYTHONDONTWRITEBYTECODE=1 python:2.7 "
                      "python /pox/pox.py pacman_ips --interval=0" % (PROJECT, PROJECT), timeout=60)
    check("E1", "POX refuses --interval=0", "interval must be > 0" in out, "error shown, controller not started")

    rc, out = pox_start()
    check("T1", "POX container starts", rc == 0, out.strip()[:12])
    wait_for(lambda: "POX 0.2.0" in pox_logs() and "Flow monitor ready" in pox_logs(), 20)

    net = build_net()
    try:
        h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")

        ok = wait_for(all_connected, 20)
        check("T2", "all 3 switches connected to POX", ok)

        loss = net.pingAll(timeout=2)
        check("T3", "pingall across 3 switches", loss == 0, "%.0f%% loss" % loss)

        counts = {s: int(sh("ovs-ofctl dump-flows %s | grep -c priority" % s)[1].strip() or 0) for s in ("s1", "s2", "s3")}
        check("T4", "learned flows installed on every switch", all(c > 0 for c in counts.values()),
              ", ".join("%s=%d" % kv for kv in sorted(counts.items())))

        # ---------------------------------------------- mirror configuration
        _, mir = sh("ovs-vsctl list mirror")
        _, desc = sh("ovs-ofctl dump-ports-desc s1")
        mon_desc = desc[desc.find("(mon0)"):][:200]
        _, addr = sh("ip -o addr show dev mon0")
        check("T5", "mirror on s1: select-all → mon0, NO_FLOOD, no IP on mon0",
              "select_all          : true" in mir and "NO_FLOOD" in mon_desc and addr.strip() == "",
              "mirror ok" if "select_all          : true" in mir else "mirror missing")

        # ---------------------------------------------- mirror carries cross-zone traffic
        pkts = capture(5, lambda: h3.cmd("ping -c 3 -i 0.3 10.0.0.1"))
        req = sum(1 for l in pkts if "10.0.0.3 > 10.0.0.1: ICMP echo request" in l)
        rep = sum(1 for l in pkts if "10.0.0.1 > 10.0.0.3: ICMP echo reply" in l)
        check("T6", "mon0 sees h3 → h1 traffic (cross-zone)", req >= 3 and rep >= 3,
              "%d requests, %d replies captured for 3 pings" % (req, rep))

        p = subprocess.Popen("timeout 6 tcpdump -l -e -nn -i mon0 2>/dev/null", shell=True,
                             stdout=subprocess.PIPE, text=True)
        idle = [l for l in p.communicate()[0].splitlines() if l.strip()]
        foreign = [l for l in idle if not re.match(r"\S+ 00:00:00:00:00:0[1-4] > ", l) or "IPv6" in l]
        check("E2", "idle network: mon0 carries only Mininet hosts' packets (no host IPv6/mDNS leak)",
              not foreign, "%d packet(s) in 6 s idle, %d foreign" % (len(idle), len(foreign)))

        intra = capture(5, lambda: h1.cmd("ping -c 3 -i 0.3 10.0.0.2"))
        icmp = sum(1 for l in intra if "ICMP" in l)
        check("E3", "intra-zone h1 → h2 traffic does not cross the core (known limit)", icmp == 0,
              "%d ICMP packet(s) on mon0" % icmp)

        # ---------------------------------------------- HTTP + PacMan on a mirror capture
        h1.cmd("cd /tmp && python3 -m http.server 80 >/dev/null 2>&1 &")
        time.sleep(1)
        pcap = "/tmp/pacman_phase2_mon0.pcap"
        p = subprocess.Popen("timeout 8 tcpdump -nn -i mon0 -w %s 2>/dev/null" % pcap, shell=True)
        time.sleep(1)
        http = h3.cmd("curl -s -o /dev/null -w '%{http_code}' http://10.0.0.1/")
        h4.cmd("curl -s -o /dev/null http://10.0.0.2:80/ --max-time 2")
        h3.cmd("ping -c 2 10.0.0.2")
        p.wait()
        check("T7", "HTTP h3 → h1 works", http.strip().endswith("200"), "HTTP %s" % http.strip())

        rc, out = sh("cd %s && %s analyze %s config/pacman-sdn.conf" % (PROJECT, PACMAN, pcap))
        out = re.sub(r"\x1b\[[0-9;]*m", "", out)
        flows = int((re.search(r"Flows\s*:\s*(\d+)", out) or [0, 0])[1])
        with open(os.path.join(RESULTS, "phase2-pacman-mon0-analysis.txt"), "w") as f:
            f.write(out)
        check("T8", "PacMan decodes the mon0 capture (flows + HTTP class)", rc == 0 and flows > 0 and "HTTP" in out,
              "%d flows" % flows)

        # ---------------------------------------------- PacMan live on mon0 (and bad interface)
        log = os.path.join(RESULTS, "pacman.log")
        if os.path.exists(log):
            os.remove(log)
        code, _ = run_tty("cd %s && exec %s live config/pacman-sdn.conf --iface mon0" % (PROJECT, PACMAN), 6)
        text = open(log).read() if os.path.exists(log) else ""
        check("T9", "PacMan live dashboard runs on mon0 (--iface, no menu)",
              code is None and "Starting live capture on interface mon0" in text and "failed" not in text,
              "still running after 6 s; log: " + (text.strip().splitlines()[0][:70] if text.strip() else "empty"))

        code, out = run_tty("cd %s && exec %s live config/pacman-sdn.conf --iface nosuch0" % (PROJECT, PACMAN), 6)
        msg = re.sub(r"\s+", " ", out.strip())
        check("E4", "PacMan exits with an error on a missing interface", code not in (None, 0) and "failed" in msg,
              "exit %s: %s" % (code, msg[:60]))

        # ---------------------------------------------- controller flow statistics
        wait_for(lambda: len({r["switch"] for r in stats_rows()}) == 3, 3 * INTERVAL + 5)
        rows = stats_rows()
        switches = sorted({r["switch"] for r in rows})
        check("T10", "flow_stats.csv has rows from all 3 switches", len(switches) == 3, ", ".join(switches))

        def h3_h1_bytes():
            vals = [int(r["bytes"]) for r in stats_rows() if r["switch"].endswith("01")
                    and r["nw_src"] == "10.0.0.3" and r["nw_dst"] == "10.0.0.1" and r["dl_type"] == "0x0800"]
            return max(vals) if vals else 0
        h3.cmd("ping -c 2 10.0.0.1")
        time.sleep(INTERVAL + 1)
        before = h3_h1_bytes()
        h3.cmd("ping -c 20 -i 0.05 10.0.0.1")
        time.sleep(INTERVAL + 1.5)
        after = h3_h1_bytes()
        check("T11", "byte counters for h3 → h1 grow between polls", after > before, "%d → %d bytes" % (before, after))

        # ---------------------------------------------- edge: controller down / restart
        first_logs = pox_logs()
        pox_stop()
        down = wait_for(lambda: not all_connected(), 15)
        for s in ("s1", "s2", "s3"):
            sh("ovs-ofctl del-flows %s" % s)
        lost = h3.cmd("ping -c 2 -W 1 10.0.0.2")
        check("E5", "controller down: switches lose it, new flows are not forwarded (fail-secure)",
              down and "100% packet loss" in lost)

        pox_start()
        back = wait_for(all_connected, 30)
        ok = wait_for(lambda: no_loss(h3.cmd("ping -c 2 -W 1 10.0.0.2")), 20, step=1)
        check("E6", "controller restart: switches reconnect and traffic recovers", back and ok)
        n_before = len(stats_rows())
        time.sleep(2 * INTERVAL + 1)
        check("E7", "flow statistics resume after the restart", len(stats_rows()) > n_before,
              "%d → %d rows" % (n_before, len(stats_rows())))

        # ---------------------------------------------- edge: uplink failure
        net.configLinkStatus("s1", "s3", "down")
        cut = h3.cmd("ping -c 2 -W 1 10.0.0.1")
        net.configLinkStatus("s1", "s3", "up")
        healed = wait_for(lambda: no_loss(h3.cmd("ping -c 2 -W 1 10.0.0.1")), 30, step=1)
        check("E8", "uplink s1–s3 down: user zone cut off; link up: recovers",
              "100% packet loss" in cut and healed)

        # ---------------------------------------------- edge: one switch leaves and rejoins
        sh("ovs-vsctl del-controller s3")
        left = wait_for(lambda: "00-00-00-00-00-03 disconnected (2 switch(es) monitored)" in pox_logs(), 15)
        n0 = len(stats_rows())
        time.sleep(2 * INTERVAL + 1)
        recent = {r["switch"] for r in stats_rows()[n0:]}
        sh("ovs-vsctl set-controller s3 tcp:127.0.0.1:6633")
        rejoined = wait_for(all_connected, 20)
        check("E9", "switch s3 leaves: monitor drops it and keeps polling s1/s2; s3 rejoins",
              left and "00-00-00-00-00-03" not in recent and rejoined and len(recent) == 2,
              "polled while s3 away: %s" % ", ".join(sorted(recent)))

        logs = first_logs + pox_logs()
        with open(os.path.join(RESULTS, "phase2-pox.log"), "w") as f:
            f.write(logs)
        check("E10", "controller logs contain no Python traceback", "Traceback" not in logs)
    finally:
        net.stop()
        pox_stop()
        for path in (STATS, os.path.join(RESULTS, "pacman.log")):
            if os.path.exists(path):
                os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        sh("chown -R %s:%s %s" % (os.environ["SUDO_UID"], os.environ["SUDO_GID"], RESULTS))

    passed = sum(1 for _, ok in results if ok)
    say("=" * 60)
    say("%d/%d checks passed" % (passed, len(results)))
    with open(os.path.join(RESULTS, "phase2_tests.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chown(os.path.join(RESULTS, "phase2_tests.txt"), int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
