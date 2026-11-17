#!/usr/bin/env python3
"""
Demo console for terminal T4 (AIS-SPRT + graded SDN blocking).

    python3 test.py            menu; type a number (or its name) to run that step
    python3 test.py 4          run step 4 directly
    python3 test.py live       Mininet commands to copy into T2

Start first: T1 `BLOCK_SECONDS=30 scripts/run_pox.sh`, T2 `sudo python3 topology/campus_topo.py`,
T3 `scripts/run_pacman.sh frontend`. This console starts the AIS-SPRT engine (detector/live.py) by itself.
Each step explains what it does, types and runs its commands with their real output, prints the AIS-SPRT
decisions it caused, and says what to watch in T1 (POX), T2 (Mininet) and T3 (PacMan).
"""
import csv
import os
import subprocess
import sys
import time

PROJECT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT)
LOG = os.path.join(PROJECT, "results", "aisprt.log")

R, B, D = "\033[0m", "\033[1m", "\033[2m"
GREEN, YELLOW, CYAN, MAGENTA, RED, BLUE = "\033[92m", "\033[93m", "\033[96m", "\033[95m", "\033[91m", "\033[94m"

WAIT_FREE = ("n=0; while sudo ovs-ofctl dump-flows s3 ip,nw_src=10.0.0.4 | grep -q actions=drop; do "
             "printf '\\r  waiting for the previous block on 10.0.0.4 to expire... %3ds' $n; sleep 1; n=$((n+1)); done; echo")
RULES = ('for s in s1 s2 s3; do echo "== $s"; sudo ovs-ofctl --no-stats dump-flows $s ip,nw_src=10.0.0.4 '
         '| grep actions=drop || echo "   (no drop rule)"; done')

TESTS = [
    {"key": "check", "title": "Environment check",
     "why": "Checks every tool the project needs: Mininet, Open vSwitch, Podman with python:2.7, POX, PacMan, sudo.",
     "files": "scripts/check_env.sh",
     "cmds": ["scripts/check_env.sh"],
     "look": {"T4": "every line [ OK ] (port 6633 shows 'in use' once POX runs)."}, "needs_net": False},

    {"key": "status", "title": "Is everything running?",
     "why": "Shows the POX container, the three switch connections, the Mininet hosts, PacMan and the AIS-SPRT engine.",
     "files": "Podman, Open vSwitch, process list",
     "cmds": ["podman ps --format '{{.Names}}  {{.Status}}'",
              "sudo ovs-vsctl --columns=target,is_connected list controller | grep is_connected",
              "pgrep -af 'mininet:h[1-4]$' | sed 's/^/  /'",
              "pgrep -ax pacman | sed 's/^/  /' || echo '  PacMan not running (T3)'",
              "pgrep -af '[d]etector/live.py' | grep -v sudo | sed 's/^/  /' || echo '  AIS-SPRT engine not running'"],
     "look": {"T4": "pacman-pox Up, three is_connected: true, h1-h4, PacMan, and detector/live.py (the AIS-SPRT engine)."},
     "needs_net": False},

    {"key": "services", "title": "Start the servers' services",
     "why": "Starts 5 TCP services on h1 (22,80,443,8080,3306) and 5 on h2 (22,80,443,25,110), so normal users and a "
            "health checker have real services to use.",
     "files": "scripts/bench/services.py (run inside h1 and h2 with scripts/on_host.sh)",
     "cmds": ["scripts/on_host.sh h1 sh -c 'python3 scripts/bench/services.py 22,80,443,8080,3306 >/dev/null 2>&1 &'",
              "scripts/on_host.sh h2 sh -c 'python3 scripts/bench/services.py 22,80,443,25,110 >/dev/null 2>&1 &'",
              "sleep 1; for p in 22 80 443 8080 3306; do scripts/on_host.sh h3 sh -c \"nc -z -w1 10.0.0.1 $p && echo '  h1:$p open'\"; done"],
     "look": {"T4": "h1:22, 80, 443, 8080, 3306 open."}},

    {"key": "normal", "title": "Normal users and a health checker: NO alarm",
     "why": "h3 acts as a health checker: it connects to all 10 services of h1 and h2, three times. h4 browses h1. "
            "Every connection succeeds, so the AIS-SPRT score of both hosts goes DOWN. (A rule that only counts ports "
            "or entropy flags health checkers; AIS-SPRT looks at whether the connections succeed.)",
     "files": "scripts/on_host.sh; AIS-SPRT engine (detector/live.py) reads mon0; results/blocklist.txt stays unchanged",
     "cmds": ["for r in 1 2 3; do for h in 10.0.0.1:22,80,443,8080,3306 10.0.0.2:22,80,443,25,110; do ip=${h%%:*}; "
              "for p in $(echo ${h#*:} | tr , ' '); do scripts/on_host.sh h3 nc -z -w1 $ip $p; done; done; done; "
              "echo '  health checker: 30 successful connections'",
              "for i in 1 2 3 4 5; do scripts/on_host.sh h4 nc -z -w1 10.0.0.1 80; done; echo '  h4: 5 web connections'"],
     "show_decisions": True,
     "look": {"T4": "AIS-SPRT decisions: none.", "T1": "no BLOCKED line.", "T3": "PacMan shows the traffic, no HIGH alert."}},

    {"key": "slow", "title": "SLOW scan (1 port every 2 s): the old detector cannot see it",
     "why": "h4 scans h1 slowly, 1 port every 2 seconds. The old rule 'more than 15 ports in 10 s' never fires (only 5 "
            "ports per 10 s). AIS-SPRT adds up the failures over time: first a PATH block (h4 -> h1), then a HOST block "
            "after about 10-20 s.",
     "files": "scripts/attacks/portscan.py --delay 2; detector/live.py; controller/pacman_ips.py",
     "cmds": [WAIT_FREE,
              "scripts/on_host.sh h4 python3 scripts/attacks/portscan.py 10.0.0.1 --ports 200-230 --timeout 0.2 --delay 2 & "
              "t=0; until sudo ovs-ofctl dump-flows s3 ip,nw_src=10.0.0.4 | grep -v nw_dst | grep -q actions=drop; do "
              "sleep 1; t=$((t+1)); printf '\\r  slow scan running... %3ds' $t; [ $t -gt 80 ] && break; done; "
              "echo; echo \"  host block on s3 after ${t} s\"; sudo pkill -f 'portscan.py 10.0.0.1 --ports 200-230' || true"],
     "show_decisions": True,
     "look": {"T4": "path block after ~10 s (SUSPECT); if the scan goes on, host block (PORT_SCAN) ~30 s.",
              "T1": "BLOCKED 10.0.0.4->10.0.0.1 (path), then BLOCKED 10.0.0.4 ... for 30 s.",
              "T3": "PacMan shows NO alert: its old 15-ports-in-10-s rule cannot see a slow scan."}},

    {"key": "attack", "title": "ATTACK: fast port scan by h4",
     "why": "Start a running ping in T2 first:  h4 ping -i 0.5 10.0.0.2   (waits until the slow-scan block has expired) "
            "Then h4 tries ports 1-50 of h1. Nearly every "
            "probe FAILS (closed port), each failure raises h4's score: at half the threshold AIS-SPRT asks for a PATH "
            "block (h4 -> h1 only), at the threshold for a HOST block (h4 everywhere). POX deletes h4's flows and installs "
            "the drop rules on all 3 switches.",
     "files": "scripts/attacks/portscan.py (in h4); detector/live.py writes results/blocklist.txt and results/aisprt.log; "
              "controller/pacman_ips.py installs the rules and writes results/block_events.csv",
     "cmds": [WAIT_FREE, "scripts/on_host.sh h4 python3 scripts/attacks/portscan.py 10.0.0.1 --ports 1-50 --timeout 0.2"],
     "show_decisions": True,
     "look": {"T4": "SUSPECT 10.0.0.4 scope=10.0.0.1, then PORT_SCAN 10.0.0.4 scope=host.",
              "T1": "BLOCKED 10.0.0.4 on 3 switches for 59 s: second offence, so the block time is doubled.",
              "T2": "h4's running ping stops getting replies.",
              "T3": "PacMan shows the scan traffic and an alert for 10.0.0.4."}},

    {"key": "proof", "title": "Proof: block requests and drop rules on every switch",
     "why": "Shows the requests AIS-SPRT wrote (ip, time, reason, scope) and the OpenFlow drop rule on each switch.",
     "files": "results/blocklist.txt (AIS-SPRT), rules from controller/pacman_ips.py",
     "cmds": ["tail -4 results/blocklist.txt | column -t -s $'\\t'", RULES],
     "look": {"T4": "'... AIS-SPRT scanner decision  host' and on s1, s2, s3: priority=65000,ip,nw_src=10.0.0.4 actions=drop."}},

    {"key": "cut", "title": "Attacker cut off, normal user unaffected",
     "why": "h4 cannot even reach the other server h2; h3 still reaches h1.",
     "files": "scripts/on_host.sh",
     "cmds": ["scripts/on_host.sh h4 ping -c 3 -W 1 10.0.0.2", "scripts/on_host.sh h3 ping -c 3 -W 1 10.0.0.1"],
     "look": {"T4": "h4: 100% packet loss; h3: 0% packet loss."}},

    {"key": "events", "title": "Controller decision log",
     "why": "Every controller decision: BLOCK_PATH, BLOCK, EXPIRE, REAPPLY, SKIP_PROTECTED, INVALID, STALE. The last "
            "column is the block time in seconds (it doubles for repeat offenders).",
     "files": "results/block_events.csv (written by controller/pacman_ips.py)",
     "cmds": ["column -t -s, results/block_events.csv | tail -8"],
     "look": {"T4": "BLOCK_PATH 10.0.0.4->10.0.0.1 and BLOCK 10.0.0.4 on 3 switches."}},

    {"key": "repeat", "title": "Repeat offender: block time doubles again",
     "why": "Waits for the block to expire, h4 scans again, and we read the hard timeout of the new drop rule and the "
            "controller log: 30 s, then 60 s, then 120 s ... (capped at 8x).",
     "files": "controller/pacman_ips.py (back-off), results/block_events.csv",
     "cmds": [WAIT_FREE,
              "scripts/on_host.sh h4 python3 scripts/attacks/portscan.py 10.0.0.1 --ports 1-60 --timeout 0.2 >/dev/null; sleep 1",
              "sudo ovs-ofctl dump-flows s3 ip,nw_src=10.0.0.4 | grep -v nw_dst | grep -o 'hard_timeout=[0-9]*'",
              "grep -E ',BLOCK,' results/block_events.csv | cut -d, -f1,2,3,6 | column -t -s, | tail -4"],
     "show_decisions": True,
     "look": {"T4": "hard_timeout about 120 and BLOCK lines with about 30, 60, 120 s.", "T1": "BLOCKED 10.0.0.4 ... for 119 s."}},

    {"key": "results", "title": "Evaluation results (24 recorded runs, 6 detectors)",
     "why": "The comparison from the paper: AIS-SPRT against TRW, Random Forest, entropy and the window detectors on the "
            "labelled dataset (8 scenarios x 3 seeds), and the ablation of each AIS-SPRT mechanism.",
     "files": "results/eval/overall.csv, results/eval/ablation.csv (scripts/eval_detectors.py)",
     "cmds": ["cut -d, -f1,6,7,8,9,10 results/eval/overall.csv | column -t -s,",
              "column -t -s, results/eval/ablation.csv"],
     "look": {"T4": "AIS-SPRT: TPR 1.000, FPR 0.000, F1 1.000; TRW 0.903, RF 0.400, window 0.222."}, "needs_net": False},

    {"key": "log", "title": "AIS-SPRT engine log",
     "why": "Every decision of the live engine with the host's score relative to the threshold (L/eta1).",
     "files": "results/aisprt.log", "cmds": ["tail -12 results/aisprt.log"],
     "look": {"T4": "SUSPECT ... scope=10.0.0.1 and PORT_SCAN ... scope=host lines."}, "needs_net": False},
]

LIVE = [
    ("Look at the network", [("nodes", "every node"), ("net", "how everything is wired"),
                             ("links", "every link and whether it is up"), ("dump", "IPs, processes, controller")]),
    ("Connectivity", [("pingall", "every host pings every other host: 0% dropped"),
                      ("h3 ping -c 3 10.0.0.1", "user -> web server through the core")]),
    ("The attacker's running connection (start BEFORE step 'attack')",
     [("h4 ping -i 0.5 10.0.0.2", "stops when h4 is blocked, comes back when the block expires; Ctrl+C for the summary")]),
    ("Failures", [("link s1 s3 down", "cut the cable to the user switch"), ("h3 ping -c 3 -W 1 10.0.0.1", "100% loss"),
                  ("link s1 s3 up", "plug it back in"), ("h3 ping -c 3 -W 1 10.0.0.1", "0% loss again")]),
    ("Switches from inside Mininet", [("sh ovs-ofctl dump-flows s3", "s3's flow table"),
                                      ("sh ovs-vsctl show", "bridges, ports, mirror, controller")]),
    ("Finish", [("exit", "stop Mininet")]),
]


def typed(text, delay=0.006):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def wrap(text, width=112, indent="  ", rest=None):
    rest = " " * len(indent) if rest is None else rest
    out = []
    for para in text.split("\n"):
        line, start = indent if not out else rest, True
        for word in para.split():
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line, start = rest, True
            line += ("" if start else " ") + word
            start = False
        out.append(line)
    return "\n".join(out)


def net_running():
    return subprocess.run("pgrep -f '^bash --norc --noediting -is mininet:h4$'", shell=True,
                          stdout=subprocess.DEVNULL).returncode == 0


def engine_running():
    return subprocess.run("pgrep -f '^python3 .*detector/live.py'", shell=True, stdout=subprocess.DEVNULL).returncode == 0


def start_engine():
    if engine_running() or not net_running():
        return
    subprocess.Popen("sudo -n nohup python3 %s/detector/live.py >/dev/null 2>&1 &" % PROJECT, shell=True)
    time.sleep(1.5)
    print(f"{GREEN}  AIS-SPRT engine started on mon0 (log: results/aisprt.log){R}" if engine_running()
          else f"{RED}  could not start the AIS-SPRT engine (is sudo passwordless?){R}")


def log_size():
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0


def show_new_decisions(start):
    try:
        with open(LOG) as f:
            f.seek(start)
            lines = [l.rstrip() for l in f if any(k in l for k in ("SUSPECT", "PORT_SCAN", "SYN_FLOOD"))]
    except OSError:
        lines = []
    print(f"{MAGENTA}AIS-SPRT decisions:{R}")
    if lines:
        for l in lines[-6:]:
            print("  " + l)
    else:
        print("  none (no host crossed the suspicion threshold)")


def run_test(t, num):
    print()
    print(f"{B}{MAGENTA}━━━ [{num}] {t['title']} ━━━{R}")
    print(f"{CYAN}What it does:{R}")
    print(wrap(t["why"]))
    if t.get("files"):
        print(f"{CYAN}Files used:{R}")
        print(wrap(t["files"]))
    if t.get("needs_net", True) and not net_running():
        print(f"{RED}  ! The Mininet network is not running. Start it in T2: sudo python3 topology/campus_topo.py{R}")
        return
    if t.get("needs_net", True):
        start_engine()
    start = log_size()
    print()
    for cmd in t["cmds"]:
        sys.stdout.write(f"{GREEN}T4 ❯ {R}")
        typed(cmd if len(cmd) < 220 else cmd[:217] + "...")
        sys.stdout.flush()
        subprocess.run(cmd, shell=True, executable="/bin/bash")
        time.sleep(0.2)
    if t.get("show_decisions"):
        time.sleep(1.5)
        show_new_decisions(start)
    print()
    print(f"{YELLOW}Where to look:{R}")
    for term in ("T1", "T2", "T3", "T4"):
        if term in t["look"]:
            name = {"T1": "POX", "T2": "Mininet", "T3": "PacMan", "T4": "this terminal"}[term]
            print(wrap(f"{B}{term}{R} ({name}): {t['look'][term]}", indent="  • ", rest="    "))
    print()


def show_live():
    print()
    print(f"{B}{MAGENTA}━━━ live: commands for T2 (the mininet> prompt) ━━━{R}")
    n = 0
    for section, items in LIVE:
        print(f"\n{B}{CYAN}{section}{R}")
        for cmd, what in items:
            n += 1
            print(f"  {YELLOW}{n:2}{R}  {GREEN}{cmd}{R}")
            print(wrap(f"{D}{what}{R}", indent="       ", rest="       "))
    print()


def menu():
    print()
    print(f"{B}{BLUE}AIS-SPRT SDN demo console{R}  {D}(T4 · {PROJECT}){R}")
    print(f"{D}  T1 BLOCK_SECONDS=30 scripts/run_pox.sh · T2 sudo python3 topology/campus_topo.py · "
          f"T3 scripts/run_pacman.sh frontend{R}")
    for i, t in enumerate(TESTS):
        print(f"  {YELLOW}{i:2}{R}  {t['key']:<9} {t['title']}")
    print(f"  {YELLOW}{'L':>2}{R}  {'live':<9} Mininet commands to copy into T2")
    print(f"  {YELLOW}{'q':>2}{R}  {'quit':<9} (Enter = menu, 'clear' = clear the screen)")
    if net_running():
        start_engine()


def pick(choice):
    choice = choice.strip().lower()
    if choice in ("l", "live"):
        show_live()
        return True
    for i, t in enumerate(TESTS):
        if choice in (str(i), t["key"]):
            run_test(t, i)
            return True
    return False


def main():
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if not pick(arg):
                print(f"unknown step: {arg}")
        return
    menu()
    while True:
        try:
            choice = input(f"{GREEN}test.py ❯ {R}")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        c = choice.strip().lower()
        if c in ("q", "quit", "exit"):
            break
        if c in ("clear", "cls"):
            os.system("clear")
            continue
        if not c or c in ("?", "m", "menu", "help"):
            menu()
            continue
        try:
            if not pick(choice):
                print(f"{RED}  unknown choice '{choice}'; type a number, a name, 'live', or Enter for the menu{R}")
        except KeyboardInterrupt:
            print(f"\n{RED}  interrupted{R}")


if __name__ == "__main__":
    main()
