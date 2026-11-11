#!/usr/bin/env python3
"""
Interactive demo console for terminal T4.

    python3 test.py            menu of every demo test; type a number (or its name) to run it
    python3 test.py 7          run test 7 directly
    python3 test.py live       Mininet commands to copy into T2

Each test explains what it does, types and runs its commands with their real output,
and tells you what changes to watch in T1 (POX), T2 (Mininet) and T3 (PacMan).
Start POX (T1), the topology (T2) and PacMan (T3) first; see DEMO.pdf.
"""
import os
import subprocess
import sys
import time

PROJECT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT)

R, B, D = "\033[0m", "\033[1m", "\033[2m"
GREEN, YELLOW, CYAN, MAGENTA, RED, BLUE = "\033[92m", "\033[93m", "\033[96m", "\033[95m", "\033[91m", "\033[94m"

TESTS = [
    {
        "key": "check", "title": "Environment check",
        "why": "Checks every tool the project needs: Mininet, Open vSwitch, Podman with the python:2.7 image, "
               "POX, the PacMan binary, passwordless sudo, and that OpenFlow port 6633 is free.",
        "cmds": ["scripts/check_env.sh"],
        "files": 'runs scripts/check_env.sh (reads ../pox/pox.py, ../pacman/build/pacman)',
        "look": {"T4": "every line [ OK ] and 'All required components found.' (port 6633 shows 'in use' once POX runs)."},
        "needs_net": False,
    },
    {
        "key": "status", "title": "Is everything running?",
        "why": "Shows the POX container, whether all 3 switches are connected to the controller, "
               "the Mininet host shells and the PacMan process.",
        "cmds": ["podman ps --format '{{.Names}}  {{.Status}}'",
                 "sudo ovs-vsctl --columns=_uuid,target,is_connected list controller | grep -E 'target|is_connected'",
                 "pgrep -af 'mininet:h[1-4]$' | sed 's/^/  /'",
                 "pgrep -ax pacman | sed 's/^/  /'"],
        "files": 'asks Podman (container pacman-pox from scripts/run_pox.sh), Open vSwitch, and the process list',
        "look": {"T4": "pacman-pox Up, three 'is_connected : true', h1–h4 shells, one PacMan process."},
        "needs_net": False,
    },
    {
        "key": "mirror", "title": "Port mirror on the core switch",
        "why": "s1 copies every packet of every port to mon0 (select_all), and mon0 is NO_FLOOD so packets the "
               "controller floods are not seen twice. PacMan captures on mon0.",
        "cmds": ["sudo ovs-vsctl list mirror", "sudo ovs-ofctl dump-ports-desc s1 | grep -A1 mon0"],
        "files": 'mirror created by topology/campus_topo.py (function add_mirror)',
        "look": {"T4": "select_all : true, output_port = mon0's port, statistics counting up; 'mon0 … NO_FLOOD'."},
    },
    {
        "key": "tcpdump", "title": "Watch the mirror live (tcpdump on mon0)",
        "why": "Captures 8 ICMP packets on mon0 while h3 pings h1. The first request appears twice: the first packet "
               "of a new flow goes to POX (PACKET_IN), POX sends it back (PACKET_OUT) and the mirror copies it again. "
               "Later packets match the new flow rule and appear once.",
        "cmds": ["(sleep 1; scripts/on_host.sh h3 ping -c 4 10.0.0.1 >/dev/null) & sudo timeout 10 tcpdump -nn -i mon0 -c 8 icmp"],
        "files": 'scripts/on_host.sh runs ping inside h3; tcpdump reads mon0 (the mirror port from topology/campus_topo.py)',
        "look": {"T3": "PacMan's packet counter and 'Recent Flows' show 10.0.0.3 ↔ 10.0.0.1.",
                 "T1": "new flow statistics on the next 5 s poll."},
    },
    {
        "key": "flows", "title": "Flow rules installed by the controller",
        "why": "h3 pings h1, then we dump s1's flow table. POX's l2_learning installs exact-match rules with "
               "idle_timeout=10 and hard_timeout=30; OVS shows them at priority 65535.",
        "cmds": ["scripts/on_host.sh h3 ping -c 3 10.0.0.1", "sudo ovs-ofctl --no-stats dump-flows s1"],
        "files": 'rules installed by POX forwarding.l2_learning (../pox/pox/forwarding/l2_learning.py)',
        "look": {"T4": "two rules (h3→h1 and h1→h3) with actions=output:… They disappear 10 s after the ping stops."},
    },
    {
        "key": "stats", "title": "Controller flow statistics (flow_stats.csv)",
        "why": "Every 5 s our pacman_ips FlowMonitor asks every switch for its flow counters (OpenFlow STATS request) "
               "and appends one row per rule to results/flow_stats.csv. This is the SDN-side monitoring view.",
        "cmds": ["(head -1 results/flow_stats.csv; tail -6 results/flow_stats.csv) | cut -d, -f1,2,6,7,8,12,13 | column -t -s,"],
        "files": 'written by controller/pacman_ips.py (class FlowMonitor) → results/flow_stats.csv',
        "look": {"T1": "a 'Stats 00-00-00-00-00-0N: … flow(s), … packets, … bytes' line per switch every 5 s."},
    },
    {
        "key": "normal", "title": "Normal traffic: no alert, no block",
        "why": "h3 and h4 browse both web servers for 10 s (needs the web servers: see 'live', section 'Start the web servers'). "
               "A good detector must stay quiet: these hosts only open 1 port per server.",
        "cmds": ["for i in 1 2 3 4 5 6 7 8 9 10; do "
                 "scripts/on_host.sh h3 curl -s -o /dev/null -w 'h3 -> h1: HTTP %{http_code}, ' http://10.0.0.1/; "
                 "scripts/on_host.sh h4 curl -s -o /dev/null -w 'h4 -> h2: HTTP %{http_code}' http://10.0.0.2:8080/; "
                 "echo; sleep 1; done",
                 "echo \"blocklist lines: $(wc -l < results/blocklist.txt)\""],
        "files": 'scripts/on_host.sh; web servers started in T2; PacMan reads config/pacman-sdn.conf, logs to results/pacman.log; results/blocklist.txt stays empty',
        "look": {"T3": "packets and flows grow, but Alerts stays HIGH 0.",
                 "T1": "nothing new except the 5 s stats lines.",
                 "T4": "20 × HTTP 200 and 'blocklist lines: 0'."},
    },
    {
        "key": "attack", "title": "ATTACK: h4 port-scans the web server",
        "why": "h4 tries TCP connections to ports 1–100 of h1 (connect scan, 0.2 s timeout). PacMan counts the "
               "connections h4 *starts*: more than 15 distinct ports on one host inside 10 s = PORT_SCAN (HIGH). "
               "PacMan appends '10.0.0.4 <time> <reason>' to results/blocklist.txt; POX reads it within 1 s, "
               "deletes h4's flows and installs a priority-65000 DROP rule on s1, s2 and s3.\n"
               "Tip: first start a running ping in T2:  h4 ping -i 0.5 10.0.0.2  and watch it freeze.",
        "cmds": ["scripts/on_host.sh h4 python3 scripts/attacks/portscan.py 10.0.0.1 --ports 1-100 --timeout 0.2"],
        "files": 'scripts/on_host.sh → scripts/attacks/portscan.py (inside h4); PacMan (../pacman, thresholds in config/pacman-sdn.conf) writes results/pacman.log and results/blocklist.txt; controller/pacman_ips.py (class Blocker) reads blocklist.txt, sends OpenFlow rules, writes results/block_events.csv',
        "look": {"T3": "Alerts box: HIGH 10.0.0.4 'Possible port scan detected' (plus MEDIUM 'High connection count').",
                 "T1": "WARNING … BLOCKED 10.0.0.4 on 3 switch(es) for 119 s (Possible port scan detected).",
                 "T2": "the running 'h4 ping' stops getting replies at that moment.",
                 "T4": "'scanned 100 ports …'; 'open: none' or '80' (probes after the block time out)."},
    },
    {
        "key": "proof", "title": "Proof: block request and DROP rules on every switch",
        "why": "Shows what PacMan wrote for the controller and the OpenFlow rule the controller installed on each switch.",
        "cmds": ["cat results/blocklist.txt",
                 "for s in s1 s2 s3; do echo \"== $s\"; sudo ovs-ofctl --no-stats dump-flows $s \"ip,nw_src=10.0.0.4\"; done"],
        "files": 'results/blocklist.txt (written by PacMan); DROP rules installed by controller/pacman_ips.py',
        "look": {"T4": "'10.0.0.4 <unix time> Possible port scan detected'; on s1, s2, s3: "
                       "hard_timeout=120, priority=65000, ip, nw_src=10.0.0.4 actions=drop.",
                 "T3": "Firewall tab (→ 8 times): SDN_DROP 10.0.0.4."},
    },
    {
        "key": "cut", "title": "Attacker cut off, normal user unaffected",
        "why": "Only the attacker is blocked: h4 cannot reach even the other server h2, while h3 still pings and "
               "browses h1.",
        "cmds": ["scripts/on_host.sh h4 ping -c 3 -W 1 10.0.0.2",
                 "scripts/on_host.sh h3 ping -c 3 -W 1 10.0.0.1",
                 "scripts/on_host.sh h3 curl -s -o /dev/null -w 'h3 -> h1: HTTP %{http_code}' http://10.0.0.1/; echo"],
        "files": 'scripts/on_host.sh runs ping/curl inside h4 and h3',
        "look": {"T4": "h4: 100% packet loss; h3: 0% packet loss and HTTP 200."},
    },
    {
        "key": "counter", "title": "Live DROP counter on the attacker's edge switch s3",
        "why": "Prints s3's drop-rule packet counter every second for 6 s. If h4 is still pinging (T2), the number "
               "climbs: the packets die at h4's own edge switch and never reach the core.",
        "cmds": ["for i in 1 2 3 4 5 6; do echo \"$(date +%T)  s3 drop rule: $(sudo ovs-ofctl dump-flows s3 "
                 "ip,nw_src=10.0.0.4 | grep actions=drop | grep -o 'n_packets=[0-9]*' || echo 'no DROP rule (not blocked)')\"; sleep 1; done"],
        "files": "reads the DROP rule's counter from switch s3 (rule from controller/pacman_ips.py)",
        "look": {"T4": "n_packets grows by ~2 per second while 'h4 ping -i 0.5' runs in T2."},
    },
    {
        "key": "silent", "title": "Mirror sees no IP traffic from the attacker",
        "why": "Listens on mon0 for 5 s for IP packets from 10.0.0.4. They are dropped at s3 before the core, so "
               "nothing arrives. (ARP still passes: the rule matches IPv4 only, dl_type=0x0800.)",
        "cmds": ["sudo timeout 5 tcpdump -nn -i mon0 ip and src host 10.0.0.4"],
        "files": 'tcpdump on mon0 (mirror from topology/campus_topo.py)',
        "look": {"T4": "'0 packets captured'.", "T3": "packet rate from 10.0.0.4 stays at zero."},
    },
    {
        "key": "events", "title": "Controller decision log (block_events.csv)",
        "why": "Every controller decision: BLOCK, REFRESH, EXPIRE, REAPPLY, SKIP_PROTECTED, INVALID, STALE.",
        "cmds": ["column -t -s, results/block_events.csv"],
        "files": 'results/block_events.csv (written by controller/pacman_ips.py)',
        "look": {"T4": "BLOCK 10.0.0.4 … 3 switches … 119 s, and later EXPIRE."},
    },
    {
        "key": "expire", "title": "Wait for the block to expire (up to 2 min)",
        "why": "The DROP rule has a hard_timeout, so the switches remove it by themselves; POX logs EXPIRE. "
               "This waits for the EXPIRE event, then shows the rules are gone and h4 is reachable again.",
        "cmds": ["n=0; until grep -q EXPIRE results/block_events.csv 2>/dev/null; do "
                 "printf '\\r  waiting for expiry… %3ds' $n; sleep 1; n=$((n+1)); [ $n -gt 130 ] && break; done; echo",
                 "column -t -s, results/block_events.csv",
                 "for s in s1 s2 s3; do echo \"== $s: $(sudo ovs-ofctl --no-stats dump-flows $s ip,nw_src=10.0.0.4 | grep actions=drop || echo no DROP rule)\"; done",
                 "scripts/on_host.sh h4 ping -c 3 -W 1 10.0.0.2"],
        "files": 'results/block_events.csv; expiry done by the switches (hard_timeout set in controller/pacman_ips.py); scripts/on_host.sh',
        "look": {"T1": "'Block on 10.0.0.4 expired; traffic from it is allowed again'.",
                 "T2": "a still-running 'h4 ping' starts getting replies again by itself.",
                 "T4": "EXPIRE row, 'no DROP rule' on s1/s2/s3, h4: 0% packet loss."},
    },
    {
        "key": "unblock", "title": "Unblock the attacker by hand (optional)",
        "why": "Deletes the DROP rule on every switch before it expires (the controller still remembers the block and "
               "would re-apply it if a switch reconnected).",
        "cmds": ["for s in s1 s2 s3; do sudo ovs-ofctl del-flows $s \"ip,nw_src=10.0.0.4\"; done",
                 "scripts/on_host.sh h4 ping -c 2 -W 1 10.0.0.2"],
        "files": 'talks to the switches directly with ovs-ofctl; scripts/on_host.sh',
        "look": {"T4": "h4 ping works again.", "T2": "a running h4 ping resumes."},
    },
]

LIVE = [
    ("Look at the network", [
        ("nodes", "list every node: controller c0, hosts h1–h4, switches s1–s3"),
        ("net", "how everything is wired (which host port goes to which switch port)"),
        ("links", "every link and whether both ends are up (OK OK)"),
        ("dump", "each node with its IP and process id; c0 is the remote controller at 127.0.0.1:6633"),
    ]),
    ("Each host is its own Linux machine (network namespace)", [
        ("h4 ip -br addr", "h4 sees only its own interface h4-eth0 with 10.0.0.4"),
        ("h4 ip route", "h4's own routing table"),
        ("h1 ps aux | grep http.server", "processes running inside h1 (after the web servers are started)"),
    ]),
    ("Connectivity", [
        ("pingall", "every host pings every other host: 0% dropped (12/12)"),
        ("h3 ping -c 3 10.0.0.1", "user → web server through s3 → s1 → s2 (crosses the core, so PacMan sees it)"),
        ("h1 ping -c 3 10.0.0.2", "h1 → h2 stays inside s2: it never crosses the core, so PacMan does NOT see it"),
    ]),
    ("Start the web servers (needed for 'normal' and 'cut' in test.py)", [
        ("h1 python3 -m http.server 80 --directory /tmp &", "web server on h1, port 80"),
        ("h2 python3 -m http.server 8080 --directory /tmp &", "web server on h2, port 8080"),
        ('h3 curl -s -o /dev/null -w "h3 -> h1: HTTP %{http_code}" http://10.0.0.1/ ; echo', "HTTP 200 from h1"),
        ('h3 curl -s -o /dev/null -w "h3 -> h2: HTTP %{http_code}" http://10.0.0.2:8080/ ; echo', "HTTP 200 from h2"),
    ]),
    ("Bandwidth (watch PacMan in T3)", [
        ("iperf h3 h1", "TCP bandwidth test through the core (~22 Gbit/s on this laptop). PacMan shows a MEDIUM "
                        "'Large transfer' alert for h3 and does NOT block it: only HIGH alerts block"),
    ]),
    ("The attacker's running connection (start BEFORE test 'attack')", [
        ("h4 ping -i 0.5 10.0.0.2", "h4 pings h2 twice a second and keeps going. When the block lands the replies stop; "
                                    "when it expires they come back. Stop with Ctrl+C: the summary shows the lost packets"),
    ]),
    ("Failures", [
        ("link s1 s3 down", "cut the cable between the core and the user switch"),
        ("h3 ping -c 3 -W 1 10.0.0.1", "100% packet loss: the user zone is cut off"),
        ("link s1 s3 up", "plug it back in"),
        ("h3 ping -c 3 -W 1 10.0.0.1", "0% loss again: the network recovers by itself"),
    ]),
    ("Switch and controller from inside Mininet", [
        ("sh ovs-ofctl dump-flows s3", "s3's flow table, run from the Mininet prompt (sh = run on the host)"),
        ("sh ovs-vsctl show", "all bridges, ports, the mirror and the controller connection"),
    ]),
    ("Finish", [
        ("exit", "stop Mininet (then run 'sudo mn -c' in T4 if anything is left over)"),
    ]),
]


def typed(text, delay=0.008):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def wrap(text, width=110, indent="  ", rest=None):
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


def run_test(t, num):
    print()
    print(f"{B}{MAGENTA}━━━ [{num}] {t['title']} ━━━{R}")
    print(f"{CYAN}What it does:{R}")
    print(wrap(t["why"]))
    if t.get("files"):
        print(f"{CYAN}Files used:{R}")
        print(wrap(t["files"]))
    if t.get("needs_net", True) and not net_running():
        print(f"{RED}  ! The Mininet network is not running. Start it in T2 first: sudo python3 topology/campus_topo.py{R}")
        return
    print()
    for cmd in t["cmds"]:
        sys.stdout.write(f"{GREEN}T4 ❯ {R}")
        typed(cmd)
        subprocess.run(cmd, shell=True, executable="/bin/bash")
        time.sleep(0.2)
    print()
    print(f"{YELLOW}Where to look:{R}")
    for term in ("T1", "T2", "T3", "T4"):
        if term in t["look"]:
            name = {"T1": "POX", "T2": "Mininet", "T3": "PacMan", "T4": "this terminal"}[term]
            print(wrap(f"{B}{term}{R} ({name}): {t['look'][term]}", indent="  • "))
    print()


def show_live():
    print()
    print(f"{B}{MAGENTA}━━━ live: commands for T2 (the mininet> prompt) ━━━{R}")
    print(f"{D}  copy a line into T2 exactly as shown (without 'mininet>'){R}")
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
    print(f"{B}{BLUE}PacMan SDN demo console{R}  {D}(T4 · {PROJECT}){R}")
    print(f"{D}  start T1 POX, T2 network, T3 PacMan first (DEMO.pdf){R}")
    for i, t in enumerate(TESTS):
        print(f"  {YELLOW}{i:2}{R}  {t['key']:<8} {t['title']}")
    print(f"  {YELLOW}{'L':>2}{R}  {'live':<8} Mininet commands to copy into T2")
    print(f"  {YELLOW}{'q':>2}{R}  {'quit':<8} (Enter = this menu again, 'clear' = clear the screen)")


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
                print(f"unknown test: {arg}")
        return
    menu()
    while True:
        try:
            choice = input(f"{GREEN}test.py ❯ {R}")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice.strip().lower() in ("q", "quit", "exit"):
            break
        if choice.strip().lower() in ("clear", "cls"):
            os.system("clear")
            continue
        if not choice.strip() or choice.strip() in ("?", "m", "menu", "help"):
            menu()
            continue
        try:
            if not pick(choice):
                print(f"{RED}  unknown choice '{choice}'; type a number, a name, 'live', or Enter for the menu{R}")
        except KeyboardInterrupt:
            print(f"\n{RED}  interrupted{R}")


if __name__ == "__main__":
    main()
