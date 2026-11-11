#!/usr/bin/env python3
"""TCP connect port scan used as the demo anomaly inside the Mininet lab.

    mininet> h4 python3 scripts/attacks/portscan.py 10.0.0.1 --ports 1-200

Only lab addresses (10.0.0.0/24) are accepted. Prints a one-line summary."""
import argparse
import ipaddress
import socket
import sys
import time

LAB_NET = ipaddress.ip_network("10.0.0.0/24")


def parse_ports(text):
    ports = []
    for part in text.split(","):
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be within 1-65535")
    return ports


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="lab host, e.g. 10.0.0.1")
    ap.add_argument("--ports", default="1-200", help="e.g. 1-200 or 22,80 (default 1-200)")
    ap.add_argument("--timeout", type=float, default=0.3, help="per-port timeout in seconds")
    ap.add_argument("--delay", type=float, default=0.0, help="pause between probes in seconds (slow scan)")
    args = ap.parse_args()
    try:
        ports = parse_ports(args.ports)
        if ipaddress.ip_address(args.target) not in LAB_NET:
            raise ValueError("target must be inside the lab network %s" % LAB_NET)
    except ValueError as e:
        sys.exit("bad argument: %s" % e)

    start = time.time()
    open_ports, failed = [], 0
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout)
        try:
            if s.connect_ex((args.target, port)) == 0:
                open_ports.append(port)
        except OSError:
            failed += 1
        finally:
            s.close()
        if args.delay > 0:
            time.sleep(args.delay)
    print("scanned %d ports on %s in %.1f s; open: %s%s" % (
        len(ports), args.target, time.time() - start, ",".join(map(str, open_ports)) or "none",
        "; %d probe(s) failed" % failed if failed else ""))


if __name__ == "__main__":
    main()
