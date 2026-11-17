#!/usr/bin/env python3
"""Horizontal scan: a few ports across many lab hosts.
    hscan.py 10.0.0.11,10.0.0.12 22,80,445 --delay 0.2"""
import argparse
import ipaddress
import socket
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("hosts")
ap.add_argument("ports")
ap.add_argument("--delay", type=float, default=0.2)
ap.add_argument("--timeout", type=float, default=0.3)
a = ap.parse_args()
hosts = a.hosts.split(",")
if any(ipaddress.ip_address(h) not in ipaddress.ip_network("10.0.0.0/24") for h in hosts):
    sys.exit("lab hosts only")
n = 0
for port in (int(p) for p in a.ports.split(",")):
    for h in hosts:
        s = socket.socket()
        s.settimeout(a.timeout)
        try:
            s.connect_ex((h, port))
        except OSError:
            pass
        s.close()
        n += 1
        time.sleep(a.delay)
print("horizontal scan: %d probes" % n)
