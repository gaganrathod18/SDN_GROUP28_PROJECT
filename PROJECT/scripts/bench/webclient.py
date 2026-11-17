#!/usr/bin/env python3
"""Benign web client for experiments: fetch a URL at a fixed rate for a fixed time.
    mininet> h3 python3 scripts/bench/webclient.py http://10.0.0.1/ --rate 4 --duration 30
Prints the number of requests and failures."""
import argparse
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("url")
ap.add_argument("--rate", type=float, default=1.0, help="requests per second")
ap.add_argument("--duration", type=float, default=30.0, help="seconds")
args = ap.parse_args()

ok = fail = 0
start = time.time()
n = 0
while time.time() - start < args.duration:
    try:
        urllib.request.urlopen(args.url, timeout=2).read()
        ok += 1
    except Exception:
        fail += 1
    n += 1
    time.sleep(max(0.0, start + n / args.rate - time.time()))
print("requests %d ok %d failed %d" % (ok + fail, ok, fail))
