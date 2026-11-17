#!/usr/bin/env python3
"""Benign client for experiments.
    client.py benign  <seed> <rate> <duration> <fail_prob>   Poisson requests to popular services; with fail_prob a
                                                              stale service (closed port) is tried, retried 3 times
    client.py health  <seed> <period> <duration>              health checker: every period, every service of every server
"""
import json
import random
import socket
import sys
import time

SERVERS = json.loads(open(__file__.replace("client.py", "servers.json")).read())


def hit(ip, port, timeout=1.5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            s.recv(256)
            return True
    except OSError:
        pass
    finally:
        s.close()
    return False


def benign(seed, rate, duration, fail_prob):
    rnd = random.Random(seed)
    ips = sorted(SERVERS)
    zipf = [1.0 / (i + 1) for i in range(len(ips))]
    end = time.time() + duration
    while time.time() < end:
        time.sleep(rnd.expovariate(rate))
        ip = rnd.choices(ips, weights=zipf)[0]
        ports = SERVERS[ip]["open"]
        if rnd.random() < fail_prob:
            port = rnd.choice(SERVERS[ip]["stale"])
            for _ in range(3):                      # an application retrying a dead service
                if hit(ip, port):
                    break
                time.sleep(1.0)
        else:
            w = [4 if p in (80, 443) else 1 for p in ports]
            hit(ip, rnd.choices(ports, weights=w)[0])


def health(seed, period, duration):
    end = time.time() + duration
    while time.time() < end:
        start = time.time()
        for ip in sorted(SERVERS):
            for port in SERVERS[ip]["open"]:
                hit(ip, port)
        time.sleep(max(0.0, period - (time.time() - start)))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "benign":
        benign(int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]))
    else:
        health(int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]))
