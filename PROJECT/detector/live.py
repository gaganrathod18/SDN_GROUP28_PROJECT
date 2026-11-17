#!/usr/bin/env python3
"""
Live AIS-SPRT engine on the core mirror: sudo python3 detector/live.py [--iface mon0]

Reads every mirrored packet (AF_PACKET), resolves initiated connection attempts in real time (success on SYN-ACK or
UDP reply, failure on RST, ICMP unreachable or 3 s without an answer), runs the AIS-SPRT detector and writes graded
block requests for the controller:

    <ip> TAB <unix time> TAB <reason> TAB <scope>        scope = destination IP (path block) or "host"

At most one request per (ip, scope) per 30 s. Log: results/aisprt.log.
"""
import argparse
import os
import socket
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapio                               # noqa: E402
from detectors import AISPRT                # noqa: E402

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Tracker(object):
    """Streaming version of pcapio.extract(): feed packets, get resolved attempts."""

    def __init__(self, timeout=pcapio.TIMEOUT):
        self.timeout, self.pending, self.seen = timeout, {}, set()

    def _close(self, key, outcome, t):
        t0 = self.pending.pop(key)
        return pcapio.Attempt(t0, key[0], key[1], key[2], key[4], key[3], outcome, t)

    def expire(self, now):
        return [self._close(k, "failure", v + self.timeout) for k, v in list(self.pending.items())
                if now - v > self.timeout]

    def feed(self, t, ipb):
        p = pcapio.parse(ipb)
        if p is None:
            return []
        src, dst, proto, sport, dport, flags, icmp = p
        key, rkey = (src, dst, proto, sport, dport), (dst, src, proto, dport, sport)
        if proto == 6:
            if flags & pcapio.SYN and not flags & pcapio.ACK:
                if key not in self.seen and pcapio.can_initiate(dst, 6, sport, dport):
                    self.seen.add(key)
                    self.pending[key] = t
            elif rkey in self.pending:
                if flags & pcapio.SYN and flags & pcapio.ACK:
                    return [self._close(rkey, "success", t)]
                if flags & pcapio.RST:
                    return [self._close(rkey, "failure", t)]
        elif proto == 17:
            if rkey in self.pending:
                return [self._close(rkey, "success", t)]
            if key not in self.seen and rkey not in self.seen and pcapio.can_initiate(dst, 17, sport, dport):
                self.seen.add(key)
                self.pending[key] = t
        elif proto == 1 and icmp and icmp[0] == 3 and icmp[2]:
            okey = tuple(icmp[2][:5])
            if okey in self.pending:
                return [self._close(okey, "failure", t)]
        if len(self.seen) > 500000:
            self.seen.clear()
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="mon0")
    ap.add_argument("--blocklist", default=os.path.join(PROJECT, "results", "blocklist.txt"))
    ap.add_argument("--log", default=os.path.join(PROJECT, "results", "aisprt.log"))
    ap.add_argument("--cooldown", type=float, default=30.0)
    a = ap.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((a.iface, 0))
    sock.settimeout(0.5)
    det, tr = AISPRT(), Tracker()
    last = {}
    log = open(a.log, "a")

    def say(msg):
        line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
        print(line, flush=True)
        log.write(line + "\n")
        log.flush()

    say("AIS-SPRT live on %s (eta1=%.2f, eta_s=%.2f, tau=%.0f s)" % (a.iface, det.eta1, det.rho * det.eta1, det.tau))
    next_expire = time.time() + 0.5
    while True:
        done = []
        try:
            frame = sock.recv(65535)
            t = time.time()
            if len(frame) >= 14 and frame[12:14] == b"\x08\x00":
                done = tr.feed(t, frame[14:])
        except socket.timeout:
            t = time.time()
        if t >= next_expire:
            done += tr.expire(t)
            next_expire = t + 0.5
        for att in done:
            for _t, src, kind, scope in det.step(att):
                reason = {"SUSPECT": "AIS-SPRT suspicion (path block)", "PORT_SCAN": "AIS-SPRT scanner decision",
                          "SYN_FLOOD": "CUSUM connection flood"}[kind]
                key = (src, scope)
                if t - last.get(key, 0) < a.cooldown:
                    continue
                last[key] = t
                with open(a.blocklist, "a") as f:
                    f.write("%s\t%d\t%s\t%s\n" % (src, int(t), reason, scope))
                say("%s %s scope=%s L/eta1=%.2f" % (kind, src, scope, det.score[src]))


if __name__ == "__main__":
    main()
