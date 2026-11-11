"""
pacman_ips - controller side of the PacMan SDN project (POX, OpenFlow 1.0).

Runs next to POX's forwarding.l2_learning, which does the forwarding. This component adds:

  FlowMonitor  every `interval` seconds asks every switch for its flow statistics and appends
               one CSV row per flow to `stats_file` (controller-side monitoring).
  Blocker      every second reads new lines PacMan appended to `blocklist`
               ("<ip>\\t<unix time>\\t<reason>") and, for each attacker IP, deletes its existing
               flows and installs an OpenFlow drop rule on every switch for `block_seconds`.
               Every decision is logged and written to `events_file`.

Run (inside the POX container, see scripts/run_pox.sh):
    ./pox.py forwarding.l2_learning pacman_ips --interval=5 --block_seconds=120 --protect=10.0.0.2
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str

import csv
import math
import os
import re
import time

log = core.getLogger("pacman_ips")

CSV_HEADER = ["time", "switch", "in_port", "dl_src", "dl_dst", "dl_type", "nw_src", "nw_dst",
              "nw_proto", "tp_src", "tp_dst", "packets", "bytes", "duration_s", "actions"]
EVENT_HEADER = ["time", "event", "ip", "reason", "switches", "seconds"]

BLOCK_PRIORITY = 65000          # above every wildcard rule; exact-match flows are deleted first
IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _text(value):
    return "" if value is None else str(value)


def _actions(actions):
    out = []
    for a in actions:
        port = getattr(a, "port", None)
        out.append("output:%s" % port if port is not None else type(a).__name__)
    return "|".join(out) if out else "drop"


def _prepare_csv(path, header):
    folder = os.path.dirname(path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "wb") as f:
            csv.writer(f).writerow(header)


def valid_unicast_ipv4(text):
    """True for a dotted-quad unicast host address (no 0.x, multicast, broadcast)."""
    m = IPV4.match(text)
    if not m:
        return False
    octets = [int(x) for x in m.groups()]
    if any(o > 255 for o in octets):
        return False
    return 0 < octets[0] < 224 and text != "255.255.255.255"


class FlowMonitor(object):
    """Polls flow statistics from every switch and records them."""

    def __init__(self, interval, stats_file):
        self.interval = interval
        self.stats_file = stats_file
        self.switches = {}                      # dpid -> connection
        _prepare_csv(stats_file, CSV_HEADER)
        core.openflow.addListeners(self)
        Timer(interval, self._poll, recurring=True)
        log.info("Flow monitor ready: polling every %ss, writing %s", interval, stats_file)

    # -------------------------------------------------------------- switches

    def _handle_ConnectionUp(self, event):
        self.switches[event.dpid] = event.connection
        log.info("Switch %s connected (%d switch(es) monitored)", dpid_to_str(event.dpid), len(self.switches))

    def _handle_ConnectionDown(self, event):
        self.switches.pop(event.dpid, None)
        log.warning("Switch %s disconnected (%d switch(es) monitored)", dpid_to_str(event.dpid), len(self.switches))

    # -------------------------------------------------------------- stats

    def _poll(self):
        for dpid, connection in list(self.switches.items()):
            try:
                connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
            except Exception as e:                # switch went away between ticks
                log.warning("Stats request to %s failed: %s", dpid_to_str(dpid), e)
                self.switches.pop(dpid, None)

    def _handle_FlowStatsReceived(self, event):
        switch = dpid_to_str(event.connection.dpid)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        total_packets = total_bytes = 0
        rows = []
        for stat in event.stats:
            m = stat.match
            total_packets += stat.packet_count
            total_bytes += stat.byte_count
            rows.append([now, switch, _text(m.in_port), _text(m.dl_src), _text(m.dl_dst),
                         "0x%04x" % m.dl_type if m.dl_type is not None else "",
                         _text(m.nw_src), _text(m.nw_dst), _text(m.nw_proto), _text(m.tp_src), _text(m.tp_dst),
                         stat.packet_count, stat.byte_count, stat.duration_sec, _actions(stat.actions)])
        if rows:
            with open(self.stats_file, "ab") as f:
                csv.writer(f).writerows(rows)
        log.info("Stats %s: %d flow(s), %d packets, %d bytes", switch, len(rows), total_packets, total_bytes)


class Blocker(object):
    """Turns PacMan's block requests into OpenFlow drop rules on every switch."""

    def __init__(self, blocklist, block_seconds, protect, events_file):
        self.blocklist = blocklist
        self.block_seconds = block_seconds
        self.protect = protect
        self.events_file = events_file
        self.offset = 0                         # bytes of the blocklist already processed
        self.inode = None
        self.missing_reported = False
        self.active = {}                        # ip -> (expiry unix time, reason)
        _prepare_csv(events_file, EVENT_HEADER)
        core.openflow.addListeners(self)
        Timer(1, self._tick, recurring=True)
        log.info("Blocker ready: reading %s every 1 s, block for %ss, protected: %s",
                 blocklist, block_seconds, ", ".join(sorted(protect)) or "none")
        self._tick()                            # apply still-valid requests from before a restart

    # -------------------------------------------------------------- events

    def _event(self, event, ip, reason="", switches="", seconds=""):
        with open(self.events_file, "ab") as f:
            csv.writer(f).writerow([time.strftime("%Y-%m-%d %H:%M:%S"), event, ip, reason, switches, seconds])

    # -------------------------------------------------------------- reading the blocklist

    def _new_lines(self):
        try:
            st = os.stat(self.blocklist)
        except OSError:
            if not self.missing_reported:
                log.info("Blocklist %s does not exist yet; waiting for PacMan", self.blocklist)
                self.missing_reported = True
            self.offset, self.inode = 0, None
            return []
        self.missing_reported = False
        if st.st_ino != self.inode or st.st_size < self.offset:
            if self.inode is not None:
                log.warning("Blocklist was replaced or truncated; reading it from the start")
            self.offset, self.inode = 0, st.st_ino
        if st.st_size == self.offset:
            return []
        with open(self.blocklist, "rb") as f:
            f.seek(self.offset)
            data = f.read()
        complete = data.rfind(b"\n") + 1        # leave a half-written last line for the next tick
        self.offset += complete
        return data[:complete].decode("utf-8", "replace").splitlines()

    def _tick(self):
        now = time.time()
        for line in self._new_lines():
            self._handle_line(line.strip(), now)
        for ip, (expiry, reason) in list(self.active.items()):
            if expiry <= now:
                del self.active[ip]
                log.info("Block on %s expired; traffic from it is allowed again", ip)
                self._event("EXPIRE", ip, reason)

    def _handle_line(self, line, now):
        if not line or line.startswith("#"):
            return
        parts = line.split("\t") if "\t" in line else line.split(None, 2)
        ip = parts[0].strip()
        stamp = None
        if len(parts) > 1:
            try:
                stamp = float(parts[1])
            except ValueError:
                stamp = None
        reason = parts[2].strip() if len(parts) > 2 else (parts[1].strip() if len(parts) > 1 and stamp is None else "")

        if not valid_unicast_ipv4(ip):
            log.warning("Ignoring invalid blocklist entry: %r", line[:80])
            self._event("INVALID", ip[:40], line[:80])
            return
        if ip in self.protect:
            log.warning("Not blocking %s: it is on the protected list (%s)", ip, reason or "no reason")
            self._event("SKIP_PROTECTED", ip, reason)
            return
        start = stamp if stamp is not None and stamp <= now + 5 else now
        remaining = start + self.block_seconds - now
        if remaining < 1:
            self._event("STALE", ip, reason, seconds="%.0f" % (now - start))
            return
        self._block(ip, reason, start + self.block_seconds)

    # -------------------------------------------------------------- OpenFlow

    def _flow_mods(self, ip, seconds):
        match = of.ofp_match(dl_type=0x0800, nw_src=IPAddr(ip))
        delete = of.ofp_flow_mod(command=of.OFPFC_DELETE, match=match)
        drop = of.ofp_flow_mod(command=of.OFPFC_ADD, match=match, priority=BLOCK_PRIORITY,
                               hard_timeout=min(65535, int(math.ceil(seconds))))
        return delete, drop                      # no actions on `drop` = discard

    def _install(self, connection, ip, seconds):
        for msg in self._flow_mods(ip, seconds):
            connection.send(msg)

    def _block(self, ip, reason, expiry):
        refreshed = ip in self.active
        self.active[ip] = (expiry, reason)
        seconds = expiry - time.time()
        done = 0
        for connection in list(core.openflow.connections):
            try:
                self._install(connection, ip, seconds)
                done += 1
            except Exception as e:
                log.warning("Could not block %s on %s: %s", ip, dpid_to_str(connection.dpid), e)
        log.warning("%s %s on %d switch(es) for %.0f s (%s)", "Refreshed block on" if refreshed else "BLOCKED",
                    ip, done, seconds, reason or "no reason")
        self._event("REFRESH" if refreshed else "BLOCK", ip, reason, done, "%.0f" % seconds)

    def _handle_ConnectionUp(self, event):
        # A switch that (re)connects gets every block that is still running.
        now = time.time()
        for ip, (expiry, reason) in self.active.items():
            if expiry - now >= 1:
                self._install(event.connection, ip, expiry - now)
                log.info("Re-applied block on %s to switch %s (%.0f s left)", ip, dpid_to_str(event.dpid), expiry - now)
                self._event("REAPPLY", ip, reason, dpid_to_str(event.dpid), "%.0f" % (expiry - now))


def launch(interval=5, stats_file="/project/results/flow_stats.csv",
           blocklist="/project/results/blocklist.txt", block_seconds=120, protect="",
           events_file="/project/results/block_events.csv"):
    interval = float(interval)
    if interval <= 0:
        raise ValueError("interval must be > 0")
    block_seconds = float(block_seconds)
    if block_seconds < 1:
        raise ValueError("block_seconds must be >= 1")
    protected = set(p.strip() for p in str(protect).split(",") if p.strip())
    bad = [p for p in protected if not valid_unicast_ipv4(p)]
    if bad:
        raise ValueError("protect: not valid IPv4 addresses: %s" % ", ".join(bad))
    core.registerNew(FlowMonitor, interval, stats_file)
    core.registerNew(Blocker, blocklist, block_seconds, protected, events_file)
