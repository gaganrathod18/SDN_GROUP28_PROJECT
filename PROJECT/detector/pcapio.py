"""Minimal pcap reader and connection-attempt extraction (no third-party packages).

extract_attempts(path) turns a capture of the core mirror into a time-ordered list of *initiated*
connection attempts with their outcome:

    Attempt(t, src, dst, proto, dport, sport, outcome, t_outcome)
        outcome: "success" (SYN-ACK / UDP reply), "failure" (RST / ICMP unreachable / no reply within TIMEOUT)

A TCP attempt is a SYN without ACK that starts a new 4-tuple; retransmitted SYNs of the same 4-tuple and the
mirror's duplicate copy of the first packet are ignored. All flows with their first packet are also returned so
that the naive (every-new-flow) baseline can be evaluated on the same capture.
"""
import struct
from collections import namedtuple

TIMEOUT = 3.0                     # seconds without an answer = failed attempt

Attempt = namedtuple("Attempt", "t src dst proto dport sport outcome t_outcome")
NewFlow = namedtuple("NewFlow", "t src dst proto dport sport")

_IP = struct.Struct("!BBHHHBBH4s4s")


def _ip(b):
    return "%d.%d.%d.%d" % tuple(b)


def _l2(linktype, data):
    """IPv4 bytes of one frame, or None."""
    if linktype == 1:                               # Ethernet
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if etype == 0x8100 and len(data) >= 18:
            etype = struct.unpack("!H", data[16:18])[0]
            off = 18
        return data[off:] if etype == 0x0800 else None
    if linktype == 101:                             # raw IP
        return data
    return None


def _read_pcapng(f):
    """Minimal pcapng reader: section header, interface descriptions and enhanced/simple packet blocks."""
    end, ifs = "<", []
    while True:
        h = f.read(8)
        if len(h) < 8:
            return
        btype = struct.unpack(end + "I", h[:4])[0]
        if btype == 0x0A0D0D0A:                     # section header: byte order from the magic
            bom = f.read(4)
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(end + "I", h[4:8])[0]
            f.read(blen - 12)
            ifs = []
            continue
        blen = struct.unpack(end + "I", h[4:8])[0]
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:                              # interface description
            linktype = struct.unpack(end + "H", body[:2])[0]
            res = 1e-6
            opts = body[8:-4]
            i = 0
            while i + 4 <= len(opts):
                code, ln = struct.unpack(end + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = opts[i + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + ((ln + 3) & ~3)
            ifs.append((linktype, res))
        elif btype == 6:                            # enhanced packet
            iface, th, tl, cap = struct.unpack(end + "IIII", body[:16])
            linktype, res = ifs[iface] if iface < len(ifs) else (1, 1e-6)
            ipb = _l2(linktype, body[20:20 + cap])
            if ipb is not None:
                yield ((th << 32) | tl) * res, ipb
        elif btype == 3 and ifs:                    # simple packet (no timestamp)
            pass


def read_packets(path):
    """Yield (timestamp, ip-layer bytes) for IPv4 packets of an Ethernet pcap or pcapng file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if gh[:4] == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            for x in _read_pcapng(f):
                yield x
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise ValueError("not a pcap file: %s" % path)
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        rec = struct.Struct(end + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(h)
            data = f.read(incl)
            t = sec + frac / (1e9 if nano else 1e6)
            if linktype == 1:                       # Ethernet
                if len(data) < 14:
                    continue
                etype = struct.unpack("!H", data[12:14])[0]
                off = 14
                if etype == 0x8100 and len(data) >= 18:
                    etype = struct.unpack("!H", data[16:18])[0]
                    off = 18
                if etype != 0x0800:
                    continue
                yield t, data[off:]
            elif linktype == 101:                   # raw IP
                yield t, data


def parse(ipb):
    """(src, dst, proto, sport, dport, flags, icmp_inner) or None. icmp_inner: (type, code, orig tuple)."""
    if len(ipb) < 20:
        return None
    vihl, _tos, _tl, _id, _frag, _ttl, proto, _ck, s, d = _IP.unpack(ipb[:20])
    ihl = (vihl & 0x0F) * 4
    src, dst = _ip(s), _ip(d)
    l4 = ipb[ihl:]
    if proto == 6 and len(l4) >= 14:
        sport, dport = struct.unpack("!HH", l4[:4])
        return src, dst, 6, sport, dport, l4[13], None
    if proto == 17 and len(l4) >= 4:
        sport, dport = struct.unpack("!HH", l4[:4])
        return src, dst, 17, sport, dport, 0, None
    if proto == 1 and len(l4) >= 8 + 20:
        itype, icode = l4[0], l4[1]
        inner = l4[8:]
        r = parse(inner) if itype == 3 else None
        return src, dst, 1, 0, 0, 0, (itype, icode, r)
    return None


SYN, ACK, RST = 0x02, 0x10, 0x04


def can_initiate(dst, proto, sport, dport):
    """False for packets that cannot start a resolvable connection attempt: broadcast/multicast destinations
    (no unicast answer is possible) and UDP sent from a well-known service port to an ephemeral port (a server's
    reply or announcement, e.g. NetBIOS name service, whose request was not seen)."""
    o = dst.split(".")
    if dst == "255.255.255.255" or o[3] == "255" or 224 <= int(o[0]) <= 239:
        return False
    if proto == 17 and sport < 1024 <= dport:
        return False
    return True


def extract(path, timeout=TIMEOUT):
    """Return (attempts, newflows, packets_seen, t_first, t_last)."""
    pending = {}            # (src, dst, proto, sport, dport) -> Attempt fields (t, ...)
    seen_tuples = set()
    flows_seen = set()
    attempts, newflows = [], []
    n = 0
    t0 = t_last = None

    def close(key, outcome, t_out):
        a = pending.pop(key)
        attempts.append(Attempt(a[0], key[0], key[1], key[2], key[4], key[3], outcome, t_out))

    for t, ipb in read_packets(path):
        n += 1
        t0 = t if t0 is None else t0
        t_last = t
        # time out attempts that never got an answer
        if pending and n % 64 == 0:
            for key in [k for k, v in pending.items() if t - v[0] > timeout]:
                close(key, "failure", pending[key][0] + timeout)
        p = parse(ipb)
        if p is None:
            continue
        src, dst, proto, sport, dport, flags, icmp = p
        if proto in (6, 17):
            fk = (src, dst, proto, sport, dport)
            if fk not in flows_seen:
                flows_seen.add(fk)
                newflows.append(NewFlow(t, src, dst, proto, dport, sport))
        if proto == 6:
            key = (src, dst, 6, sport, dport)
            rkey = (dst, src, 6, dport, sport)
            if flags & SYN and not flags & ACK:
                if key not in seen_tuples and can_initiate(dst, 6, sport, dport):
                    seen_tuples.add(key)
                    pending[key] = (t,)
            elif rkey in pending:
                if flags & SYN and flags & ACK:
                    close(rkey, "success", t)
                elif flags & RST:
                    close(rkey, "failure", t)
        elif proto == 17:
            key = (src, dst, 17, sport, dport)
            rkey = (dst, src, 17, dport, sport)
            if rkey in pending:
                close(rkey, "success", t)
            elif key not in seen_tuples and rkey not in seen_tuples and can_initiate(dst, 17, sport, dport):
                seen_tuples.add(key)
                pending[key] = (t,)
        elif proto == 1 and icmp and icmp[0] == 3 and icmp[2]:
            osrc, odst, oproto, osport, odport = icmp[2][:5]
            okey = (osrc, odst, oproto, osport, odport)
            if okey in pending:
                close(okey, "failure", t)
    for key in list(pending):
        close(key, "failure", min(pending[key][0] + timeout, (t_last or 0) + timeout))
    attempts.sort(key=lambda a: a.t_outcome)
    return attempts, newflows, n, t0, t_last
