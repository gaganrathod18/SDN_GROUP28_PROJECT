"""Scan / flood detectors evaluated on the same connection attempts.

All detectors consume the time-ordered output of pcapio.extract() and return, per source host, the time of the
first alarm (or None) plus a continuous score used for ROC curves.

    AISPRT       proposed: adaptive, initiation-aware sequential probability ratio test with novelty-weighted
                 evidence, retry de-duplication, evidence decay and a CUSUM flood detector
    TRW          Threshold Random Walk (Jung et al., 2004) on first-contact (destination, port) pairs
    IAWindow     initiation-aware sliding-window distinct-port threshold (our previous PacMan detector)
    NaiveWindow  every new flow counts (replies included), sliding-window distinct-port threshold
    Entropy      sliding-window port entropy of initiated connections
"""
import math
from collections import defaultdict, deque


class Result(object):
    def __init__(self):
        self.alarm = {}            # src -> first alarm time
        self.kind = {}             # src -> alarm type
        self.score = defaultdict(float)   # src -> max score reached
        self.events = []           # (t, src, action, scope)

    def fire(self, t, src, kind, scope="host"):
        if src not in self.alarm:
            self.alarm[src] = t
            self.kind[src] = kind
        self.events.append((t, src, kind, scope))


# ------------------------------------------------------------------------------------------- proposed
class AISPRT(object):
    """Adaptive Initiation-aware SPRT.

    For every source s a log-likelihood ratio L_s between H1 (scanner, success prob theta1) and H0 (benign,
    success prob theta0) is updated with the outcome of each *new* first contact (d, p):
        success: L += w * ln(theta1/theta0)          failure: L += w * ln((1-theta1)/(1-theta0))
    w = novelty weight of (d, p): 1 if no other source has contacted (d, p) in the past, w_min..1 decreasing with
    the number of distinct other sources that use that service (popular broken services are weak evidence).
    Each (s, d, p) is scored once (first contact; `dedup` = horizon, default: the whole observation), so retries and
    repeated benign use of the same service are not re-counted. L decays towards 0 with time constant tau
    between updates, so benign noise does not accumulate forever while scans faster than ~1 probe per tau/eta
    still cross the threshold. Wald thresholds: eta1 = ln(beta/alpha) (scanner), eta0 = ln((1-beta)/(1-alpha))
    (benign, reset). Graded response: L >= eta_s = rho*eta1 -> block (s, d*) only; L >= eta1 -> block host.
    Floods: one-sided CUSUM on the per-second rate of initiated connections.
    """

    def __init__(self, theta0=0.8, theta1=0.2, alpha=0.01, beta=0.99, tau=600.0, rho=0.5, dedup=float("inf"),
                 w_min=0.25, use_novelty=True, use_decay=True, use_dedup=True, use_cusum=True, cusum_k=20.0, cusum_h=150.0,
                 eta1=None):
        self.t0, self.t1 = theta0, theta1
        self.eta1 = math.log(beta / alpha) if eta1 is None else eta1
        self.eta0 = math.log((1 - beta) / (1 - alpha))
        self.tau, self.rho, self.dedup, self.w_min = tau, rho, dedup, w_min
        self.use_novelty, self.use_decay, self.use_dedup, self.use_cusum = use_novelty, use_decay, use_dedup, use_cusum
        self.k, self.h = cusum_k, cusum_h
        self.s_succ = math.log(theta1 / theta0)
        self.s_fail = math.log((1 - theta1) / (1 - theta0))

        self.reset()

    def reset(self):
        self.L, self.tl = defaultdict(float), {}
        self.users = defaultdict(set)             # (d, p) -> sources that contacted it
        self.recent = {}                          # (s, d, p) -> last time counted
        self.fails_to = defaultdict(lambda: defaultdict(int))
        self.suspected = set()
        self.cus, self.cus_bucket, self.cus_count = defaultdict(float), {}, defaultdict(int)
        self.score = defaultdict(float)

    def step(self, a):
        """Process one resolved attempt; return a list of actions (t, src, kind, scope)."""
        out = []
        s, d, p, t = a.src, a.dst, a.dport, a.t_outcome
        # flood: one-sided CUSUM on initiated connections per second
        b = int(a.t)
        if self.cus_bucket.get(s) != b:
            if s in self.cus_bucket:
                gap = b - self.cus_bucket[s]
                self.cus[s] = max(0.0, self.cus[s] + self.cus_count[s] - self.k)
                for _ in range(min(gap - 1, 50)):
                    self.cus[s] = max(0.0, self.cus[s] - self.k)
            self.cus_bucket[s], self.cus_count[s] = b, 0
        self.cus_count[s] += 1
        if self.use_cusum and self.cus[s] + self.cus_count[s] - self.k > self.h:
            out.append((a.t, s, "SYN_FLOOD", "host"))
        # scan: sequential test on de-duplicated first contacts, novelty-weighted, with decay
        key = (s, d, p)
        if self.use_dedup and key in self.recent and t - self.recent[key] < self.dedup:
            self.users[(d, p)].add(s)
            return out
        self.recent[key] = t
        others = len(self.users[(d, p)] - {s})
        self.users[(d, p)].add(s)
        w = max(self.w_min, 1.0 / (1.0 + others)) if (self.use_novelty and others) else 1.0
        if self.use_decay and s in self.tl:
            self.L[s] *= math.exp(-(t - self.tl[s]) / self.tau)
        self.tl[s] = t
        if a.outcome == "success":
            self.L[s] += self.s_succ
        else:
            self.L[s] += w * self.s_fail
            self.fails_to[s][d] += 1
        self.score[s] = max(self.score[s], self.L[s] / self.eta1)
        if self.L[s] >= self.eta1:
            out.append((t, s, "PORT_SCAN", "host"))
            self.L[s] = 0.0
            self.suspected.discard(s)            # a new attack after this decision is graded again
        elif self.L[s] >= self.rho * self.eta1 and s not in self.suspected:
            self.suspected.add(s)
            victim = max(self.fails_to[s].items(), key=lambda kv: kv[1])[0]
            out.append((t, s, "SUSPECT", victim))
        elif self.L[s] <= self.eta0:
            self.L[s] = 0.0
        return out

    def run(self, attempts):
        self.reset()
        r = Result()
        for a in attempts:
            for t, s, kind, scope in self.step(a):
                if kind == "SUSPECT":
                    r.events.append((t, s, kind, scope))
                else:
                    r.fire(t, s, kind, scope)
        r.score = self.score
        return r


# ------------------------------------------------------------------------------------------- baselines
class TRW(object):
    """Threshold Random Walk (Jung et al., 2004), first contacts = distinct (dst, port) per source."""

    def __init__(self, theta0=0.8, theta1=0.2, alpha=0.01, beta=0.99, eta1=None):
        self.eta1 = math.log(beta / alpha) if eta1 is None else eta1
        self.eta0 = math.log((1 - beta) / (1 - alpha))
        self.s_succ = math.log(theta1 / theta0)
        self.s_fail = math.log((1 - theta1) / (1 - theta0))

    def run(self, attempts):
        r = Result()
        L = defaultdict(float)
        first = set()
        for a in attempts:
            key = (a.src, a.dst, a.dport)
            if key in first:
                continue
            first.add(key)
            L[a.src] += self.s_succ if a.outcome == "success" else self.s_fail
            r.score[a.src] = max(r.score[a.src], L[a.src] / self.eta1)
            if L[a.src] >= self.eta1:
                r.fire(a.t_outcome, a.src, "PORT_SCAN")
                L[a.src] = 0.0
            elif L[a.src] <= self.eta0:
                L[a.src] = 0.0
        return r


class _Window(object):
    def __init__(self, window=10.0, threshold=15):
        self.W, self.th = window, threshold

    def _run(self, items):
        r = Result()
        ports = defaultdict(dict)        # (src, dst) -> {port: last t}
        for t, s, d, p in items:
            m = ports[(s, d)]
            m[p] = t
            for q in [q for q, tq in m.items() if t - tq > self.W]:
                del m[q]
            r.score[s] = max(r.score[s], len(m) / float(self.th))
            if len(m) > self.th:
                r.fire(t, s, "PORT_SCAN")
        return r


class IAWindow(_Window):
    """Previous PacMan detector: initiated connections only, > threshold distinct ports on one host in W s."""

    def run(self, attempts):
        return self._run((a.t, a.src, a.dst, a.dport) for a in sorted(attempts, key=lambda x: x.t))


class NaiveWindow(_Window):
    """Every new flow counts (replies included): the common simplification."""

    def run(self, newflows):
        return self._run((f.t, f.src, f.dst, f.dport) for f in newflows)


class Entropy(object):
    """Shannon entropy (bits) of destination ports of a source's initiated connections in a W-second window."""

    def __init__(self, window=10.0, h=3.0, min_n=10):
        self.W, self.h, self.min_n = window, h, min_n

    def run(self, attempts):
        r = Result()
        q = defaultdict(deque)
        for a in sorted(attempts, key=lambda x: x.t):
            dq = q[a.src]
            dq.append((a.t, a.dport))
            while dq and a.t - dq[0][0] > self.W:
                dq.popleft()
            if len(dq) < self.min_n:
                continue
            cnt = defaultdict(int)
            for _, p in dq:
                cnt[p] += 1
            n = float(len(dq))
            H = -sum(c / n * math.log(c / n, 2) for c in cnt.values())
            r.score[a.src] = max(r.score[a.src], H / self.h)
            if H > self.h:
                r.fire(a.t, a.src, "PORT_SCAN")
        return r


def window_features(attempts, src, t_from, t_to):
    """Per-source features of one window, for the machine-learning baseline."""
    xs = [a for a in attempts if a.src == src and t_from <= a.t < t_to]
    n = len(xs)
    if n == 0:
        return [0, 0, 0, 0, 0, 0]
    dsts = len({a.dst for a in xs})
    ports = len({(a.dst, a.dport) for a in xs})
    fail = sum(1 for a in xs if a.outcome == "failure") / float(n)
    cnt = defaultdict(int)
    for a in xs:
        cnt[a.dport] += 1
    H = -sum(c / float(n) * math.log(c / float(n), 2) for c in cnt.values())
    return [n, dsts, ports, fail, H, n / max(t_to - t_from, 1e-6)]
