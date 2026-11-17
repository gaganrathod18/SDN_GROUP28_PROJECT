#!/usr/bin/env python3
"""
Cross-dataset test on the public CIC-IDS2017 Friday capture (Sharafaldin et al., ICISSP 2018).

    python3 scripts/eval_cicids.py

Protocol (no tuning on test data):
  * Calibration part: Friday 09:00-12:00 local time, before the scan and the DDoS (botnet hosts excluded). Only the
    flood threshold h of the CUSUM is set there: h = 1.2 x the largest CUSUM statistic of any host (kappa stays
    20/s). The scan test keeps the Wald thresholds of the paper, which follow from (alpha, beta) and need no data.
  * Test part: Friday 12:00-end. The Random Forest is trained on our emulated dataset only.
Ground truth (dataset description; local time ADT = UTC-3, 7 July 2017):
  ARES botnet 10:02-11:02, infected hosts .5/.8/.9/.14/.15 (C&C traffic, no scanning: excluded);
  PortScan 13:55-15:24 and DDoS LOIT 15:56-16:04 (from the labelled flows) by 172.16.0.1 (NAT address of the attacker) -> 192.168.10.50.
Every other source that initiates traffic in the test part is a negative. Alarms of the attacker outside its two
episodes (60 s slack) are reported separately. Writes results/eval_cicids/*, report_ieee/figures/c_trace.pdf and
report_ieee/generated/cicids.tex. After the first run only the small attempts cache is needed (the pcap may be deleted).
"""
import calendar
import csv
import math
import os
import pickle
import sys
import time
from collections import defaultdict

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(PROJECT, "detector"))
sys.path.insert(0, HERE)
import pcapio                                          # noqa: E402
from detectors import AISPRT, TRW, IAWindow, NaiveWindow, Entropy  # noqa: E402

# the capture (or its extracted attempts cache) lives in ../datasets/cicids2017 next to PROJECT; override with CICIDS_DIR
DATA = os.environ.get("CICIDS_DIR", os.path.join(os.path.dirname(PROJECT), "datasets", "cicids2017"))
PCAP = os.path.join(DATA, "Friday-WorkingHours.pcap")
CACHE = PCAP.replace(".pcap", ".attempts.pkl")
OUT = os.path.join(PROJECT, "results", "eval_cicids")
FIG = os.path.join(PROJECT, "report_ieee", "figures")
GEN = os.path.join(PROJECT, "report_ieee", "generated")
TZ = -3 * 3600
SLACK = 60.0
KAPPA = 20.0
ALARMS = ("PORT_SCAN", "SYN_FLOOD")
ATTACKER = "172.16.0.1"
BOTS = {"192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"}


def local(hm):
    h, m = map(int, hm.split(":"))
    return calendar.timegm((2017, 7, 7, h, m, 0)) - TZ


SPLIT = local("12:00")
# episode windows = first and last minute of the labelled attack flows in the official CSVs
# (Friday-WorkingHours-Afternoon-PortScan/-DDos.pcap_ISCX.csv); the times on the dataset web page are not exact
# PortScan: 13:55-14:16 only probes 5 services (80, 443, 21, 22, 444); the scan proper (~1000 ports) starts at 14:51,
# and its delay is measured from there. DDoS: the labelled flows stop at 16:03, but the same port-80 flood from
# 172.16.0.1 continues until 16:16, as the dataset description says.
EPISODES = [("PortScan", local("13:55"), local("15:24")), ("DDoS LOIT", local("15:56"), local("16:16"))]
DELAY_FROM = {"PortScan": local("14:51"), "DDoS LOIT": local("15:56")}


def methods(h):
    return {
        "AIS-SPRT (ours)": lambda: AISPRT(cusum_h=h),
        "TRW": lambda: TRW(),
        "Entropy": lambda: Entropy(10.0, 3.0, 10),
        "IA-Window": lambda: IAWindow(10.0, 15),
        "Naive-Window": lambda: NaiveWindow(10.0, 15),
        "AIS-SPRT, emulation h": lambda: AISPRT(),
        "w/o novelty weight": lambda: AISPRT(cusum_h=h, use_novelty=False),
        "w/o flood CUSUM": lambda: AISPRT(cusum_h=h, use_cusum=False),
        "w/o evidence decay": lambda: AISPRT(cusum_h=h, use_decay=False),
        "re-score after 30 s": lambda: AISPRT(cusum_h=h, dedup=30.0),
    }


def load():
    if os.path.exists(CACHE) and (not os.path.exists(PCAP) or os.path.getmtime(CACHE) > os.path.getmtime(PCAP)):
        return pickle.load(open(CACHE, "rb"))
    t = time.time()
    att, nf, n, t0, t1 = pcapio.extract(PCAP)
    att.sort(key=lambda a: a.t)
    d = dict(attempts=att, newflows=nf, packets=n, t0=t0, t1=t1, secs=time.time() - t)
    pickle.dump(d, open(CACHE, "wb"), protocol=4)
    return d


def cusum_max(attempts, k=KAPPA):
    """Largest one-sided CUSUM statistic of initiated connections per second, per source (as in AISPRT)."""
    per = defaultdict(lambda: defaultdict(int))
    for a in attempts:
        per[a.src][int(a.t)] += 1
    out = {}
    for s, cnt in per.items():
        S, best, last = 0.0, 0.0, None
        for sec in sorted(cnt):
            if last is not None:
                S = max(0.0, S - k * min(sec - last - 1, 50))
            S = max(0.0, S + cnt[sec] - k)
            best = max(best, S)
            last = sec
        out[s] = best
    return out


def evaluate(events, srcs, episodes):
    det, first_fp, outside = {}, {}, 0
    for t, s, kind, _ in sorted(events):
        if kind not in ALARMS:
            continue
        if s == ATTACKER:
            hit = [n for n, a, b in episodes if a - SLACK <= t <= b + SLACK]
            if not hit:
                outside += 1
            elif hit[0] not in det:
                det[hit[0]] = t
        elif s not in BOTS:
            first_fp.setdefault(s, t)
    neg = [s for s in srcs if s != ATTACKER and s not in BOTS]
    P, TP = len(episodes), len(det)
    FP = sum(1 for s in neg if s in first_fp)
    prec = TP / float(TP + FP) if TP + FP else float("nan")
    tpr = TP / float(P) if P else float("nan")
    return dict(P=P, TP=TP, N=len(neg), FP=FP, TPR=tpr, FPR=FP / float(len(neg)), precision=prec,
                F1=2 * prec * tpr / (prec + tpr) if TP else 0.0, outside=outside, fp_hosts=sorted(first_fp),
                delay={n: (max(0.0, det[n] - DELAY_FROM[n]) if n in det else None) for n, a, _ in episodes})


# ------------------------------------------------------------------------------- Random Forest (trained on our data)
def bucket_features(attempts, W=10.0):
    """The six features of detectors.window_features, computed in one pass: (src, window end) -> features."""
    g = defaultdict(list)
    for a in attempts:
        g[(a.src, int(a.t // W))].append(a)
    out = {}
    for (s, k), xs in g.items():
        n = len(xs)
        cnt = defaultdict(int)
        for a in xs:
            cnt[a.dport] += 1
        H = -sum(c / float(n) * math.log(c / float(n), 2) for c in cnt.values())
        out[(s, (k + 1) * W)] = [n, len({a.dst for a in xs}), len({(a.dst, a.dport) for a in xs}),
                                 sum(1 for a in xs if a.outcome == "failure") / float(n), H, n / W]
    return out


def rf_events(attempts):
    from sklearn.ensemble import RandomForestClassifier
    import eval_detectors as ed
    X, Y = [], []
    for r in ed.load():
        if r["seed"] != 1:
            continue
        for (s, t1), f in bucket_features(r["attempts"]).items():
            X.append(f)
            Y.append(int(s in r["attackers"] and r["atk_t"] is not None and t1 > r["atk_t"]))
    clf = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced").fit(X, Y)
    feats = bucket_features(attempts)
    keys = list(feats)
    p = clf.predict_proba([feats[k] for k in keys])[:, 1]
    return [(t, s, "PORT_SCAN", "host") for (s, t), q in zip(keys, p) if q >= 0.5]


def iforest_events(train, test):
    """Isolation Forest (unsupervised) fitted on the benign calibration part; alarm when a window is in the most
    anomalous 0.1 % of the calibration windows' scores."""
    from sklearn.ensemble import IsolationForest
    tr = bucket_features([a for a in train if a.src not in BOTS])
    X = list(tr.values())
    clf = IsolationForest(n_estimators=200, random_state=0).fit(X)
    import numpy as np
    thr = np.percentile(clf.score_samples(X), 0.1)
    feats = bucket_features(test)
    keys = list(feats)
    sc = clf.score_samples([feats[k] for k in keys])
    return [(t, s, "PORT_SCAN", "host") for (s, t), q in zip(keys, sc) if q < thr]


# ------------------------------------------------------------------------------- main
def fmt(x, nd=1):
    return "--" if x is None else ("%.*f" % (nd, x))


def main():
    os.makedirs(OUT, exist_ok=True)
    d = load()
    am = [a for a in d["attempts"] if a.t < SPLIT]
    pm = [a for a in d["attempts"] if a.t >= SPLIT]
    nf_am = [f for f in d["newflows"] if f.t < SPLIT]
    nf_pm = [f for f in d["newflows"] if f.t >= SPLIT]
    log = []

    def say(s):
        print(s)
        log.append(s)

    hm = lambda t: time.strftime("%H:%M", time.gmtime(t + TZ))  # noqa: E731
    say("Friday: packets %d, attempts %d, capture %s-%s local, extraction %.0f s" % (
        d["packets"], len(d["attempts"]), hm(d["t0"]), hm(d["t1"]), d["secs"]))
    say("calibration part: %d attempts, %d sources; test part: %d attempts, %d sources" % (
        len(am), len({a.src for a in am}), len(pm), len({a.src for a in pm})))
    for n, a, b in EPISODES:
        xs = [x for x in pm if x.src == ATTACKER and a <= x.t <= b]
        say("    %-10s attacker attempts %7d, failures %7d, ports %d" % (
            n, len(xs), sum(x.outcome == "failure" for x in xs), len({x.dport for x in xs})))

    cm = cusum_max([a for a in am if a.src not in BOTS])
    top = sorted(cm.items(), key=lambda kv: -kv[1])[:5]
    h = int(math.ceil(1.2 * top[0][1] / 10.0) * 10)
    say("calibration: largest CUSUM %s -> h = %d" % (", ".join("%s %.0f" % kv for kv in top), h))

    per = {}
    calib = {}
    srcs_am, srcs_pm = sorted({a.src for a in am}), sorted({a.src for a in pm})
    for m, f in methods(h).items():
        res = f().run(nf_pm if m.startswith("Naive") else pm)
        per[m] = evaluate(res.events, srcs_pm, EPISODES)
        res = f().run(nf_am if m.startswith("Naive") else am)
        calib[m] = evaluate(res.events, srcs_am, [])
    per["Random Forest"] = evaluate(rf_events(pm), srcs_pm, EPISODES)
    per["Isolation Forest"] = evaluate(iforest_events(am, pm), srcs_pm, EPISODES)

    eps = [n for n, _, _ in EPISODES]
    with open(os.path.join(OUT, "overall.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["method", "P", "TP", "N", "FP", "TPR", "FPR", "precision", "F1"] + ["delay_s " + e for e in eps] +
                   ["attacker alarms outside episodes", "calibration-part FP", "fp_hosts"])
        for m, r in per.items():
            c = calib.get(m)
            w.writerow([m, r["P"], r["TP"], r["N"], r["FP"], "%.3f" % r["TPR"], "%.4f" % r["FPR"], "%.3f" % r["precision"],
                        "%.3f" % r["F1"]] + [fmt(r["delay"][e]) for e in eps] +
                       [r["outside"], "" if c is None else "%d/%d" % (c["FP"], c["N"]), " ".join(r["fp_hosts"])])
            say("%-24s TP %d/%d  FP %3d/%d  F1 %.3f  delay %s s  outside %d  calib FP %s" % (
                m, r["TP"], r["P"], r["FP"], r["N"], r["F1"], " / ".join(fmt(r["delay"][e]) for e in eps), r["outside"],
                "-" if c is None else "%d/%d" % (c["FP"], c["N"])))
            if r["fp_hosts"] and len(r["fp_hosts"]) <= 8:
                say("    FP hosts: " + " ".join(r["fp_hosts"]))
    open(os.path.join(OUT, "summary.txt"), "w").write("\n".join(log) + "\n")
    sw = sweep(pm, srcs_pm, h)
    write_tex(d, am, pm, per, calib, h, top[0][1], eps, sw)
    figure_alpha(sw)


ALPHAS = (0.03, 0.01, 0.003, 0.001, 0.0003, 0.0001)


def sweep(pm, srcs, h):
    """F1 against the false-alarm target alpha (eta1 = ln(beta/alpha)) on both datasets, AIS-SPRT and TRW."""
    import eval_detectors as ed
    emu = [r for r in ed.load() if r["seed"] != 1]
    rows = []
    for alpha in ALPHAS:
        eta = math.log(0.99 / alpha)
        for m, mk in (("AIS-SPRT", lambda: AISPRT(cusum_h=h, eta1=eta)), ("TRW", lambda: TRW(eta1=eta))):
            r = evaluate(mk().run(pm).events, srcs, EPISODES)
            rows.append(dict(alpha=alpha, method=m, dataset="CIC-IDS2017", F1=r["F1"], TP=r["TP"], FP=r["FP"],
                             delay=r["delay"]["PortScan"]))
        for m, mk in (("AIS-SPRT", lambda: AISPRT(eta1=eta)), ("TRW", lambda: TRW(eta1=eta))):
            out = []
            for run in emu:
                out += ed.outcome(run, mk().run(run["attempts"]))
            sm = ed.summarise(out)
            rows.append(dict(alpha=alpha, method=m, dataset="emulated", F1=sm["F1"], TP=sm["TP"], FP=sm["FP"],
                             delay=sm["delay_med"]))
    with open(os.path.join(OUT, "alpha_sweep.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["dataset", "method", "alpha", "TP", "FP", "F1", "delay"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
            print("sweep %-12s %-8s alpha %-7g TP %3d FP %2d F1 %.3f delay %s" % (
                r["dataset"], r["method"], r["alpha"], r["TP"], r["FP"], r["F1"], fmt(r["delay"], 2)))
    return rows


def figure_alpha(rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8.5, "pdf.fonttype": 42})
    fig, ax = plt.subplots(figsize=(3.5, 2.15))
    sty = {("AIS-SPRT", "CIC-IDS2017"): ("#e11d48", "-", "o"), ("AIS-SPRT", "emulated"): ("#e11d48", "--", "s"),
           ("TRW", "CIC-IDS2017"): ("#57534e", "-", "o"), ("TRW", "emulated"): ("#57534e", "--", "s")}
    for (m, ds), (c, ls, mk) in sty.items():
        xs = [r["alpha"] for r in rows if r["method"] == m and r["dataset"] == ds]
        ys = [r["F1"] for r in rows if r["method"] == m and r["dataset"] == ds]
        ax.plot(xs, ys, color=c, ls=ls, marker=mk, ms=3.5, lw=1.1, label="%s, %s" % (m, ds))
    ax.axvline(0.01, color="#a8a29e", ls=":", lw=0.8)
    ax.text(0.0095, 0.53, r"default $\alpha$", fontsize=7, color="#57534e")
    ax.set_xscale("log")
    ax.invert_xaxis()
    ax.set_xlabel(r"False-alarm target $\alpha$ (stricter $\rightarrow$)")
    ax.set_ylabel("F1")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=6.5, loc="lower center", ncol=2, frameon=False, columnspacing=1.0, handlelength=2.2)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "c_alpha.pdf"))


def write_tex(d, am, pm, per, calib, h, smax, eps, sw):
    os.makedirs(GEN, exist_ok=True)
    order = ["AIS-SPRT (ours)", "TRW", "Entropy", "Random Forest", "Isolation Forest", "IA-Window", "Naive-Window"]
    rows = []
    for m in order:
        r = per[m]
        name = "\\textbf{AIS-SPRT}" if m.startswith("AIS") else m
        rows.append("%s & %d/%d & %d/%d & %.3f & %s \\\\" % (
            name, r["TP"], r["P"], r["FP"], r["N"], r["F1"], " & ".join(fmt(r["delay"][e]) for e in eps)))

    def c(x):
        return "{:,}".format(x).replace(",", "{,}")
    with open(os.path.join(GEN, "cicids.tex"), "w") as fh:
        fh.write("%% generated by scripts/eval_cicids.py\n")
        fh.write("\\newcommand{\\cicPackets}{%s}\n" % c(d["packets"]))
        fh.write("\\newcommand{\\cicAttempts}{%s}\n" % c(len(d["attempts"])))
        fh.write("\\newcommand{\\cicCalAttempts}{%s}\n" % c(len(am)))
        fh.write("\\newcommand{\\cicTestAttempts}{%s}\n" % c(len(pm)))
        fh.write("\\newcommand{\\cicNeg}{%d}\n" % per["TRW"]["N"])
        fh.write("\\newcommand{\\cicH}{%d}\n" % h)
        fh.write("\\newcommand{\\cicSmax}{%.0f}\n" % smax)
        fh.write("\\newcommand{\\cicRows}{%s}\n" % "\n".join(rows))
        for r in sw:
            if r["method"] == "AIS-SPRT" and r["alpha"] in (0.001, 0.0003):
                key = ("Cic" if r["dataset"] == "CIC-IDS2017" else "Emu") + ("A" if r["alpha"] == 0.001 else "B")
                fh.write("\\newcommand{\\sw%sFone}{%.2f}\\newcommand{\\sw%sFP}{%d}\\newcommand{\\sw%sDelay}{%s}\n" % (
                    key, r["F1"], key, r["FP"], key, fmt(r["delay"], 1)))
        for m, key in (("AIS-SPRT (ours)", "Ours"), ("AIS-SPRT, emulation h", "EmuH"), ("w/o novelty weight", "NoNov"),
                       ("w/o flood CUSUM", "NoCus"), ("w/o evidence decay", "NoDecay"), ("re-score after 30 s", "Rescore")):
            r = per[m]
            fh.write("\\newcommand{\\cic%sTP}{%d}\\newcommand{\\cic%sFP}{%d}\\newcommand{\\cic%sCalFP}{%d}\n" % (
                key, r["TP"], key, r["FP"], key, calib[m]["FP"]))


def figure(att, h):
    """Afternoon: normalised scan evidence of the attacker vs. the most suspicious negative host."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8.5, "pdf.fonttype": 42})
    det = AISPRT(cusum_h=h)
    tr = defaultdict(list)
    for a in att:
        det.step(a)
        tr[a.src].append((a.t_outcome, det.L[a.src] / det.eta1))
    neg = [s for s in tr if s != ATTACKER and s not in BOTS]
    worst = max(neg, key=lambda s: max(v for _, v in tr[s]))
    hrs = lambda t: (t - local("00:00")) / 3600.0  # noqa: E731
    fig, ax = plt.subplots(figsize=(3.5, 2.3))
    for s, col, lab in ((worst, "#059669", "most suspicious benign (%s)" % worst), (ATTACKER, "#e11d48", "attacker 172.16.0.1")):
        ax.plot([hrs(t) for t, _ in tr[s]], [min(v, 1.0) for _, v in tr[s]], color=col, lw=0.8, label=lab)
    for _, a, b in EPISODES:
        ax.axvspan(hrs(a), hrs(b), color="#fde68a", alpha=0.7, lw=0)
    ax.axhline(1.0, color="#44403c", ls="--", lw=0.8)
    ax.axhline(0.5, color="#a8a29e", ls=":", lw=0.8)
    ax.text(hrs(local("14:40")), 1.04, "scan", ha="center", fontsize=7)
    ax.text(hrs(local("16:00")), 1.04, "DDoS", ha="center", fontsize=7)
    ax.set_xlabel("Local time, Friday 7 July 2017 (h)")
    ax.set_ylabel(r"Scan evidence $L_s/\eta_1$")
    ax.set_ylim(-1.05, 1.15)
    ax.legend(fontsize=6.5, loc="lower left", frameon=False)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "c_trace.pdf"))
    print("figure: most suspicious benign host", worst, "peak %.2f" % max(v for _, v in tr[worst]))


if __name__ == "__main__":
    main()
