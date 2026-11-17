#!/usr/bin/env python3
"""
Evaluate the proposed AIS-SPRT detector against five baselines on the labelled dataset (results/dataset/).

    python3 scripts/eval_detectors.py

Host-level ground truth: the attackers of a run are positives from the attack start on; every other host that
initiates traffic is a negative. Writes results/eval/*.csv and report_ieee/figures/e_*.pdf.
"""
import csv
import glob
import json
import math
import os
import statistics
import sys
from collections import defaultdict

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(PROJECT, "detector"))
import pcapio                                          # noqa: E402
from detectors import AISPRT, TRW, IAWindow, NaiveWindow, Entropy, window_features  # noqa: E402

DATA = os.path.join(PROJECT, "results", "dataset")
OUT = os.path.join(PROJECT, "results", "eval")
FIG = os.path.join(PROJECT, "report_ieee", "figures")
SCEN = ["benign", "outage", "vfast", "vslow05", "vslow02", "horiz", "dist", "flood"]
SCEN_LABEL = {"benign": "Benign only", "outage": "Server outage", "vfast": "Fast vertical", "vslow05": "Slow 0.5/s", "vslow02": "Slow 0.2/s",
              "horiz": "Horizontal", "dist": "Distributed", "flood": "Flood"}
ALARM_KINDS = ("PORT_SCAN", "SYN_FLOOD")


def load():
    runs = []
    for js in sorted(glob.glob(os.path.join(DATA, "*.json"))):
        meta = json.load(open(js))
        att, nf, n, t0, t1 = pcapio.extract(js.replace(".json", ".pcap"))
        if not att:
            continue
        meta["attempts"], meta["newflows"], meta["packets"] = att, nf, n
        meta["t0"] = t0
        meta["atk_t"] = meta.get("attack_t")          # pcap timestamps and attack_t are both wall-clock time
        runs.append(meta)
    return runs


def sources(run):
    return sorted({a.src for a in run["attempts"]})


def outcome(run, res):
    """Per-host classification of one run: TP/FN for attackers (alarm after attack start), FP/TN otherwise."""
    atk = set(run["attackers"])
    first = defaultdict(lambda: None)
    for t, s, kind, _scope in sorted(res.events):
        if kind not in ALARM_KINDS:
            continue
        if s in atk and run["atk_t"] is not None and t >= run["atk_t"] - 0.5:
            if first[s] is None:
                first[s] = t
        elif s not in atk:
            first.setdefault(("fp", s), t)
    rows = []
    for s in sources(run):
        if s in atk:
            t = first[s]
            delay = (t - run["atk_t"]) if t is not None else None
            probes = sum(1 for a in run["attempts"] if a.src == s and run["atk_t"] - 0.5 <= a.t <= t) if t is not None else None
            rows.append(dict(host=s, label=1, alarm=t is not None, delay=delay, probes=probes))
        else:
            rows.append(dict(host=s, label=0, alarm=("fp", s) in first, delay=None, probes=None))
    return rows


def run_detector(name, det, run):
    if name.startswith("Naive"):
        return det.run(run["newflows"])
    return det.run(run["attempts"])


DEFAULTS = {
    "AIS-SPRT (ours)": lambda: AISPRT(),
    "TRW": lambda: TRW(),
    "IA-Window": lambda: IAWindow(10.0, 15),
    "Naive-Window": lambda: NaiveWindow(10.0, 15),
    "Entropy": lambda: Entropy(10.0, 3.0, 10),
}
SWEEP = {
    "AIS-SPRT (ours)": [AISPRT(eta1=x) for x in (1, 2, 3, 4, 4.6, 6, 8, 10, 14, 20)],
    "TRW": [TRW(eta1=x) for x in (1, 2, 3, 4, 4.6, 6, 8, 10, 14, 20)],
    "IA-Window": [IAWindow(10.0, k) for k in (2, 4, 6, 8, 10, 15, 20, 30, 50, 80)],
    "Naive-Window": [NaiveWindow(10.0, k) for k in (2, 4, 6, 8, 10, 15, 20, 30, 50, 80)],
    "Entropy": [Entropy(10.0, h, 10) for h in (0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0)],
}
ABLATION = {
    "AIS-SPRT (full)": lambda: AISPRT(),
    "w/o novelty weight": lambda: AISPRT(use_novelty=False),
    "w/o flood CUSUM": lambda: AISPRT(use_cusum=False),
    "w/o evidence decay": lambda: AISPRT(use_decay=False),
    "re-score after 30 s": lambda: AISPRT(dedup=30.0),
    "TRW": lambda: TRW(),
}


# ------------------------------------------------------------------------------- ML baseline (Random Forest)
def rf_baseline(runs, train_seed=1, W=10.0):
    from sklearn.ensemble import RandomForestClassifier

    def windows(run):
        xs, ys, keys = [], [], []
        att = sorted(run["attempts"], key=lambda a: a.t)
        t0, t1 = att[0].t, att[-1].t
        k = 0
        while t0 + k * W <= t1:
            a0, a1 = t0 + k * W, t0 + (k + 1) * W
            for s in sources(run):
                f = window_features(run["attempts"], s, a0, a1)
                if f[0] == 0:
                    continue
                lab = int(s in run["attackers"] and run["atk_t"] is not None and a1 > run["atk_t"])
                xs.append(f)
                ys.append(lab)
                keys.append((s, a1))
            k += 1
        return xs, ys, keys

    X, Y = [], []
    for r in runs:
        if r["seed"] == train_seed:
            x, y, _ = windows(r)
            X += x
            Y += y
    clf = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced").fit(X, Y)
    out = {}
    for r in runs:
        if r["seed"] == train_seed:
            continue
        x, _y, keys = windows(r)
        probs = clf.predict_proba(x)[:, 1] if x else []
        out[(r["scenario"], r["seed"])] = list(zip(keys, probs))
    return out


def rf_outcome(run, scored, thr=0.5):
    class R(object):
        pass
    r = R()
    r.events = [(t, s, "PORT_SCAN", "host") for (s, t), p in scored if p >= thr]
    return outcome(run, r)


# ------------------------------------------------------------------------------- metrics
def summarise(rows):
    P = [r for r in rows if r["label"] == 1]
    N = [r for r in rows if r["label"] == 0]
    tp = sum(r["alarm"] for r in P)
    fp = sum(r["alarm"] for r in N)
    tpr = tp / float(len(P)) if P else float("nan")
    fpr = fp / float(len(N)) if N else float("nan")
    prec = tp / float(tp + fp) if tp + fp else float("nan")
    f1 = 2 * prec * tpr / (prec + tpr) if tp and prec == prec else 0.0
    d = [r["delay"] for r in P if r["alarm"]]
    pr = [r["probes"] for r in P if r["alarm"]]
    return dict(P=len(P), N=len(N), TP=tp, FP=fp, TPR=tpr, FPR=fpr, precision=prec, F1=f1,
                delay_med=statistics.median(d) if d else float("nan"),
                probes_med=statistics.median(pr) if pr else float("nan"))


def main():
    os.makedirs(OUT, exist_ok=True)
    runs = load()
    test = [r for r in runs if r["seed"] != 1]
    print("runs: %d (%d test)" % (len(runs), len(test)))
    print("packets: %d, attempts: %d" % (sum(r["packets"] for r in runs), sum(len(r["attempts"]) for r in runs)))

    rf = rf_baseline(runs)
    methods = list(DEFAULTS) + ["Random Forest"]
    per = defaultdict(list)                 # (method, scenario) -> rows (test seeds only, for comparability with RF)
    for r in test:
        for m in methods:
            if m == "Random Forest":
                rows = rf_outcome(r, rf[(r["scenario"], r["seed"])])
            else:
                rows = outcome(r, run_detector(m, DEFAULTS[m](), r))
            per[(m, r["scenario"])] += rows

    with open(os.path.join(OUT, "per_scenario.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "scenario", "P", "N", "TP", "FP", "TPR", "FPR", "precision", "F1", "delay_med_s", "probes_med"])
        for m in methods:
            for sc in SCEN:
                s = summarise(per[(m, sc)])
                w.writerow([m, sc] + [s[k] for k in ("P", "N", "TP", "FP")] +
                           ["%.3f" % s[k] for k in ("TPR", "FPR", "precision", "F1", "delay_med", "probes_med")])
    overall = {}
    with open(os.path.join(OUT, "overall.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "P", "N", "TP", "FP", "TPR", "FPR", "precision", "F1", "delay_med_s", "probes_med"])
        for m in methods:
            rows = [x for sc in SCEN for x in per[(m, sc)]]
            s = summarise(rows)
            overall[m] = s
            w.writerow([m] + [s[k] for k in ("P", "N", "TP", "FP")] +
                       ["%.3f" % s[k] for k in ("TPR", "FPR", "precision", "F1", "delay_med", "probes_med")])
            print("%-16s TPR %.3f FPR %.3f P %.3f F1 %.3f delay %.1f s probes %.0f"
                  % (m, s["TPR"], s["FPR"], s["precision"], s["F1"], s["delay_med"], s["probes_med"]))

    # ROC (threshold sweep, test seeds)
    roc = {}
    for m, dets in SWEEP.items():
        pts = []
        for det in dets:
            rows = []
            for r in test:
                rows += outcome(r, run_detector(m, det, r))
            s = summarise(rows)
            pts.append((s["FPR"], s["TPR"]))
        roc[m] = sorted(pts)
    rfpts = []
    for thr in (0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        rows = []
        for r in test:
            rows += rf_outcome(r, rf[(r["scenario"], r["seed"])], thr)
        s = summarise(rows)
        rfpts.append((s["FPR"], s["TPR"]))
    roc["Random Forest"] = sorted(rfpts)
    with open(os.path.join(OUT, "roc.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "FPR", "TPR"])
        for m, pts in roc.items():
            for x, y in pts:
                w.writerow([m, "%.4f" % x, "%.4f" % y])

    # ablation (all seeds)
    abl = {}
    for name, mk in ABLATION.items():
        rows = []
        for r in runs:
            rows += outcome(r, mk().run(r["attempts"]))
        abl[name] = summarise(rows)
    with open(os.path.join(OUT, "ablation.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["variant", "TPR", "FPR", "F1", "delay_med_s"])
        for k, s in abl.items():
            w.writerow([k, "%.3f" % s["TPR"], "%.3f" % s["FPR"], "%.3f" % s["F1"], "%.2f" % s["delay_med"]])
            print("ablation %-24s TPR %.3f FPR %.3f F1 %.3f delay %.1f" % (k, s["TPR"], s["FPR"], s["F1"], s["delay_med"]))

    # graded mitigation: time of first containment vs full block, and collateral connections of false alarms
    grad = []
    for r in runs:
        res = AISPRT().run(r["attempts"])
        atk = set(r["attackers"])
        for s in atk:
            ev = [(t, k, sc) for t, h, k, sc in res.events if h == s and r["atk_t"] and t >= r["atk_t"] - 0.5]
            sus = next((t for t, k, sc in ev if k == "SUSPECT"), None)
            blk = next((t for t, k, sc in ev if k in ALARM_KINDS), None)
            grad.append(dict(scenario=r["scenario"], seed=r["seed"], host=s,
                             suspect=(sus - r["atk_t"]) if sus else None, block=(blk - r["atk_t"]) if blk else None))
    with open(os.path.join(OUT, "graded.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario", "seed", "host", "suspect", "block"])
        w.writeheader()
        w.writerows(grad)

    json.dump({"overall": overall, "ablation": abl, "runs": len(runs), "test_runs": len(test),
               "packets": sum(r["packets"] for r in runs), "attempts": sum(len(r["attempts"]) for r in runs)},
              open(os.path.join(OUT, "summary.json"), "w"), indent=1, default=str)
    figures(per, methods, roc, abl, grad)


# ------------------------------------------------------------------------------- figures
COL = {"AIS-SPRT (ours)": "#059669", "TRW": "#7c3aed", "IA-Window": "#d97706", "Naive-Window": "#e11d48",
       "Entropy": "#78716c", "Random Forest": "#0f766e"}


def figures(per, methods, roc, abl, grad):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8.5, "font.family": "DejaVu Sans", "axes.spines.top": False,
                         "axes.spines.right": False, "axes.grid": True, "grid.color": "#e7e5e4", "grid.linewidth": 0.6})
    os.makedirs(FIG, exist_ok=True)
    ls = {"Random Forest": "--", "Entropy": ":"}

    # ROC
    fig, ax = plt.subplots(figsize=(3.5, 2.35))
    for m in methods:
        pts = [(0.0, 0.0)] + roc[m] + [(1.0, 1.0)]
        ax.plot([p[0] for p in pts], [p[1] for p in pts], ls.get(m, "-"), marker="o", ms=3, lw=1.8 if "ours" in m else 1.2,
                color=COL[m], label=m)
    ax.set_xlabel("False-positive rate")
    ax.set_ylabel("True-positive rate")
    ax.set_xlim(-0.01, 0.6)
    ax.set_ylim(0, 1.02)
    ax.legend(fontsize=7, loc="lower right", frameon=False)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "e_roc.pdf"))
    plt.close(fig)

    # detection rate and false alarms per scenario
    atk_sc = [s for s in SCEN if s not in ("benign", "outage")]
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.3), gridspec_kw={"width_ratios": [6, 8]})
    w = 0.8 / len(methods)
    for i, m in enumerate(methods):
        vals = [summarise(per[(m, s)])["TPR"] for s in atk_sc]
        axes[0].bar([j + i * w for j in range(len(atk_sc))], vals, w, color=COL[m], label=m)
    axes[0].set_xticks([j + 0.4 - w / 2 for j in range(len(atk_sc))])
    axes[0].set_xticklabels([SCEN_LABEL[s] for s in atk_sc], rotation=25, ha="right", fontsize=8)
    axes[0].set_ylabel("Detection rate (TPR)")
    axes[0].set_ylim(0, 1.05)
    for i, m in enumerate(methods):
        vals = [summarise(per[(m, s)])["FPR"] for s in SCEN]
        axes[1].bar([j + i * w for j in range(len(SCEN))], vals, w, color=COL[m], label=m)
    axes[1].set_xticks([j + 0.4 - w / 2 for j in range(len(SCEN))])
    axes[1].set_xticklabels([SCEN_LABEL[s] for s in SCEN], rotation=25, ha="right", fontsize=8)
    axes[1].set_ylabel("False-positive rate (FPR)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=6, fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig(os.path.join(FIG, "e_scenarios.pdf"))
    plt.close(fig)

    # detection delay per scenario (probes until alarm)
    fig, ax = plt.subplots(figsize=(3.5, 2.45))
    for m in methods:
        ys = []
        for s in atk_sc:
            v = summarise(per[(m, s)])["delay_med"]
            ys.append(v if v == v else None)
        xs = [i for i, y in enumerate(ys) if y is not None]
        ax.plot(xs, [ys[i] for i in xs], ls.get(m, "-"), marker="o", ms=3.5, color=COL[m], lw=1.8 if "ours" in m else 1.2, label=m)
    ax.set_yscale("log")
    ax.set_xticks(range(len(atk_sc)))
    ax.set_xticklabels([SCEN_LABEL[s] for s in atk_sc], rotation=25, ha="right", fontsize=7.5)
    ax.set_ylabel("Median delay (s, log)")
    h_, l_ = ax.get_legend_handles_labels()
    fig.legend(h_, l_, fontsize=6.8, frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.0), columnspacing=0.8, handlelength=1.6)
    fig.tight_layout(rect=(0, 0, 1, 0.84))
    fig.savefig(os.path.join(FIG, "e_delay.pdf"))
    plt.close(fig)

    # ablation
    names = list(abl)
    fig, ax = plt.subplots(figsize=(3.5, 2.15))
    xs = range(len(names))
    ax.bar([x - 0.2 for x in xs], [abl[n]["TPR"] for n in names], 0.4, color="#059669", label="TPR")
    ax.bar([x + 0.2 for x in xs], [abl[n]["FPR"] for n in names], 0.4, color="#e11d48", label="FPR")
    for x, n in zip(xs, names):
        ax.text(x - 0.2, abl[n]["TPR"] + 0.02, "%.2f" % abl[n]["TPR"], ha="center", fontsize=6.3)
        ax.text(x + 0.2, abl[n]["FPR"] + 0.02, "%.2f" % abl[n]["FPR"], ha="center", fontsize=6.3)
    ax.set_xticks(list(xs))
    ax.set_xticklabels([n.replace("AIS-SPRT (full)", "full AIS-SPRT").replace("w/o evidence decay", "w/o decay").replace("w/o novelty weight", "w/o novelty") for n in names], rotation=25, ha="right", fontsize=7.5)
    ax.set_ylim(0, 1.18)
    ax.legend(fontsize=7.5, frameon=False, ncol=2, loc="upper right", bbox_to_anchor=(1, 1.12))
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "e_ablation.pdf"))
    plt.close(fig)

    # graded mitigation: suspect vs block time
    gs = [g for g in grad if g["block"] is not None]
    if gs:
        fig, ax = plt.subplots(figsize=(3.5, 2.15))
        order = [s for s in atk_sc if any(g["scenario"] == s for g in gs)]
        for i, s in enumerate(order):
            sus = [g["suspect"] for g in gs if g["scenario"] == s and g["suspect"] is not None]
            blk = [g["block"] for g in gs if g["scenario"] == s]
            if sus:
                ax.scatter([i - 0.12] * len(sus), sus, color="#d97706", s=14, label="per-destination block" if i == 0 else None)
            ax.scatter([i + 0.12] * len(blk), blk, color="#059669", s=14, marker="s", label="host block" if i == 0 else None)
        ax.set_yscale("log")
        ax.set_xticks(range(len(order)))
        ax.set_xticklabels([SCEN_LABEL[s] for s in order], rotation=25, ha="right", fontsize=7.5)
        ax.set_ylabel("Time after start (s, log)")
        ax.legend(fontsize=7.5, frameon=False, loc="upper right")
        fig.tight_layout()
        fig.savefig(os.path.join(FIG, "e_graded.pdf"))
        plt.close(fig)


if __name__ == "__main__":
    main()
