"""Task 5: figures, from results/*.json only.

Nothing is computed here that is not present in the measurement output, and no
figure mixes a container size with a raw signature size without saying so in
the axis label. Every latency figure carries n and an IQR error bar.

A machine-readable table accompanies every figure (results/summary.csv), which
is also the accessibility fallback: two of the four categorical colors sit below
3:1 against the chart surface, so the figures carry direct value labels and the
table is the non-color reading of the same data.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

# Categorical slots 1-4, assigned in fixed order and never cycled. Validated
# for CVD separation and lightness band against the #fcfcfb chart surface.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK = "#0b0b0b"
INK_MUTED = "#52514e"
SURFACE = "#fcfcfb"
GRID = "#e3e2df"

ALG_ORDER = ["ECDSA-P256", "ML-DSA-65", "Falcon-512",
             "SPHINCS+-SHA2-128s-simple"]
ALG_COLOR = dict(zip(ALG_ORDER, SERIES))

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK,
    "axes.titlesize": 11,
    "axes.titleweight": "bold",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "text.color": INK,
    "xtick.color": INK_MUTED,
    "ytick.color": INK_MUTED,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "font.size": 9,
    "legend.frameon": False,
    "figure.dpi": 200,
    "savefig.bbox": "tight",
})


def _bytes_fmt(v, _pos=None):
    if v >= 1024:
        return "%.0fK" % (v / 1024)
    return "%.0f" % v


def _save(fig, out: Path, name: str):
    p = out / name
    fig.savefig(p)
    plt.close(fig)
    print("  %s" % p)
    return p


# --------------------------------------------------------------------------

def fig_signature_size(prim: dict, out: Path):
    """Raw signature bytes vs the detached CMS container carrying them.

    Kept as two explicitly-labelled groups because conflating them is exactly
    the error this figure replaces.
    """
    rows = [r for r in prim["rows"] if r["kind"] == "size"]
    algs = [a for a in ALG_ORDER if any(r["algorithm"] == a for r in rows)]
    vals = [next(r["signature_bytes"] for r in rows if r["algorithm"] == a)
            for a in algs]

    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    bars = ax.bar(range(len(algs)), vals,
                  color=[ALG_COLOR[a] for a in algs], width=0.62,
                  edgecolor=SURFACE, linewidth=1.2)
    for b, v in zip(bars, vals):
        ax.annotate("%d B" % v, (b.get_x() + b.get_width() / 2, v),
                    ha="center", va="bottom", fontsize=8.5, color=INK,
                    xytext=(0, 3), textcoords="offset points")
    ax.set_yscale("log")
    ax.set_ylabel("raw signature (bytes, log scale)")
    ax.set_xticks(range(len(algs)))
    ax.set_xticklabels([a.replace("-SHA2-128s-simple", "\n-SHA2-128s")
                        for a in algs], fontsize=8)
    ax.set_title("Raw signature size (no container)")
    ax.yaxis.grid(True); ax.set_axisbelow(True)
    ax.yaxis.set_major_formatter(FuncFormatter(_bytes_fmt))
    return _save(fig, out, "fig1_signature_size.png")


def fig_hybrid_composition(sep: dict, out: Path):
    """Where the bytes of a hybrid artifact go.

    Stacked horizontal bars, one per algorithm, for the `bound-attr` mode.
    2px surface-coloured gaps separate segments.
    """
    cases = [c for c in sep["cases"] if c["mode"] == "bound-attr"]
    labels = [c["algorithm"] for c in cases]
    parts = [
        ("classical CMS (incl. EC cert)", "classical_only_cms_bytes"),
        ("PQC signature", "pqc_signature_raw_bytes"),
        ("PQC public key", "pqc_public_key_raw_bytes"),
        ("PQC certificate", "pqc_certificate_der_bytes"),
    ]
    fig, ax = plt.subplots(figsize=(6.4, 2.8))
    left = [0.0] * len(cases)
    for i, (name, key) in enumerate(parts):
        vals = [c["sizes"][key] for c in cases]
        ax.barh(range(len(cases)), vals, left=left, height=0.55,
                color=SERIES[i], label=name,
                edgecolor=SURFACE, linewidth=1.4)
        left = [l + v for l, v in zip(left, vals)]
    for i, c in enumerate(cases):
        ax.annotate("%d B total" % c["sizes"]["hybrid_cms_bytes"],
                    (left[i], i), va="center", ha="left", fontsize=8.5,
                    color=INK, xytext=(4, 0), textcoords="offset points")
    ax.set_yticks(range(len(cases)))
    ax.set_yticklabels([l.replace("-SHA2-128s-simple", "-128s")
                        for l in labels], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("bytes in the detached CMS SignedData (bound-attr mode)")
    ax.set_title("Size composition of the hybrid artifact")
    ax.xaxis.grid(True); ax.set_axisbelow(True)
    ax.xaxis.set_major_formatter(FuncFormatter(_bytes_fmt))
    # Legend below the axes: in-axes placement collides with the SPHINCS+ bar,
    # which is wide enough to reach any interior corner.
    ax.legend(fontsize=8, ncol=4, loc="upper center",
              bbox_to_anchor=(0.5, -0.28))
    ax.margins(x=0.20)
    return _save(fig, out, "fig2_hybrid_composition.png")


def fig_latency(prim: dict, out: Path):
    """Median latency by operation, IQR error bars, log scale."""
    ops = ["keygen", "sign_digest", "verify_digest"]
    op_labels = {"keygen": "keygen", "sign_digest": "sign",
                 "verify_digest": "verify"}
    rows = {(r["algorithm"], r["operation"]): r
            for r in prim["rows"] if r["kind"] == "latency"}
    algs = [a for a in ALG_ORDER if (a, "keygen") in rows]

    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    width = 0.8 / len(algs)
    for i, a in enumerate(algs):
        xs = [j + i * width - 0.4 + width / 2 for j in range(len(ops))]
        med = [rows[(a, o)]["median_us"] for o in ops]
        # One-sided IQR whisker. These distributions are right-skewed by
        # scheduler preemption, so a symmetric bar would imply a lower tail
        # that does not exist and would run below the log axis floor.
        iqr = [rows[(a, o)]["iqr_us"] for o in ops]
        ax.bar(xs, med, width=width * 0.9, color=ALG_COLOR[a], label=a,
               edgecolor=SURFACE, linewidth=1.0,
               yerr=[[0] * len(ops), iqr], capsize=2.5,
               error_kw={"ecolor": INK_MUTED, "elinewidth": 1.0})
    ns = sorted({rows[(a, o)]["n"] for a in algs for o in ops})
    ax.set_yscale("log")
    ax.set_ylabel("median latency (us, log scale)")
    ax.set_xticks(range(len(ops)))
    ax.set_xticklabels([op_labels[o] for o in ops])
    ax.set_title("Operation latency, in process (error bars: IQR; "
                 "n = %s)" % (ns[0] if len(ns) == 1 else "%d-%d"
                              % (ns[0], ns[-1])))
    ax.yaxis.grid(True); ax.set_axisbelow(True)
    # SPHINCS+ signing reaches ~1e5 us, so an in-axes legend overlaps it.
    ax.legend(fontsize=8, ncol=4, loc="upper center",
              bbox_to_anchor=(0.5, -0.10))
    return _save(fig, out, "fig3_latency.png")


def fig_overhead_pct(prim: dict, sep: dict, out: Path):
    """Signature overhead as a percentage of document size.

    The artifact size is constant in document size (detached signature over a
    hash), so these are hyperbolas; the log-log view is what makes the
    crossover points readable.
    """
    cases = [c for c in sep["cases"] if c["mode"] == "bound-attr"]
    sizes = sorted(prim["payload_sizes_bytes"].values())
    labels_by_size = {v: k for k, v in prim["payload_sizes_bytes"].items()}

    fig, ax = plt.subplots(figsize=(5.8, 3.2))
    for c in cases:
        art = c["sizes"]["hybrid_cms_bytes"]
        ys = [100.0 * art / s for s in sizes]
        ax.plot(sizes, ys, marker="o", markersize=5, linewidth=2,
                color=ALG_COLOR[c["algorithm"]], label=c["algorithm"])
        ax.annotate("%.2f%%" % ys[-1], (sizes[-1], ys[-1]),
                    xytext=(5, 0), textcoords="offset points",
                    fontsize=8, color=INK, va="center")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("document size (bytes, log scale)")
    ax.set_ylabel("hybrid signature as % of document")
    ax.set_xticks(sizes)
    ax.set_xticklabels([labels_by_size[s] for s in sizes])
    ax.set_title("Storage overhead of the hybrid artifact")
    ax.grid(True); ax.set_axisbelow(True)
    ax.legend(fontsize=8)
    ax.margins(x=0.12)
    return _save(fig, out, "fig4_overhead_pct.png")


# --------------------------------------------------------------------------

def write_summary(prim: dict, sep: dict, out: Path):
    rows = []
    for r in prim["rows"]:
        if r["kind"] == "latency":
            rows.append({
                "table": "latency", "algorithm": r["algorithm"],
                "operation": r["operation"], "payload": r["payload"],
                "n": r["n"], "median_us": round(r["median_us"], 3),
                "iqr_us": round(r["iqr_us"], 3),
                "p95_us": round(r["p95_us"], 3),
                "min_us": round(r["min_us"], 3),
                "truncated": r["truncated"],
            })
        else:
            rows.append({
                "table": "size", "algorithm": r["algorithm"],
                "operation": "raw_signature_bytes",
                "value": r["signature_bytes"],
            })
    for c in sep["cases"]:
        for k, v in c["sizes"].items():
            rows.append({"table": "hybrid_size", "algorithm": c["algorithm"],
                         "operation": "%s/%s" % (c["mode"], k), "value": v})
        for artifact in ("intact", "stripped"):
            for verifier in ("hybrid_policy", "classical_policy",
                             "openssl_legacy", "openssl_oqs"):
                rows.append({
                    "table": "verdict", "algorithm": c["algorithm"],
                    "operation": "%s/%s/%s" % (c["mode"], artifact, verifier),
                    "value": c[artifact][verifier]["accepted"],
                })
    fields = sorted({k for r in rows for k in r})
    p = out / "summary.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print("  %s" % p)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="render figures from results/")
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="results/figures")
    args = ap.parse_args(argv)

    res = Path(args.results)
    prim = json.loads((res / "primitives.json").read_text())
    sep = json.loads((res / "separability.json").read_text())

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print("figures:")
    fig_signature_size(prim, out)
    fig_hybrid_composition(sep, out)
    fig_latency(prim, out)
    fig_overhead_pct(prim, sep, out)
    write_summary(prim, sep, res)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
