"""Publication figures for the paper, generated from results/.

Two figures only. Anything that merely restates a table is omitted: the
primitive latency and size numbers are in Table I and do not need a bar chart,
and the verification matrices are categorical and belong in Tables II and V.

  fig_scaling      end-to-end verification against payload size, with SHA-256
                   alone as the reference line. Makes the hashing-dominance
                   result visible: the curves converge onto the hash line above
                   ~1 MB. Single column.

  fig_size         (a) where the bytes go in a hybrid artifact, and (b) that
                   overhead as a fraction of the document. Panel (a) shows the
                   PQC certificate outweighing the PQC signature; panel (b)
                   shows the whole overhead becoming negligible at document
                   scale. Together they carry the affordability argument.
                   Double column.

Output is PDF (vector) rather than PNG: LaTeX embeds it without resampling and
IEEE prefers it. Styling is deliberately plain -- no titles, since IEEE uses
captions -- and every series is distinguishable in greyscale, because print
review copies are not colour.

    python -m bench.paper_figures --results results --out results/figures
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# IEEEtran is Times at 10pt; 8pt serif in the figure sits right next to it.
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.4,
    "axes.axisbelow": True,
    "figure.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})

COL_W = 3.45      # IEEE single column, inches
COL2_W = 7.16     # IEEE double column, inches

PAYLOADS = [("10KB", 10 * 1024), ("100KB", 100 * 1024),
            ("1MB", 1024 ** 2), ("10MB", 10 * 1024 ** 2)]

# Greyscale-safe: distinct marker AND distinct dash pattern per series.
SERIES = [
    ("ECDSA-P256",                "o", "-",  "#1f4e79"),
    ("ML-DSA-65",                 "s", "--", "#c0504d"),
    ("Falcon-512",                "^", "-.", "#2e7d32"),
    ("SPHINCS+-SHA2-128s-simple", "D", ":",  "#e08214"),
]
LABEL = {"SPHINCS+-SHA2-128s-simple": "SLH-DSA-128s"}


def _bytes_fmt(v, _pos):
    for unit, div in (("MB", 1024 ** 2), ("KB", 1024)):
        if v >= div:
            return f"{v/div:g}{unit}"
    return f"{v:g}B"


def load_primitives(results: Path) -> tuple[list[dict], dict]:
    """Return the measurement rows and the *actual* payload byte counts.

    The harness records what it really generated under payload_sizes_bytes.
    Using those rather than the nominal 10 KB / 1 MB labels matters: an earlier
    version of gen_payloads.sh base64-encoded its output, so the file behind the
    "10KB" label was 13,836 bytes. Reading the recorded sizes means a figure
    cannot silently inherit that class of error.
    """
    doc = json.loads((results / "primitives.json").read_text())
    return doc["rows"], doc["payload_sizes_bytes"]


def median_of(rows, algorithm, operation, payload=""):
    for r in rows:
        if (r.get("algorithm") == algorithm
                and r.get("operation") == operation
                and (r.get("payload") or "") == (payload or "")
                and r.get("kind") == "latency"):
            return r["median_us"]
    return None


# --------------------------------------------------------------------------

def fig_scaling(rows, sizes: dict, out: Path) -> Path:
    fig, ax = plt.subplots(figsize=(COL_W, 2.5))
    labels = [lbl for lbl, _ in PAYLOADS if lbl in sizes]
    xs = [sizes[lbl] for lbl in labels]

    hash_ys = [median_of(rows, "SHA-256", "hash", lbl) for lbl in labels]
    ax.plot(xs, hash_ys, color="0.45", linestyle=(0, (1, 1)), linewidth=1.6,
            marker="x", markersize=4, label="SHA-256 only", zorder=1)

    for alg, marker, dash, colour in SERIES:
        ys = [median_of(rows, alg, "verify_e2e", lbl) for lbl in labels]
        if any(y is None for y in ys):
            continue
        ax.plot(xs, ys, marker=marker, linestyle=dash, color=colour,
                linewidth=1.0, markersize=3.4,
                label=LABEL.get(alg, alg), zorder=2)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("document size")
    ax.set_ylabel(r"end-to-end verification ($\mu$s)")
    ax.xaxis.set_major_formatter(FuncFormatter(_bytes_fmt))
    ax.set_xticks(xs)
    ax.legend(loc="upper left", frameon=False, handlelength=2.6,
              labelspacing=0.25, borderpad=0.2)

    path = out / "fig_scaling.pdf"
    fig.savefig(path)
    plt.close(fig)
    return path


def fig_size(sep_doc: dict, sizes: dict, out: Path) -> Path:
    # Table IV in the paper reports concat; keep the figure on the same mode.
    cases = {c["algorithm"]: c["sizes"]
             for c in sep_doc["cases"] if c["mode"] == "concat"}
    order = ["Falcon-512", "ML-DSA-65", "SPHINCS+-SHA2-128s-simple"]
    order = [a for a in order if a in cases]
    names = [LABEL.get(a, a) for a in order]

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(COL2_W, 2.15),
        gridspec_kw={"width_ratios": [1.35, 1.0], "wspace": 0.28})

    # ---- (a) where the bytes go -------------------------------------------
    components = [
        ("classical artifact", "classical_only_cms_bytes", "#1f4e79", None),
        ("PQC signature",      "pqc_signature_raw_bytes",  "#c0504d", None),
        ("PQC public key",     "pqc_public_key_raw_bytes", "#2e7d32", "///"),
        ("PQC certificate",    "pqc_certificate_der_bytes", "#e08214", "..."),
    ]
    left = [0.0] * len(order)
    ypos = range(len(order))
    for label, key, colour, hatch in components:
        vals = [cases[a][key] for a in order]
        ax1.barh(ypos, vals, left=left, height=0.55, color=colour,
                 edgecolor="white", linewidth=0.5, hatch=hatch, label=label)
        left = [l + v for l, v in zip(left, vals)]

    for y, a in enumerate(order):
        total = cases[a]["hybrid_cms_bytes"]
        ax1.text(left[y] + 350, y, f"{total:,} B", va="center", fontsize=6.5)

    ax1.set_yticks(list(ypos))
    ax1.set_yticklabels(names)
    ax1.set_xlabel("bytes in the detached CMS artifact")
    ax1.set_xlim(0, max(left) * 1.22)
    ax1.grid(axis="y", visible=False)
    ax1.legend(loc="lower right", frameon=False, ncol=1,
               labelspacing=0.2, borderpad=0.2, handlelength=1.4)
    ax1.text(-0.16, 1.02, "(a)", transform=ax1.transAxes, fontweight="bold")

    # ---- (b) overhead as a fraction of the document -----------------------
    doc_sizes = [sizes[lbl] for lbl, _ in PAYLOADS if lbl in sizes]
    style = {name: (m, d, c) for name, m, d, c in SERIES}
    for a in order:
        marker, dash, colour = style[a]
        oh = cases[a]["pqc_attribute_overhead_bytes"]
        ax2.plot(doc_sizes, [100.0 * oh / d for d in doc_sizes],
                 marker=marker, linestyle=dash, color=colour,
                 linewidth=1.0, markersize=3.4, label=LABEL.get(a, a))

    ax2.axhline(1.0, color="0.45", linestyle=(0, (1, 1)), linewidth=0.9)
    ax2.text(1.1 * doc_sizes[0], 1.15, "1%", fontsize=6.5, color="0.35")
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel("document size")
    ax2.set_ylabel("PQC overhead (% of document)")
    ax2.xaxis.set_major_formatter(FuncFormatter(_bytes_fmt))
    ax2.set_xticks(doc_sizes)
    ax2.legend(loc="upper right", frameon=False, labelspacing=0.2,
               borderpad=0.2, handlelength=2.2)
    ax2.text(-0.22, 1.02, "(b)", transform=ax2.transAxes, fontweight="bold")

    path = out / "fig_size.pdf"
    fig.savefig(path)
    plt.close(fig)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="results/figures")
    args = ap.parse_args(argv)

    results = Path(args.results)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    rows, sizes = load_primitives(results)
    sep = json.loads((results / "separability.json").read_text())

    for p in (fig_scaling(rows, sizes, out), fig_size(sep, sizes, out)):
        print("wrote %s" % p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
