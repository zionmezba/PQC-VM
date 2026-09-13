"""Methodology figure for the paper.

One figure, double column, rendered as vector PDF for direct \\includegraphics:

  fig_method       (a) the hybrid artifact: what the classical signature covers,
                       what it does not, and the single value that differs
                       between the three modes.
                   (b) the evaluation design: five artifact states put through
                       five verifiers, with the cells each research question
                       actually rests on marked.

This figure describes the experimental design, not its outcome. No cell is
filled with a verdict: the verdicts live in Tables II and V, generated from
results/separability.json and results/substitution.json. Drawing them here
would duplicate a table and invite the two to disagree.

Styling follows bench/paper_figures.py -- 8pt serif against IEEEtran's 10pt
Times, no title (IEEE uses captions), and no reliance on colour, since print
review copies are greyscale. Structure is carried by line style and fill:
solid outline = covered by the classical signature, dashed = not covered.

    python -m bench.paper_methodology --out results/figures

Suggested caption:

  Fig. N. Methodology. (a) The hybrid CMS SignedData. The ECDSA signature
  covers signedAttrs only; the PQC key, certificate, mode label and signature
  ride in an unsignedAttrs field that no signature covers, which is what makes
  stripping and substitution possible. The modes differ solely in X and Y.
  (b) Evaluation design: each of the three PQC algorithms x three modes is
  built once and put through five verifiers in five artifact states. Boxed
  cells carry the claims; the tampered-document row is a control that every
  verifier must reject before any other row is read.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "figure.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
    "pdf.fonttype": 42,   # embed TrueType; avoids Type 3 rejection at IEEE
    "ps.fonttype": 42,
})

COL2_W = 7.16     # IEEE double column, inches

LW = 0.8          # box outline
LW_THIN = 0.5     # rules inside the matrix
FS_BOX = 6.6      # text inside boxes
FS_SMALL = 6.0    # annotations
FS_HEAD = 7.0     # panel headings and matrix labels

SHADE = "0.92"    # grey fill for the control row, greyscale-safe


def box(ax, x, y, w, h, *, dashed=False, lw=LW, fill=None):
    ax.add_patch(Rectangle(
        (x, y), w, h,
        facecolor="none" if fill is None else fill,
        edgecolor="black", linewidth=lw,
        linestyle=(0, (2.4, 1.6)) if dashed else "solid",
        zorder=2))


def arrow(ax, x1, y1, x2, y2, *, lw=LW):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=5,
        linewidth=lw, color="black", shrinkA=0, shrinkB=0, zorder=3))


def txt(ax, x, y, s, *, size=FS_BOX, ha="left", va="center", style=None,
        weight=None, family=None):
    ax.text(x, y, s, fontsize=size, ha=ha, va=va, style=style, weight=weight,
            family=family, zorder=4)


def panel_artifact(ax) -> None:
    """(a) the artifact, and the one value that varies between modes."""
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    txt(ax, 0, 97, "(a) hybrid artifact", size=FS_HEAD, weight="bold")

    # --- the container ----------------------------------------------------
    box(ax, 1, 43.5, 98, 46.5, lw=LW)
    txt(ax, 4, 86, "CMS SignedData, detached, one SignerInfo", size=FS_SMALL,
        style="italic")

    # signedAttrs: what ECDSA actually signs
    box(ax, 4, 57, 41, 25)
    txt(ax, 6.5, 78.5, "signedAttrs", size=FS_BOX, weight="bold")
    txt(ax, 6.5, 73.5, "contentType", size=FS_SMALL)
    txt(ax, 6.5, 69, "messageDigest = X", size=FS_SMALL)
    txt(ax, 6.5, 64.5, "bindingAttr = B", size=FS_SMALL)
    txt(ax, 6.5, 61, "(bound modes only)", size=FS_SMALL, style="italic")

    arrow(ax, 24.5, 57, 24.5, 54.5)
    txt(ax, 26, 55.8, "DER", size=FS_SMALL)

    box(ax, 4, 47.5, 41, 7)
    txt(ax, 24.5, 51, "ECDSA P-256 signature", size=FS_SMALL,
        ha="center")

    # unsignedAttrs: what nothing signs
    box(ax, 50, 44.5, 47, 36.5, dashed=True)
    txt(ax, 52.5, 77.5, "unsignedAttrs", size=FS_BOX, weight="bold")
    txt(ax, 52.5, 73.5, "OID 1.3.6.1.4.1.59999.1", size=FS_SMALL,
        style="italic")
    txt(ax, 52.5, 70, "(unregistered)", size=FS_SMALL, style="italic")
    txt(ax, 52.5, 65.5, "pk$_{pqc}$, PQC certificate", size=FS_SMALL)
    txt(ax, 52.5, 61.5, "mode label", size=FS_SMALL)
    txt(ax, 52.5, 57.5, "PQC signature over Y", size=FS_SMALL)
    txt(ax, 52.5, 53, "no signature covers this:", size=FS_SMALL)
    txt(ax, 52.5, 49.8, "deletable, replaceable,", size=FS_SMALL)
    txt(ax, 52.5, 46.8, "rewritable", size=FS_SMALL)

    # --- the experimental variable ---------------------------------------
    txt(ax, 1, 39.5, "the modes differ only here", size=FS_SMALL,
        style="italic")

    ax.plot([1, 92], [36, 36], color="black", lw=LW_THIN, zorder=2)
    ax.plot([1, 92], [30.5, 30.5], color="black", lw=LW_THIN, zorder=2)
    ax.plot([1, 92], [13.5, 13.5], color="black", lw=LW_THIN, zorder=2)

    txt(ax, 1, 33.5, "mode", size=FS_SMALL, style="italic")
    txt(ax, 38, 33.5, "X: classical digest", size=FS_SMALL,
        style="italic")
    txt(ax, 74, 33.5, "Y: PQC signs", size=FS_SMALL, style="italic")

    table = (
        (28.0, "concat",       "H(M)", "H(M)"),
        (22.5, "bound-attr",   "H(M)", "B"),
        (17.0, "bound-digest", "B",    "B"),
    )
    for y, mode, x_val, y_val in table:
        txt(ax, 1, y, mode, size=FS_BOX, family="monospace")
        txt(ax, 38, y, x_val, size=FS_BOX)
        txt(ax, 74, y, y_val, size=FS_BOX)

    txt(ax, 1, 8.5,
        "B = H( ctx $\\|$ mode $\\|$ pk$_{classical}$ $\\|$ pk$_{pqc}$ "
        "$\\|$ H(M) ),", size=FS_SMALL)
    txt(ax, 1, 4.5, "each field length-prefixed", size=FS_SMALL)


def panel_matrix(ax) -> None:
    """(b) artifact states x verifiers, with the load-bearing cells marked."""
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    txt(ax, 0, 97, "(b) evaluation design", size=FS_HEAD, weight="bold")
    txt(ax, 0, 92,
        "3 PQC algorithms $\\times$ 3 modes, every cell recorded",
        size=FS_SMALL, style="italic")

    x_lab = 0
    x0 = 34
    cw = 16.5
    centres = [x0 + cw * (i + 0.5) for i in range(4)]

    verifiers = ("hybrid", "hardened", "classical", "openssl")
    for cx, name in zip(centres, verifiers):
        txt(ax, cx, 76.5, name, size=FS_BOX, ha="center")

    # the last column is a verifier we did not write
    ax.plot([centres[3] - cw / 2 + 1.5, centres[3] + cw / 2 - 1.5],
            [83, 83], color="black", lw=LW_THIN, zorder=2)
    txt(ax, 100, 87, "unmodified third party", size=FS_SMALL,
        ha="right", style="italic")

    rows = (
        ("intact",             "$\\bullet$", "--", "$\\bullet$", "RQ1"),
        ("PQC attr. deleted",  "$\\bullet$", "--", "$\\bullet$", "attack"),
        ("PQC half replaced",  "separates", "$\\bullet$", "$\\bullet$",
         "$\\bullet$"),
        ("mode rewritten", "downgrade", "remedy", "$\\bullet$",
         "$\\bullet$"),
        ("document altered",   "reject", "reject", "reject", "reject"),
    )
    boxed = {(0, 3), (1, 3), (2, 0), (3, 0), (3, 1)}

    top = 70
    rh = 11
    ax.plot([x_lab, 100], [top, top], color="black", lw=LW, zorder=2)
    for i, (label, *cells) in enumerate(rows):
        y_top = top - i * rh
        y_mid = y_top - rh / 2
        if i == len(rows) - 1:
            ax.add_patch(Rectangle((x_lab, y_top - rh), 100 - x_lab, rh,
                                   facecolor=SHADE, edgecolor="none",
                                   zorder=0))
        txt(ax, x_lab, y_mid, label, size=FS_SMALL)
        for j, cell in enumerate(cells):
            cx = centres[j]
            if (i, j) in boxed:
                box(ax, cx - 7.9, y_mid - 3.2, 15.8, 6.4, lw=LW)
            txt(ax, cx, y_mid, cell,
                size=FS_BOX if cell.startswith("$") else 5.2,
                ha="center")
        ax.plot([x_lab, 100], [y_top - rh, y_top - rh], color="black",
                lw=LW_THIN if i < len(rows) - 1 else LW, zorder=2)

    for k in range(5):
        x = x0 + cw * k
        ax.plot([x, x], [top, top - rh * len(rows)], color="black",
                lw=LW_THIN, zorder=2)

    txt(ax, 0, 12,
        "hybrid: our verifier, full rules.  hardened: + mode-consistency "
        "check.", size=FS_SMALL)
    txt(ax, 0, 8.5,
        "classical: RFC 5652 only.  openssl: CLI with no OQS provider loaded.",
        size=FS_SMALL)
    txt(ax, 0, 4.5,
        "$\\bullet$ recorded;  boxed: the cell a claim rests on;  "
        "-- not applicable.  Shaded row is a", size=FS_SMALL)
    txt(ax, 0, 1,
        "control: if any verifier accepts it, the run aborts and no row is "
        "reported.", size=FS_SMALL)


def fig_method(out: Path) -> Path:
    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(COL2_W, 3.0),
                                     gridspec_kw={"width_ratios": [1, 1.05],
                                                  "wspace": 0.14})
    panel_artifact(ax_a)
    panel_matrix(ax_b)
    path = out / "fig_method.pdf"
    fig.savefig(path)
    fig.savefig(path.with_suffix(".png"))   # for slides and quick review
    plt.close(fig)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="render the methodology figure")
    ap.add_argument("--out", default="results/figures")
    args = ap.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = fig_method(out)
    print("wrote %s" % path)
    print("wrote %s" % path.with_suffix(".png"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
