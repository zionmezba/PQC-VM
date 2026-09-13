# PQC-VM — hybrid classical + post-quantum digital signatures

Experimental code for a study of hybrid signatures pairing ECDSA P-256 with
ML-DSA-65, Falcon-512 and SPHINCS+-SHA2-128s-simple, embedded in RFC 5652
CMS `SignedData`.

The measurement layer here replaces an earlier shell-driven harness whose
results were not usable. What was wrong with it, and why, is recorded in
[`scripts/legacy/README.md`](scripts/legacy/README.md); those scripts are kept
for provenance and must not be run to produce results.

## Running it

Everything runs in a pinned container, so a reviewer gets the same liboqs and
oqs-provider builds the authors did.

```bash
make image      # build (liboqs + oqs-provider from source; takes a while)
make test       # correctness tests for the hybrid construction
make quick      # smoke run with small n — checks wiring, NOT a result
make run        # full experiment set + figures -> results/
```

`make run` writes:

| file | contents |
|---|---|
| `results/primitives.json` / `.csv` | keygen / sign / verify latency, in process |
| `results/cli_overhead.json` | process-launch cost, measured deliberately |
| `results/separability.json` | hybrid artifacts, verdict matrix, byte accounting |
| `results/summary.csv` | every figure's underlying table |
| `results/figures/*.png` | the four exploratory figures |
| `results/figures/*.pdf` | the manuscript figures, vector |

## How the measurements are taken

**In process, with nothing forked inside the timed region.**
[`bench/timing.py`](bench/timing.py) uses `time.perf_counter_ns`, warms up
before the first recorded sample, disables the garbage collector across the
measurement, and reports n, median, IQR, p95, p99, min and max for every cell.
The mean is recorded but is not the headline statistic: these distributions are
right-skewed by scheduler preemption.

Hashing is measured separately from signing. Three families appear in the
output and are never mixed:

- `hash` — SHA-256 over the payload; scales with document size.
- `sign_digest` / `verify_digest` — the signature operation over the 32-byte
  digest alone; constant in document size by construction.
- `sign_e2e` / `verify_e2e` — hash and signature inside one timed region,
  measured directly rather than summed, so it carries its own dispersion.

Slow cells are bounded by a wall-clock budget rather than being allowed to run
for hours. When the budget bites, `n` drops and the `truncated` column says so.
SPHINCS+-128s signing is where this matters.

**Sizes are labelled by what they count.** Raw signature bytes, DER certificate
bytes, and full CMS container bytes are separate columns and separate figure
series. Key sizes are raw key bytes, not PEM file sizes on disk.

## Figures for the manuscript

`results/figures/` carries two sets and they are not substitutes for one
another. [`bench/figures.py`](bench/figures.py) renders the exploratory PNGs
used to read the data. [`bench/paper_figures.py`](bench/paper_figures.py) and
[`bench/paper_methodology.py`](bench/paper_methodology.py) render the vector
PDFs that go into the paper: 8pt serif against IEEEtran's 10pt Times, no
titles (IEEE uses captions), TrueType-embedded, and legible in greyscale,
because print review copies are not colour.

`fig_method.pdf` is the methodology figure — double column, two panels. Panel
(a) is the artifact: what the ECDSA signature covers, what it does not, and
the single value that differs between the three modes. Panel (b) is the
evaluation design: five artifact states through five verifiers, with the cells
each claim rests on boxed and the control row shaded. It carries no verdicts;
those belong to the tables generated from `separability.json` and
`substitution.json`, and duplicating them in a figure only invites the two to
disagree. It is drawn from the design, not from a results file, so it is
regenerated on every run to keep it from drifting from the code it depicts:

```bash
python -m bench.paper_methodology --out results/figures
```

## The CLI-overhead result

[`bench/cli_overhead.py`](bench/cli_overhead.py) times `sh -c true`,
`python3 -c pass`, `openssl version` without the OQS provider, and
`openssl version` with it, then reports the inflation factor against the
in-process verification figures. This is a finding, not a caveat: shell-driven
benchmarking of PQC signature verification measures process startup, and the
factor by which it inflates the result is in `results/cli_overhead.json`.

## Hybrid CMS and the separability question

[`bench/hybrid_cms.py`](bench/hybrid_cms.py) builds a real detached
`SignedData`: one `SignerInfo` with the classical ECDSA signature in the
standard slot, and the PQC signature carried as an **unsigned attribute** under
an experimental OID arc (`1.3.6.1.4.1.59999.1`, unregistered — see
[`bench/asn1_defs.py`](bench/asn1_defs.py) for why an unsigned attribute rather
than a second `SignerInfo`).

Three modes are implemented:

| mode | classical `messageDigest` | PQC signs | binding attribute |
|---|---|---|---|
| `concat` | `H(M)` | `H(M)` | — |
| `bound-attr` | `H(M)` | `B` | present, signed |
| `bound-digest` | `B` | `B` | present, signed |

where `B = H(ctx ‖ mode ‖ pk_classical ‖ pk_pqc ‖ H(M))`, each field
length-prefixed.

[`bench/attack.py`](bench/attack.py) runs every mode past four verifiers — our
hybrid verifier, our verifier restricted to what RFC 5652 mandates, the
`openssl` CLI **with no OQS provider loaded**, and the CLI with it — on both
the intact artifact and one with the PQC attribute deleted. The intact/legacy
cell is RQ1; the stripped/legacy cell is the attack.

The tests in [`tests/test_hybrid.py`](tests/test_hybrid.py) assert the
uncomfortable direction as well as the comfortable one. In particular
`bound-attr` is expected to remain acceptable to a conforming legacy verifier
even after stripping: CMS has no criticality flag for signed attributes, so a
verifier that does not recognise the binding attribute ignores it. The binding
is real, but it is policy-enforced rather than self-enforcing. `bound-digest`
closes that gap and loses legacy acceptance on the intact artifact in exchange.
Whether any mode achieves both is answered by `results/separability.json`, not
asserted here.

## Reporting rules this repository is held to

- No number is reported that the code did not measure.
- No CMS envelope is compared against a raw signature without both being named.
- Every latency carries n, a median, and a dispersion measure.
- Algorithm identifiers are resolved against
  `oqs.get_enabled_sig_mechanisms()` at run time; an unavailable mechanism is a
  hard error, never a silent substitution.
- Falcon's OID is an Open Quantum Safe private-arc value and is **not**
  registered; ML-DSA and SLH-DSA use their NIST assignments. Any table listing
  them says which is which.
