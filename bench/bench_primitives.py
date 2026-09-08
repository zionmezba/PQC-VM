"""Task 1: keygen / sign / verify latency, measured in process.

Three families of measurement are reported separately, because collapsing them
is what produced the original misleading numbers:

  hash          SHA-256 over the payload. Scales with document size.
  *_digest      Signature operation over the 32-byte digest alone. Constant in
                document size by construction -- that is the point of measuring
                it apart from the hash.
  *_e2e         Hash *and* signature operation inside one timed region. This is
                the number an application sees. It is measured directly rather
                than added up from the two rows above, so it carries its own
                dispersion instead of an assumed-independent sum.

Payloads are generated in memory from a fixed-seed PRNG. Nothing is read from
disk inside a timed region, so page cache state cannot leak into a result.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import algs, envinfo
from .timing import measure

DEFAULT_SIZES = {
    "10KB": 10 * 1024,
    "100KB": 100 * 1024,
    "1MB": 1024 * 1024,
    "10MB": 10 * 1024 * 1024,
}


def make_payload(nbytes: int, seed: int = 0xC0FFEE) -> bytes:
    rng = random.Random(seed)
    return rng.randbytes(nbytes)


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# --------------------------------------------------------------------------
# ECDSA P-256 (classical baseline)
# --------------------------------------------------------------------------

def bench_ecdsa(payloads, n, warmup, budget):
    rows = []
    curve = ec.SECP256R1()
    prehashed = ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))

    rows.append(_row("ECDSA-P256", "keygen", None,
                     measure(lambda: ec.generate_private_key(curve),
                             n=n, warmup=warmup, budget_s=budget)))

    sk = ec.generate_private_key(curve)
    pk = sk.public_key()
    digest = sha256(payloads[next(iter(payloads))])
    sig = sk.sign(digest, prehashed)

    rows.append(_row("ECDSA-P256", "sign_digest", None,
                     measure(lambda: sk.sign(digest, prehashed),
                             n=n, warmup=warmup, budget_s=budget)))
    rows.append(_row("ECDSA-P256", "verify_digest", None,
                     measure(lambda: pk.verify(sig, digest, prehashed),
                             n=n, warmup=warmup, budget_s=budget)))

    for label, payload in payloads.items():
        rows.append(_row("SHA-256", "hash", label,
                         measure(lambda p=payload: sha256(p),
                                 n=n, warmup=warmup, budget_s=budget)))
        rows.append(_row("ECDSA-P256", "sign_e2e", label,
                         measure(lambda p=payload: sk.sign(sha256(p), prehashed),
                                 n=n, warmup=warmup, budget_s=budget)))
        sig_p = sk.sign(sha256(payload), prehashed)
        rows.append(_row("ECDSA-P256", "verify_e2e", label,
                         measure(lambda p=payload, s=sig_p:
                                 pk.verify(s, sha256(p), prehashed),
                                 n=n, warmup=warmup, budget_s=budget)))

    raw_pub = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    # ECDSA DER signatures are variable length (70-72 B typical) because r and s
    # are minimally-encoded INTEGERs. len(sig) is one sample, not a constant.
    rows.append(_size_row("ECDSA-P256", len(sig), len(raw_pub), 32))
    return rows


# --------------------------------------------------------------------------
# PQC via liboqs
# --------------------------------------------------------------------------

def bench_pqc(mech, label, payloads, n, warmup, budget):
    import oqs

    rows = []
    with oqs.Signature(mech) as signer, oqs.Signature(mech) as verifier:
        rows.append(_row(label, "keygen", None,
                         measure(signer.generate_keypair,
                                 n=n, warmup=warmup, budget_s=budget)))

        pub = signer.generate_keypair()
        digest = sha256(payloads[next(iter(payloads))])
        sig = signer.sign(digest)

        rows.append(_row(label, "sign_digest", None,
                         measure(lambda: signer.sign(digest),
                                 n=n, warmup=warmup, budget_s=budget)))
        rows.append(_row(label, "verify_digest", None,
                         measure(lambda: verifier.verify(digest, sig, pub),
                                 n=n, warmup=warmup, budget_s=budget)))

        for plabel, payload in payloads.items():
            rows.append(_row(label, "sign_e2e", plabel,
                             measure(lambda p=payload: signer.sign(sha256(p)),
                                     n=n, warmup=warmup, budget_s=budget)))
            sig_p = signer.sign(sha256(payload))
            rows.append(_row(label, "verify_e2e", plabel,
                             measure(lambda p=payload, s=sig_p:
                                     verifier.verify(sha256(p), s, pub),
                                     n=n, warmup=warmup, budget_s=budget)))

        details = signer.details
        rows.append(_size_row(
            label,
            sig_bytes=len(sig),
            pub_bytes=len(pub),
            sec_bytes=details.get("length_secret_key"),
            # liboqs reports the *maximum* signature length. Falcon is variable
            # length, so this bound and the measured len(sig) differ; the
            # manuscript must say which one a given table reports.
            sig_bytes_max=details.get("length_signature"),
        ))
    return rows


# --------------------------------------------------------------------------

def _row(alg, op, payload, st):
    d = {"kind": "latency", "algorithm": alg, "operation": op,
         "payload": payload or ""}
    d.update(st.as_dict())
    return d


def _size_row(alg, sig_bytes, pub_bytes, sec_bytes, sig_bytes_max=None):
    return {
        "kind": "size", "algorithm": alg, "operation": "size", "payload": "",
        "signature_bytes": sig_bytes,
        "signature_bytes_max": sig_bytes_max or sig_bytes,
        "public_key_bytes": pub_bytes,
        "secret_key_bytes": sec_bytes,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="in-process PQC/classical benchmark")
    ap.add_argument("-n", type=int, default=1000,
                    help="iterations per cell (default 1000)")
    ap.add_argument("--warmup", type=int, default=50)
    ap.add_argument("--budget", type=float, default=60.0,
                    help="wall-clock seconds per cell before n is truncated")
    ap.add_argument("--out", default="results")
    ap.add_argument("--sizes", nargs="*", default=list(DEFAULT_SIZES))
    args = ap.parse_args(argv)

    import oqs
    resolved = algs.resolve_all(list(oqs.get_enabled_sig_mechanisms()))

    payloads = {k: make_payload(DEFAULT_SIZES[k]) for k in args.sizes}

    rows = bench_ecdsa(payloads, args.n, args.warmup, args.budget)
    for a in algs.PQC_ALGS:
        rows += bench_pqc(resolved[a.key], a.label, payloads,
                          args.n, args.warmup, args.budget)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "environment": envinfo.collect(),
        "resolved_mechanisms": resolved,
        "payload_sizes_bytes": {k: DEFAULT_SIZES[k] for k in args.sizes},
        "rows": rows,
    }
    (out / "primitives.json").write_text(json.dumps(doc, indent=2))

    fields = sorted({k for r in rows for k in r})
    with (out / "primitives.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    trunc = [r for r in rows if r.get("truncated")]
    print("wrote %s and %s (%d rows)"
          % (out / "primitives.json", out / "primitives.csv", len(rows)))
    if trunc:
        print("NOTE: %d cell(s) hit the %.0fs budget and report n < %d; "
              "see the 'truncated' column."
              % (len(trunc), args.budget, args.n))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
