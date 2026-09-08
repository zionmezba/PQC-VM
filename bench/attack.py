"""Task 3 (legacy compatibility) and Task 4 (separability under attack).

For every (PQC algorithm, hybrid mode) pair this builds a real hybrid
SignedData and puts it through four verifiers:

  hybrid_policy     our verifier, full hybrid rules
  classical_policy  our verifier, restricted to what RFC 5652 mandates
  openssl_legacy    the openssl CLI with **no OQS provider loaded** -- an
                    unmodified verifier that has never heard of ML-DSA
  openssl_oqs       the openssl CLI with oqsprovider activated

each on both the intact artifact and the stripped one. `openssl_legacy` on the
intact artifact is RQ1: does the classical half still verify when a PQC
component is present but unrecognised? `openssl_legacy` on the stripped
artifact is the attack: is the classical half accepted as a standalone
signature once the PQC half is deleted?

The two together are the result. A mode is only non-separable if the second
answer is "no", and only backwards compatible if the first is "yes". Whether
any mode achieves both is the question, and the answer is written to
results/separability.json rather than assumed here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography import x509 as cx509

from . import algs, asn1_defs, envinfo, hybrid_cms, keymat
from .hybrid_cms import MODES
from .timing import measure


def _openssl_verify(art_der: bytes, message: bytes, ec_cert_der: bytes,
                    env: dict) -> dict:
    """Run `openssl cms -verify` on a detached signature.

    Two flags are load-bearing and both were absent from the original scripts:

    -noverify disables *certificate chain* validation, required here because
    the signer certificate is self-signed. It does not disable signature
    checking. Omitting it is why every classical row in the old metrics.csv
    reported pass=0.

    -binary disables S/MIME canonicalisation of the detached content. Without
    it, `openssl cms` rewrites LF to CRLF before hashing, so its content digest
    never matches the messageDigest attribute for any document containing a
    newline, and every artifact is rejected with a
    CMS_SignerInfo_verify_content error regardless of whether the signature is
    sound. That failure mode is indistinguishable from a genuine legacy
    rejection, which would silently invert the RQ1 result.
    """
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "art.der").write_bytes(art_der)
        (d / "msg.bin").write_bytes(message)
        cert = cx509.load_der_x509_certificate(ec_cert_der)
        (d / "signer.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM))
        cmd = [
            "openssl", "cms", "-verify",
            "-inform", "DER", "-in", str(d / "art.der"),
            "-content", str(d / "msg.bin"),
            "-certfile", str(d / "signer.pem"),
            "-noverify",
            "-binary",
            "-out", os.devnull,
        ]
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                               timeout=120)
        except FileNotFoundError:
            return {"accepted": None, "detail": "openssl not found"}
        return {
            "accepted": r.returncode == 0,
            "returncode": r.returncode,
            "detail": (r.stderr or "").strip()[:400],
        }


def _sizes(intact: bytes, stripped: bytes, keys) -> dict:
    """Byte accounting for the size-composition figure.

    Every field says what it counts. The original study compared a 742 B CMS
    envelope against a 3309 B raw signature and called it a size ratio; these
    names exist so that cannot happen again.
    """
    from asn1crypto import cms as _cms

    ci = _cms.ContentInfo.load(intact)
    si = ci["content"]["signer_infos"][0]
    pqc_attr_der = None
    for a in si["unsigned_attrs"]:
        if a["type"].dotted == asn1_defs.OID_PQC_SIGNATURE:
            pqc_attr_der = a.dump()
    pqc_sig_len = len(hybrid_cms_pqc_sig(intact))

    return {
        "hybrid_cms_bytes": len(intact),
        "classical_only_cms_bytes": len(stripped),
        "pqc_attribute_total_bytes": len(pqc_attr_der) if pqc_attr_der else 0,
        "pqc_attribute_overhead_bytes": len(intact) - len(stripped),
        "pqc_signature_raw_bytes": pqc_sig_len,
        "pqc_public_key_raw_bytes": len(keys.pqc_public),
        "pqc_certificate_der_bytes": (len(keys.pqc_cert_der)
                                      if keys.pqc_cert_der else 0),
        "ec_certificate_der_bytes": len(keys.ec_cert_der),
        "ec_signature_der_bytes": len(bytes(si["signature"])),
    }


def hybrid_cms_pqc_sig(der: bytes) -> bytes:
    from asn1crypto import cms as _cms
    from .asn1_defs import PqcSignatureValue
    si = _cms.ContentInfo.load(der)["content"]["signer_infos"][0]
    for a in si["unsigned_attrs"]:
        if a["type"].dotted == asn1_defs.OID_PQC_SIGNATURE:
            v = a["values"][0]
            if not isinstance(v, PqcSignatureValue):
                v = PqcSignatureValue.load(v.dump())
            return bytes(v["signature"])
    return b""


def run(message: bytes, n: int, warmup: int, budget: float,
        oqs_conf: str) -> dict:
    legacy_env = dict(os.environ)
    legacy_env.pop("OPENSSL_CONF", None)
    oqs_env = dict(os.environ)
    oqs_env["OPENSSL_CONF"] = str(Path(oqs_conf).resolve())

    cases = []
    for alg in algs.PQC_ALGS:
        keys = keymat.generate(alg.key, outdir=Path("out"))
        for mode in MODES:
            intact = hybrid_cms.sign(keys, message, mode, detached=True)
            stripped = hybrid_cms.strip_pqc(intact)

            case = {
                "algorithm": alg.label,
                "algorithm_key": alg.key,
                "mechanism": keys.pqc_mech,
                "mode": mode,
                "sizes": _sizes(intact, stripped, keys),
                "intact": {}, "stripped": {},
            }

            for label, art in (("intact", intact), ("stripped", stripped)):
                case[label]["hybrid_policy"] = hybrid_cms.verify(
                    art, message, policy="hybrid")
                case[label]["classical_policy"] = hybrid_cms.verify(
                    art, message, policy="classical")
                case[label]["openssl_legacy"] = _openssl_verify(
                    art, message, keys.ec_cert_der, legacy_env)
                case[label]["openssl_oqs"] = _openssl_verify(
                    art, message, keys.ec_cert_der, oqs_env)

            # Cost of the binding, measured the same way as everything else.
            case["latency"] = {
                "sign_us": measure(
                    lambda k=keys, m=mode: hybrid_cms.sign(k, message, m),
                    n=n, warmup=warmup, budget_s=budget).as_dict(),
                "verify_hybrid_us": measure(
                    lambda a=intact: hybrid_cms.verify(a, message, "hybrid"),
                    n=n, warmup=warmup, budget_s=budget).as_dict(),
            }
            cases.append(case)
    return {"environment": envinfo.collect(), "cases": cases}


def _fmt(v):
    return {True: "accept", False: "REJECT", None: "n/a"}[v]


def print_matrix(doc: dict) -> None:
    hdr = ("%-26s %-13s %-8s %-9s %-9s %-9s %-9s"
           % ("algorithm", "mode", "artifact",
              "hybrid", "classical", "ossl-lgcy", "ossl-oqs"))
    print(hdr)
    print("-" * len(hdr))
    for c in doc["cases"]:
        for label in ("intact", "stripped"):
            r = c[label]
            print("%-26s %-13s %-8s %-9s %-9s %-9s %-9s" % (
                c["algorithm"], c["mode"], label,
                _fmt(r["hybrid_policy"]["accepted"]),
                _fmt(r["classical_policy"]["accepted"]),
                _fmt(r["openssl_legacy"]["accepted"]),
                _fmt(r["openssl_oqs"]["accepted"]),
            ))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="hybrid separability experiment")
    ap.add_argument("--message", default="data/msg.txt")
    ap.add_argument("-n", type=int, default=200,
                    help="iterations for the binding-cost measurement")
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--budget", type=float, default=60.0)
    ap.add_argument("--out", default="results")
    ap.add_argument("--oqs-conf", default="config/openssl-oqs.cnf")
    args = ap.parse_args(argv)

    msg_path = Path(args.message)
    if not msg_path.exists() or msg_path.stat().st_size == 0:
        raise SystemExit(
            "%s is missing or empty. Run `make payloads` first -- signing a "
            "zero-byte document is what produced a third of the original runs."
            % msg_path)
    message = msg_path.read_bytes()

    doc = run(message, args.n, args.warmup, args.budget, args.oqs_conf)
    doc["message_bytes"] = len(message)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "separability.json").write_text(json.dumps(doc, indent=2))
    print_matrix(doc)
    print("\nwrote %s" % (out / "separability.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
