"""Task 6: substitution attacks against the hybrid CMS artifacts.

bench/attack.py establishes what happens when an adversary *deletes* the PQC
attribute. That experiment cannot distinguish `concat` from `bound-attr`: both
modes give identical results in all eight cells, because a deletion is invisible
to any verifier that was not already looking for the attribute. The binding does
real cryptographic work in `bound-attr` -- the classical signature commits to
pk_pqc -- and the stripping experiment gives it nothing to do.

Substitution is where the modes separate. The adversary does not delete the PQC
half; they replace it with one of their own, generated under a keypair they
control. Three variants are tested:

  substituted       The PQC attribute is replaced with the adversary's public
                    key, certificate, and a signature over whatever payload the
                    artifact's declared mode requires. Under `concat` the
                    verifier reads pk_pqc from the attribute and has nothing to
                    check it against, so the forged half should verify. Under
                    the bound modes the signed binding attribute commits to the
                    *original* pk_pqc, so the recomputed binding should not
                    match and the artifact should be rejected.

  mode_downgrade    As above, but the adversary also rewrites the `mode` field
                    inside the PQC attribute to "concat". That field lives in an
                    *unsigned* attribute, so nothing prevents the rewrite, and
                    bench/hybrid_cms.py:verify() reads the binding rule from it.
                    If the verifier honours the claimed mode, a `bound-attr`
                    artifact can be steered into the `concat` code path, where
                    the binding attribute is never examined. This is a self-test
                    of our own verifier, not of the construction.

  content_tamper   Control. The adversary alters the document. Every mode and
                    every verifier must reject; if any accepts, the harness is
                    wrong and the other two rows mean nothing.

The `hybrid_hardened` verifier adds one rule to `hybrid_policy`: an artifact
whose PQC attribute claims mode "concat" while a binding attribute is present in
signedAttrs is rejected as inconsistent. Reporting both columns lets the
mode-downgrade result be stated as a finding with its remedy attached rather
than as a defect.

Usage
-----
    python -m bench.substitute --message data/msg.txt --out results
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from asn1crypto import cms, core
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from . import algs, attack, envinfo, hybrid_cms, keymat
from .asn1_defs import (ATTR_NAME_PQC, OID_HYBRID_BINDING, OID_PQC_SIGNATURE,
                        PqcSignatureValue)
from .hybrid_cms import MODES, binding_value, sha256

STATES = ("substituted", "mode_downgrade", "content_tamper")


# --------------------------------------------------------------------------
# artifact surgery
# --------------------------------------------------------------------------

def _signer_info(ci: cms.ContentInfo):
    return ci["content"]["signer_infos"][0]


def _pqc_value(si) -> PqcSignatureValue | None:
    unsigned = si["unsigned_attrs"]
    if unsigned is core.VOID or unsigned is None:
        return None
    for a in unsigned:
        if a["type"].dotted == OID_PQC_SIGNATURE:
            v = a["values"][0]
            if not isinstance(v, PqcSignatureValue):
                v = PqcSignatureValue.load(v.dump())
            return v
    return None


def _ec_public_raw(ci: cms.ContentInfo) -> bytes:
    """Recover the signer's EC public key from the embedded certificate.

    The adversary cannot alter this without invalidating the classical
    signature, so it is a fixed input to the binding from their perspective.
    """
    cert_der = ci["content"]["certificates"][0].chosen.dump()
    pub = cx509.load_der_x509_certificate(cert_der).public_key()
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


def substitute_pqc(der: bytes, message: bytes, adversary: hybrid_cms.HybridKeys,
                   claim_mode: str | None = None) -> bytes:
    """Replace the PQC half with one the adversary controls.

    `claim_mode` overrides the mode recorded in the replacement attribute. The
    adversary signs whatever payload *that* mode's rule requires, computed
    against their own public key, which is the best they can do: the binding
    attribute inside signedAttrs is covered by the classical signature and
    cannot be updated to match.

    Nothing else in the artifact is touched. signedAttrs, the classical
    signature, and the embedded EC certificate are all left intact.
    """
    import oqs

    ci = cms.ContentInfo.load(der)
    si = _signer_info(ci)
    original = _pqc_value(si)
    if original is None:
        raise ValueError("artifact carries no PQC attribute to substitute")

    declared_mode = original["mode"].native
    mode = claim_mode or declared_mode
    if mode not in MODES:
        raise ValueError("unknown claim_mode %r" % mode)

    content_digest = sha256(message)
    ec_pub_raw = _ec_public_raw(ci)

    # The payload a verifier applying `mode`'s rule will check against.
    if mode == "concat":
        payload = content_digest
    else:
        payload = binding_value(mode, ec_pub_raw, adversary.pqc_public,
                                content_digest)

    with oqs.Signature(adversary.pqc_mech, adversary.pqc_secret) as signer:
        forged = signer.sign(payload)

    replacement = PqcSignatureValue({
        "version": 1,
        "mode": mode,
        "algorithm": {"algorithm": adversary.pqc_alg_oid},
        "public_key": adversary.pqc_public,
        "signature": forged,
    })
    if adversary.pqc_cert_der:
        replacement["certificate"] = adversary.pqc_cert_der

    kept = [a for a in si["unsigned_attrs"]
            if a["type"].dotted != OID_PQC_SIGNATURE]
    kept.append(cms.CMSAttribute({"type": ATTR_NAME_PQC,
                                  "values": [replacement]}))
    si["unsigned_attrs"] = cms.CMSAttributes(kept)
    return ci.dump()


def tamper_content(message: bytes) -> bytes:
    """Flip one bit of the document. The artifact is left alone."""
    b = bytearray(message)
    b[0] ^= 0x01
    return bytes(b)


# --------------------------------------------------------------------------
# hardened verifier
# --------------------------------------------------------------------------

def verify_hardened(der: bytes, message: bytes) -> dict:
    """hybrid_policy, plus a consistency rule on the claimed mode.

    The PQC attribute is unsigned, so its `mode` field is adversary-controlled.
    A verifier that dispatches on it without cross-checking can be steered from
    the strict rule to the permissive one. The signed attributes are not
    adversary-controlled, so their contents decide: if a binding attribute is
    present, the artifact was signed under a bound mode, and a PQC attribute
    claiming "concat" is inconsistent regardless of what else verifies.
    """
    ci = cms.ContentInfo.load(der)
    si = _signer_info(ci)

    binding_present = False
    signed = si["signed_attrs"]
    if signed is not core.VOID and signed is not None:
        binding_present = any(a["type"].dotted == OID_HYBRID_BINDING
                              for a in signed)

    pv = _pqc_value(si)
    claimed = pv["mode"].native if pv is not None else None

    if binding_present and claimed == "concat":
        return {
            "policy": "hybrid_hardened",
            "mode": claimed,
            "accepted": False,
            "reason": ("mode/attribute inconsistency: PQC attribute claims "
                       "concat but a binding attribute is present in "
                       "signedAttrs"),
        }

    result = hybrid_cms.verify(der, message, policy="hybrid")
    result["policy"] = "hybrid_hardened"
    return result


# --------------------------------------------------------------------------
# experiment
# --------------------------------------------------------------------------

def run(message: bytes, oqs_conf: str) -> dict:
    legacy_env = dict(os.environ)
    legacy_env.pop("OPENSSL_CONF", None)
    oqs_env = dict(os.environ)
    oqs_env["OPENSSL_CONF"] = str(Path(oqs_conf).resolve())

    cases = []
    for alg in algs.PQC_ALGS:
        victim = keymat.generate(alg.key, outdir=Path("out"))
        # Fresh keypair under the adversary's control, same mechanism.
        adversary = keymat.generate(alg.key, outdir=None)

        for mode in MODES:
            intact = hybrid_cms.sign(victim, message, mode, detached=True)

            variants = {
                "substituted": (
                    substitute_pqc(intact, message, adversary), message),
                "mode_downgrade": (
                    substitute_pqc(intact, message, adversary,
                                   claim_mode="concat"), message),
                "content_tamper": (intact, tamper_content(message)),
            }

            case = {
                "algorithm": alg.label,
                "algorithm_key": alg.key,
                "mode": mode,
                "adversary_pqc_public_bytes": len(adversary.pqc_public),
            }

            for state, (art, msg) in variants.items():
                case[state] = {
                    "hybrid_policy": hybrid_cms.verify(art, msg,
                                                       policy="hybrid"),
                    "hybrid_hardened": verify_hardened(art, msg),
                    "classical_policy": hybrid_cms.verify(art, msg,
                                                          policy="classical"),
                    "openssl_legacy": attack._openssl_verify(
                        art, msg, victim.ec_cert_der, legacy_env),
                    "openssl_oqs": attack._openssl_verify(
                        art, msg, victim.ec_cert_der, oqs_env),
                }

            cases.append(case)

    return {"environment": envinfo.collect(), "cases": cases}


def _fmt(v):
    return {True: "ACCEPT", False: "reject", None: "n/a"}[v]


def print_matrix(doc: dict) -> None:
    hdr = ("%-26s %-13s %-15s %-8s %-9s %-10s %-9s"
           % ("algorithm", "mode", "attack",
              "hybrid", "hardened", "classical", "ossl-lgcy"))
    print(hdr)
    print("-" * len(hdr))
    for c in doc["cases"]:
        for state in STATES:
            r = c[state]
            print("%-26s %-13s %-15s %-8s %-9s %-10s %-9s" % (
                c["algorithm"], c["mode"], state,
                _fmt(r["hybrid_policy"]["accepted"]),
                _fmt(r["hybrid_hardened"]["accepted"]),
                _fmt(r["classical_policy"]["accepted"]),
                _fmt(r["openssl_legacy"]["accepted"]),
            ))


def check_control(doc: dict) -> int:
    """content_tamper must be rejected everywhere. If not, stop."""
    bad = []
    for c in doc["cases"]:
        r = c["content_tamper"]
        for k in ("hybrid_policy", "hybrid_hardened", "classical_policy",
                  "openssl_legacy", "openssl_oqs"):
            if r[k].get("accepted"):
                bad.append((c["algorithm"], c["mode"], k))
    if bad:
        print("\nCONTROL FAILED -- tampered content accepted by:")
        for a, m, k in bad:
            print("  %s / %s / %s" % (a, m, k))
        print("The other rows cannot be trusted. Fix the harness first.")
        return 1
    print("\ncontrol OK: tampered content rejected by every verifier")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="substitution attack experiment")
    ap.add_argument("--message", default="data/msg.txt")
    ap.add_argument("--out", default="results")
    ap.add_argument("--oqs-conf", default="config/openssl-oqs.cnf")
    args = ap.parse_args(argv)

    msg_path = Path(args.message)
    if not msg_path.exists() or msg_path.stat().st_size == 0:
        raise SystemExit(
            "%s is missing or empty. Run `make payloads` first." % msg_path)
    message = msg_path.read_bytes()

    doc = run(message, args.oqs_conf)
    doc["message_bytes"] = len(message)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "substitution.json").write_text(json.dumps(doc, indent=2))
    print_matrix(doc)
    rc = check_control(doc)
    print("\nwrote %s" % (out / "substitution.json"))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
