"""Minimal self-signed X.509 certificates for PQC keys.

Why hand-rolled rather than asn1crypto.x509
-------------------------------------------
asn1crypto's `x509.Certificate` resolves the SubjectPublicKeyInfo body from the
algorithm OID. ML-DSA, Falcon and SLH-DSA are not in its tables, so round-
tripping a PQC certificate through it depends on how a given asn1crypto release
handles an unmapped algorithm. The structures below are declared explicitly, so
parsing behaviour does not vary with the dependency version -- which matters for
a repository a reviewer is expected to re-run.

These certificates are deliberately kept *out* of `SignedData.certificates` (see
bench/asn1_defs.py) and carried inside the PQC attribute instead, so a legacy
verifier walking the certificate set never encounters one it cannot parse. The
structure here is standards-shaped, but the point is not to claim PKI
interoperability -- it is to give the PQC half a certificate-shaped identity
binding of the kind the manuscript describes.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from asn1crypto import core, x509


class AlgorithmIdentifier(core.Sequence):
    _fields = [
        ("algorithm", core.ObjectIdentifier),
        ("parameters", core.Any, {"optional": True}),
    ]


class SubjectPublicKeyInfo(core.Sequence):
    _fields = [
        ("algorithm", AlgorithmIdentifier),
        ("public_key", core.OctetBitString),
    ]


class Validity(core.Sequence):
    _fields = [
        ("not_before", x509.Time),
        ("not_after", x509.Time),
    ]


class Version(core.Integer):
    _map = {0: "v1", 1: "v2", 2: "v3"}


class TbsCertificate(core.Sequence):
    _fields = [
        ("version", Version, {"explicit": 0, "default": "v1"}),
        ("serial_number", core.Integer),
        ("signature", AlgorithmIdentifier),
        ("issuer", x509.Name),
        ("validity", Validity),
        ("subject", x509.Name),
        ("subject_public_key_info", SubjectPublicKeyInfo),
    ]


class PqcCertificate(core.Sequence):
    _fields = [
        ("tbs_certificate", TbsCertificate),
        ("signature_algorithm", AlgorithmIdentifier),
        ("signature_value", core.OctetBitString),
    ]


def self_signed(mech: str, alg_oid: str, public_key: bytes,
                secret_key: bytes, common_name: str,
                days: int = 365) -> bytes:
    """Build and self-sign a PQC certificate. Returns DER."""
    import oqs

    now = datetime.now(timezone.utc)
    name = x509.Name.build({"common_name": common_name})
    alg = AlgorithmIdentifier({"algorithm": alg_oid})

    tbs = TbsCertificate({
        "version": "v3",
        "serial_number": int.from_bytes(os.urandom(16), "big") >> 1,
        "signature": alg,
        "issuer": name,
        "validity": Validity({
            "not_before": x509.Time({"utc_time": now}),
            "not_after": x509.Time({"utc_time": now + timedelta(days=days)}),
        }),
        "subject": name,
        "subject_public_key_info": SubjectPublicKeyInfo({
            "algorithm": alg,
            "public_key": public_key,
        }),
    })

    with oqs.Signature(mech, secret_key) as signer:
        sig = signer.sign(tbs.dump())

    return PqcCertificate({
        "tbs_certificate": tbs,
        "signature_algorithm": alg,
        "signature_value": sig,
    }).dump()


def verify_self_signed(der: bytes, mech: str) -> bool:
    """Check that a PQC certificate's signature validates under its own key."""
    import oqs

    cert = PqcCertificate.load(der)
    tbs = cert["tbs_certificate"]
    pub = tbs["subject_public_key_info"]["public_key"].native
    sig = cert["signature_value"].native
    with oqs.Signature(mech) as v:
        try:
            return bool(v.verify(tbs.dump(), sig, pub))
        except Exception:
            return False
