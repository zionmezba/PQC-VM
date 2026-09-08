"""Key and certificate material for the hybrid artifacts.

Generated fresh per run and written to `out/` so an artifact can be inspected
by hand, but nothing here is read back inside a timed region.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import algs, pqc_x509
from .hybrid_cms import HybridKeys


def _ec_self_signed(key, common_name: str, days: int = 365) -> bytes:
    name = cx509.Name([
        cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
        cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC-VM experiment"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(cx509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .add_extension(
            cx509.KeyUsage(digital_signature=True, content_commitment=True,
                           key_encipherment=False, data_encipherment=False,
                           key_agreement=False, key_cert_sign=True,
                           crl_sign=False, encipher_only=False,
                           decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def generate(alg_key: str, outdir: Path | None = None,
             with_pqc_cert: bool = True) -> HybridKeys:
    """Generate an ECDSA P-256 keypair/cert and a PQC keypair/cert."""
    import oqs

    alg = algs.BY_KEY[alg_key]
    mech = algs.resolve(alg, list(oqs.get_enabled_sig_mechanisms()))

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_cert = _ec_self_signed(ec_key, "PQC-VM classical signer (ECDSA P-256)")

    with oqs.Signature(mech) as signer:
        pqc_pub = signer.generate_keypair()
        pqc_sec = signer.export_secret_key()

    pqc_cert = None
    if with_pqc_cert:
        pqc_cert = pqc_x509.self_signed(
            mech, alg.oid, pqc_pub, pqc_sec,
            "PQC-VM pqc signer (%s)" % alg.label)

    keys = HybridKeys(
        ec_private=ec_key,
        ec_cert_der=ec_cert,
        pqc_mech=mech,
        pqc_alg_oid=alg.oid,
        pqc_public=pqc_pub,
        pqc_secret=pqc_sec,
        pqc_cert_der=pqc_cert,
    )

    if outdir is not None:
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "ecdsa.key.pem").write_bytes(ec_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        (outdir / "ecdsa.crt.der").write_bytes(ec_cert)
        (outdir / ("%s.pub.raw" % alg_key)).write_bytes(pqc_pub)
        (outdir / ("%s.key.raw" % alg_key)).write_bytes(pqc_sec)
        if pqc_cert:
            (outdir / ("%s.crt.der" % alg_key)).write_bytes(pqc_cert)
        # Sizes are recorded as *raw DER/key bytes*. The original study reported
        # PEM file sizes on disk, which are ~33% larger from base64 plus header
        # and footer lines, and are not key sizes.
        (outdir / ("%s.keysizes.json" % alg_key)).write_text(json.dumps({
            "mechanism": mech,
            "ec_public_key_raw_bytes": len(keys.ec_public_raw),
            "ec_certificate_der_bytes": len(ec_cert),
            "pqc_public_key_raw_bytes": len(pqc_pub),
            "pqc_secret_key_raw_bytes": len(pqc_sec),
            "pqc_certificate_der_bytes": len(pqc_cert) if pqc_cert else None,
        }, indent=2))

    return keys
