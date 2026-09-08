"""Task 3 + Task 4: hybrid SignedData construction, verification, and the
three binding modes whose differences the separability analysis turns on.

Modes
-----
Both halves always sign *something*; the modes differ in what, and in what the
classical `messageDigest` attribute is set to.

  concat        classical signs signedAttrs{contentType, messageDigest=H(M)};
                PQC signs H(M).
                The two signatures are independent statements about the same
                document. Deleting one leaves the other a valid, standalone,
                standards-conformant signature. Naive and separable.

  bound-attr    as `concat`, plus a signed attribute carrying
                B = H(ctx || mode || pk_c || pk_p || H(M)); PQC signs B.
                The classical signature now covers B, so the classical half is
                cryptographically committed to the PQC public key. A verifier
                that understands the binding attribute can detect a stripped
                artifact. A verifier that does not will ignore an unrecognised
                signed attribute and accept -- RFC 5652 has no criticality
                flag, so the commitment cannot enforce itself. Backwards
                compatible, but only policy-enforced.

  bound-digest  messageDigest is set to B instead of H(M); PQC signs B.
                Now a legacy verifier recomputes H(eContent), compares against
                B, and fails. Non-separability is enforced by any conforming
                verifier -- including on the *unmodified* artifact, which is
                the price. This mode is deliberately not backwards compatible.

The point of implementing all three is that they do not merely differ in
strength; they trade against each other. `bound-attr` and `bound-digest` sit on
opposite sides of a choice between legacy acceptance and self-enforcing
binding, and CMS offers nothing in between. bench/attack.py measures that.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from asn1crypto import algos, cms, core, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from . import asn1_defs
from .asn1_defs import (ATTR_NAME_BINDING, ATTR_NAME_PQC, OID_HYBRID_BINDING,
                        OID_PQC_SIGNATURE, PqcSignatureValue)

MODES = ("concat", "bound-attr", "bound-digest")

BIND_CONTEXT = b"PQCVM-HYBRID-BIND-v1"


class VerificationError(Exception):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _lp(b: bytes) -> bytes:
    """Length-prefix a field before concatenation.

    Without this, H(pk_c || pk_p || H(M)) is ambiguous: two different
    (pk_c, pk_p) splits of the same byte string produce the same preimage.
    For fixed-length keys the ambiguity is not exploitable today, but Falcon
    public keys are fixed while its *signatures* are not, and a study that
    publishes a binding construction should not publish one that only happens
    to be safe.
    """
    return len(b).to_bytes(4, "big") + b


def binding_value(mode: str, pk_classical: bytes, pk_pqc: bytes,
                  content_digest: bytes) -> bytes:
    return sha256(
        BIND_CONTEXT
        + _lp(mode.encode("utf-8"))
        + _lp(pk_classical)
        + _lp(pk_pqc)
        + _lp(content_digest)
    )


# --------------------------------------------------------------------------


def _sorted_attrs(attrs: list) -> cms.CMSAttributes:
    """DER requires SET OF members in ascending encoding order.

    asn1crypto does not sort on dump, and some verifiers re-encode before
    hashing. Sorting here keeps the bytes the signer signed and the bytes a
    strict verifier reconstructs identical.
    """
    return cms.CMSAttributes(sorted(attrs, key=lambda a: a.dump()))


@dataclass
class HybridKeys:
    ec_private: object            # cryptography EC private key
    ec_cert_der: bytes            # DER X.509 for the EC key
    pqc_mech: str                 # liboqs mechanism name
    pqc_alg_oid: str
    pqc_public: bytes
    pqc_secret: bytes
    pqc_cert_der: bytes | None = None

    @property
    def ec_public_raw(self) -> bytes:
        return self.ec_private.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)


def sign(keys: HybridKeys, message: bytes, mode: str,
         detached: bool = True) -> bytes:
    """Produce a DER-encoded CMS ContentInfo carrying a hybrid signature."""
    if mode not in MODES:
        raise ValueError("unknown mode %r; expected one of %r" % (mode, MODES))

    import oqs

    content_digest = sha256(message)
    binding = binding_value(mode, keys.ec_public_raw, keys.pqc_public,
                            content_digest)

    # What each half actually signs.
    if mode == "concat":
        message_digest_attr = content_digest
        pqc_payload = content_digest
    elif mode == "bound-attr":
        message_digest_attr = content_digest
        pqc_payload = binding
    else:  # bound-digest
        message_digest_attr = binding
        pqc_payload = binding

    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest",
                          "values": [core.OctetString(message_digest_attr)]}),
    ]
    if mode != "concat":
        attrs.append(cms.CMSAttribute({
            "type": ATTR_NAME_BINDING,
            "values": [core.OctetString(binding)],
        }))
    signed_attrs = _sorted_attrs(attrs)

    # RFC 5652 5.4: sign the DER SET OF encoding, not the implicitly-tagged
    # [0] form that appears inside SignerInfo.
    to_sign = signed_attrs.untag().dump()
    ec_sig = keys.ec_private.sign(
        to_sign, ec.ECDSA(hashes.SHA256()))

    with oqs.Signature(keys.pqc_mech, keys.pqc_secret) as signer:
        pqc_sig = signer.sign(pqc_payload)

    pqc_value = PqcSignatureValue({
        "version": 1,
        "mode": mode,
        "algorithm": {"algorithm": keys.pqc_alg_oid},
        "public_key": keys.pqc_public,
        "signature": pqc_sig,
    })
    if keys.pqc_cert_der:
        pqc_value["certificate"] = keys.pqc_cert_der

    ec_cert = x509.Certificate.load(keys.ec_cert_der)
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": ec_cert.issuer,
                "serial_number": ec_cert.serial_number,
            })
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm(
            {"algorithm": "sha256_ecdsa"}),
        "signature": ec_sig,
        "unsigned_attrs": cms.CMSAttributes([
            cms.CMSAttribute({"type": ATTR_NAME_PQC, "values": [pqc_value]}),
        ]),
    })

    # asn1crypto types SignedData.encap_content_info as ContentInfo (not
    # EncapsulatedContentInfo), so hand it a dict and let it build the right
    # class rather than naming one.
    encap = {"content_type": "data"}
    if not detached:
        encap["content"] = core.ParsableOctetString(message)

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": encap,
        "certificates": [cms.CertificateChoices({"certificate": ec_cert})],
        "signer_infos": [signer_info],
    })
    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


# --------------------------------------------------------------------------


def strip_pqc(der: bytes) -> bytes:
    """The attack: delete the PQC unsigned attribute and re-encode.

    Nothing else is touched. The classical signature is not recomputed and does
    not need to be -- unsigned attributes are outside its scope, which is the
    whole problem.
    """
    ci = cms.ContentInfo.load(der)
    sd = ci["content"]
    for si in sd["signer_infos"]:
        unsigned = si["unsigned_attrs"]
        if unsigned is core.VOID or unsigned is None:
            continue
        kept = [a for a in unsigned
                if a["type"].dotted != OID_PQC_SIGNATURE]
        if kept:
            si["unsigned_attrs"] = cms.CMSAttributes(kept)
        else:
            del si["unsigned_attrs"]
    return ci.dump()


def _find_attr(attrs, oid: str):
    if attrs is None or attrs is core.VOID:
        return None
    for a in attrs:
        if a["type"].dotted == oid:
            return a["values"]
    return None


def verify(der: bytes, message: bytes, policy: str = "hybrid") -> dict:
    """Verify a hybrid artifact.

    policy="hybrid"    full check, including the binding rule for bound modes.
    policy="classical" simulate a verifier that has never heard of the PQC
                       attribute: check contentType, messageDigest against
                       H(M), and the classical signature. Nothing else. This is
                       what a conforming RFC 5652 implementation does, and it
                       is the comparison the stripping attack rests on.

    Returns a dict; `accepted` is the verdict and `reason` says why not.
    """
    if policy not in ("hybrid", "classical"):
        raise ValueError("policy must be 'hybrid' or 'classical'")

    import oqs

    result = {
        "policy": policy,
        "mode": None,
        "pqc_attribute_present": False,
        "binding_attribute_present": False,
        "content_digest_ok": False,
        "classical_ok": False,
        "pqc_ok": None,
        "binding_ok": None,
        "accepted": False,
        "reason": "",
    }

    ci = cms.ContentInfo.load(der)
    sd = ci["content"]
    si = sd["signer_infos"][0]
    signed_attrs = si["signed_attrs"]

    content_digest = sha256(message)

    md_values = _find_attr(signed_attrs, "1.2.840.113549.1.9.4")
    if md_values is None:
        result["reason"] = "no messageDigest attribute"
        return result
    claimed_digest = bytes(md_values[0])

    binding_values = _find_attr(signed_attrs, OID_HYBRID_BINDING)
    result["binding_attribute_present"] = binding_values is not None

    # Classical signature over the DER SET OF of the signed attributes.
    ec_cert = x509.Certificate.load(sd["certificates"][0].chosen.dump())
    pub = serialization.load_der_public_key(ec_cert.public_key.dump())
    try:
        pub.verify(bytes(si["signature"]),
                   signed_attrs.untag().dump(),
                   ec.ECDSA(hashes.SHA256()))
        result["classical_ok"] = True
    except Exception as exc:
        result["reason"] = "classical signature invalid: %s" % type(exc).__name__

    unsigned = si["unsigned_attrs"]
    pqc_values = _find_attr(unsigned, OID_PQC_SIGNATURE)
    result["pqc_attribute_present"] = pqc_values is not None

    if policy == "classical":
        # A conforming legacy verifier compares messageDigest against the hash
        # of the content. Under bound-digest it holds the binding value, so
        # this is where that mode fails closed.
        result["content_digest_ok"] = (claimed_digest == content_digest)
        if not result["content_digest_ok"] and not result["reason"]:
            result["reason"] = "messageDigest does not match H(content)"
        result["accepted"] = result["content_digest_ok"] and result["classical_ok"]
        if result["accepted"]:
            result["reason"] = "accepted: valid RFC 5652 SignedData"
        return result

    # ---- hybrid policy ----
    if pqc_values is None:
        result["content_digest_ok"] = (claimed_digest == content_digest)
        result["reason"] = "PQC signature attribute absent"
        if result["binding_attribute_present"]:
            result["reason"] += " but binding attribute present: stripped artifact"
        result["accepted"] = False
        return result

    pv = pqc_values[0]
    if not isinstance(pv, PqcSignatureValue):
        pv = PqcSignatureValue.load(pv.dump())
    mode = str(pv["mode"])
    result["mode"] = mode
    pqc_pub = bytes(pv["public_key"])
    pqc_sig = bytes(pv["signature"])
    pqc_oid = pv["algorithm"]["algorithm"].dotted

    from .algs import PQC_ALGS
    match = [a for a in PQC_ALGS if a.oid == pqc_oid]
    if not match:
        result["reason"] = "unknown PQC algorithm OID %s" % pqc_oid
        return result

    ec_pub_raw = pub.public_bytes(serialization.Encoding.X962,
                                  serialization.PublicFormat.UncompressedPoint)
    expected_binding = binding_value(mode, ec_pub_raw, pqc_pub, content_digest)

    if mode == "concat":
        result["content_digest_ok"] = (claimed_digest == content_digest)
        pqc_payload = content_digest
        result["binding_ok"] = None
    elif mode == "bound-attr":
        result["content_digest_ok"] = (claimed_digest == content_digest)
        pqc_payload = expected_binding
        result["binding_ok"] = (
            binding_values is not None
            and bytes(binding_values[0]) == expected_binding)
    elif mode == "bound-digest":
        result["content_digest_ok"] = (claimed_digest == expected_binding)
        pqc_payload = expected_binding
        result["binding_ok"] = (
            binding_values is not None
            and bytes(binding_values[0]) == expected_binding)
    else:
        result["reason"] = "unknown hybrid mode %r" % mode
        return result

    import oqs as _oqs
    from .algs import resolve
    mech = resolve(match[0], list(_oqs.get_enabled_sig_mechanisms()))
    with _oqs.Signature(mech) as verifier:
        try:
            result["pqc_ok"] = bool(
                verifier.verify(pqc_payload, pqc_sig, pqc_pub))
        except Exception:
            result["pqc_ok"] = False

    checks = [result["content_digest_ok"], result["classical_ok"],
              result["pqc_ok"]]
    if mode != "concat":
        checks.append(result["binding_ok"])
    result["accepted"] = all(bool(c) for c in checks)
    if not result["reason"]:
        result["reason"] = ("accepted: both halves valid"
                            if result["accepted"] else
                            "one or more checks failed")
    return result
