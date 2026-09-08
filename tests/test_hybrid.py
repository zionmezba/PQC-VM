"""Correctness tests for the hybrid construction.

These assert the properties the manuscript claims. Two of them assert the
*negative* result — that `concat` and `bound-attr` remain acceptable to a
classical-policy verifier after stripping — because that is the finding, and a
test suite that only asserted the comfortable direction would let a future
change quietly turn the finding into an artifact of a bug.
"""

from __future__ import annotations

import pytest

from bench import algs, hybrid_cms, keymat, pqc_x509
from bench.hybrid_cms import MODES

MESSAGE = b"PQC-VM hybrid signature test document.\n"


@pytest.fixture(scope="module", params=[a.key for a in algs.PQC_ALGS])
def keys(request):
    return keymat.generate(request.param, outdir=None)


@pytest.mark.parametrize("mode", MODES)
def test_roundtrip_accepts(keys, mode):
    art = hybrid_cms.sign(keys, MESSAGE, mode)
    r = hybrid_cms.verify(art, MESSAGE, policy="hybrid")
    assert r["accepted"], r
    assert r["classical_ok"] and r["pqc_ok"]
    assert r["mode"] == mode


@pytest.mark.parametrize("mode", MODES)
def test_wrong_message_rejected(keys, mode):
    art = hybrid_cms.sign(keys, MESSAGE, mode)
    r = hybrid_cms.verify(art, MESSAGE + b"x", policy="hybrid")
    assert not r["accepted"], r


@pytest.mark.parametrize("mode", MODES)
def test_stripping_removes_pqc_half(keys, mode):
    art = hybrid_cms.sign(keys, MESSAGE, mode)
    stripped = hybrid_cms.strip_pqc(art)
    assert len(stripped) < len(art)
    assert not hybrid_cms.verify(stripped, MESSAGE, policy="hybrid")["accepted"]


def test_concat_is_separable(keys):
    """The naive mode: the classical half survives stripping intact."""
    stripped = hybrid_cms.strip_pqc(hybrid_cms.sign(keys, MESSAGE, "concat"))
    r = hybrid_cms.verify(stripped, MESSAGE, policy="classical")
    assert r["accepted"], "concat should remain a valid classical signature"


def test_bound_attr_is_still_separable_under_a_conforming_verifier(keys):
    """The uncomfortable result.

    `bound-attr` commits the classical signature to the PQC public key, but
    RFC 5652 has no criticality flag for signed attributes, so a verifier that
    does not recognise the binding attribute ignores it and accepts. The
    binding is real; it is just not self-enforcing.
    """
    stripped = hybrid_cms.strip_pqc(
        hybrid_cms.sign(keys, MESSAGE, "bound-attr"))
    r = hybrid_cms.verify(stripped, MESSAGE, policy="classical")
    assert r["accepted"], (
        "if this fails, the classical-policy verifier is enforcing more than "
        "RFC 5652 requires and the separability result is not comparable to a "
        "real legacy verifier")


def test_bound_digest_is_not_separable(keys):
    """`bound-digest` fails closed — at the cost of legacy acceptance."""
    art = hybrid_cms.sign(keys, MESSAGE, "bound-digest")
    assert not hybrid_cms.verify(art, MESSAGE, "classical")["accepted"], (
        "bound-digest must also be rejected by a classical verifier on the "
        "*intact* artifact; that is the trade-off being measured")
    stripped = hybrid_cms.strip_pqc(art)
    assert not hybrid_cms.verify(stripped, MESSAGE, "classical")["accepted"]


def test_binding_is_domain_separated(keys):
    """Same keys and document, different mode => different binding value."""
    b1 = hybrid_cms.binding_value("bound-attr", keys.ec_public_raw,
                                  keys.pqc_public, hybrid_cms.sha256(MESSAGE))
    b2 = hybrid_cms.binding_value("bound-digest", keys.ec_public_raw,
                                  keys.pqc_public, hybrid_cms.sha256(MESSAGE))
    assert b1 != b2


def test_binding_commits_to_the_pqc_key(keys):
    """Swapping in a different PQC public key changes the binding."""
    import oqs
    with oqs.Signature(keys.pqc_mech) as other:
        other_pub = other.generate_keypair()
    digest = hybrid_cms.sha256(MESSAGE)
    assert (hybrid_cms.binding_value("bound-attr", keys.ec_public_raw,
                                     keys.pqc_public, digest)
            != hybrid_cms.binding_value("bound-attr", keys.ec_public_raw,
                                        other_pub, digest))


def test_pqc_certificate_self_verifies(keys):
    assert keys.pqc_cert_der is not None
    assert pqc_x509.verify_self_signed(keys.pqc_cert_der, keys.pqc_mech)


@pytest.mark.parametrize("mode", MODES)
def test_substituted_pqc_signature_rejected(keys, mode):
    """A PQC signature over a different document must not be accepted."""
    art = hybrid_cms.sign(keys, MESSAGE, mode)
    other = hybrid_cms.sign(keys, b"a different document", mode)

    from asn1crypto import cms
    from bench.asn1_defs import OID_PQC_SIGNATURE

    donor = cms.ContentInfo.load(other)["content"]["signer_infos"][0]
    donor_attr = [a for a in donor["unsigned_attrs"]
                  if a["type"].dotted == OID_PQC_SIGNATURE][0]

    ci = cms.ContentInfo.load(art)
    si = ci["content"]["signer_infos"][0]
    si["unsigned_attrs"] = cms.CMSAttributes([donor_attr])
    forged = ci.dump()

    assert not hybrid_cms.verify(forged, MESSAGE, "hybrid")["accepted"]
