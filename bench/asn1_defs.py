"""ASN.1 definitions for the hybrid CMS artifacts, and their registration into
asn1crypto's OID tables.

OID policy
----------
Everything under 1.3.6.1.4.1.59999 is an **unregistered, experimental** arc
chosen for this study. It is not an IANA/ITU assignment and must never be
presented as one. Any table or figure that names these attributes has to say
"experimental" next to them. The PQC *algorithm* OIDs in bench/algs.py are a
separate matter: ML-DSA and SLH-DSA carry real NIST assignments, Falcon does
not.

Design note: why an unsigned attribute
--------------------------------------
RFC 5652 gives three places a second signature could live:

  1. A second SignerInfo. Standards-clean, but a legacy verifier that iterates
     SignerInfos will hit an unparseable algorithm and, depending on the
     implementation, either fail the whole SignedData or silently skip it. The
     behaviour is not portable, which makes it a poor basis for RQ1.
  2. A signed attribute. Covered by the classical signature, but then the
     classical signature depends on the PQC signature, which does not exist
     yet when the attribute is built -- circular.
  3. An unsigned attribute. Not covered by the classical signature, freely
     strippable, and ignored by every conforming legacy verifier.

We use (3), and the fact that it is freely strippable is not a flaw in the
encoding -- it is the finding. See bench/hybrid_cms.py for how the `bound`
modes attempt to close that gap, and bench/attack.py for how far they get.
"""

from __future__ import annotations

from asn1crypto import cms, core

ARC = "1.3.6.1.4.1.59999.1"

OID_PQC_SIGNATURE = ARC + ".1"   # unsigned attribute: the PQC half
OID_HYBRID_BINDING = ARC + ".2"  # signed attribute: the binding value

ATTR_NAME_PQC = "pqc_signature"
ATTR_NAME_BINDING = "hybrid_binding"


class PqcAlgorithmIdentifier(core.Sequence):
    _fields = [
        ("algorithm", core.ObjectIdentifier),
        ("parameters", core.Any, {"optional": True}),
    ]


class PqcSignatureValue(core.Sequence):
    """The PQC half of a hybrid signature, carried as one unsigned attribute.

    `mode` is recorded in the artifact rather than inferred by the verifier.
    A verifier that had to guess which binding rule applied could be steered
    into checking the weaker one by an attacker who rewrote the field -- but
    `mode` is also folded into the binding preimage for the bound modes, so
    rewriting it there invalidates both halves. Under `concat` there is nothing
    to protect and nothing is claimed.
    """

    _fields = [
        ("version", core.Integer),
        ("mode", core.UTF8String),
        ("algorithm", PqcAlgorithmIdentifier),
        ("public_key", core.OctetString),
        ("signature", core.OctetString),
        ("certificate", core.OctetString, {"implicit": 0, "optional": True}),
    ]


class SetOfPqcSignatureValue(core.SetOf):
    _child_spec = PqcSignatureValue


class SetOfOctetString(core.SetOf):
    _child_spec = core.OctetString


def register() -> None:
    """Teach asn1crypto our two attribute types.

    Idempotent: importing this module twice, or importing it after another
    module already registered, must not raise.
    """
    cms.CMSAttributeType._map.setdefault(OID_PQC_SIGNATURE, ATTR_NAME_PQC)
    cms.CMSAttributeType._map.setdefault(OID_HYBRID_BINDING, ATTR_NAME_BINDING)
    cms.CMSAttribute._oid_specs.setdefault(ATTR_NAME_PQC, SetOfPqcSignatureValue)
    cms.CMSAttribute._oid_specs.setdefault(ATTR_NAME_BINDING, SetOfOctetString)


register()
