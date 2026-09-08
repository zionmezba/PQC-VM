"""Algorithm registry.

liboqs mechanism names have changed across releases (Dilithium3 -> ML-DSA-65
when FIPS 204 landed), so nothing here hardcodes a single spelling. Each entry
carries a candidate list that is resolved against
``oqs.get_enabled_sig_mechanisms()`` for the liboqs build actually loaded, and
resolution failure is a hard error rather than a silent fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PqcAlg:
    key: str                    # stable identifier used in output files
    label: str                  # human-readable, for figures
    candidates: tuple[str, ...]  # liboqs mechanism names, most-preferred first
    oid: str                    # X.509 signatureAlgorithm OID
    oid_registered: bool        # False => private/experimental arc


# NIST assigned OIDs under 2.16.840.1.101.3.4.3 for the standardised schemes.
# Falcon (FN-DSA) has no published FIPS OID at time of writing; the value below
# is the Open Quantum Safe private-arc codepoint and is NOT registered. Any
# table in the manuscript that lists it must say so.
PQC_ALGS: tuple[PqcAlg, ...] = (
    PqcAlg(
        key="mldsa65",
        label="ML-DSA-65",
        candidates=("ML-DSA-65", "Dilithium3"),
        oid="2.16.840.1.101.3.4.3.18",
        oid_registered=True,
    ),
    PqcAlg(
        key="falcon512",
        label="Falcon-512",
        candidates=("Falcon-512", "falcon512"),
        oid="1.3.9999.3.11",
        oid_registered=False,
    ),
    PqcAlg(
        key="sphincs128s",
        label="SPHINCS+-SHA2-128s-simple",
        candidates=(
            "SPHINCS+-SHA2-128s-simple",
            "SPHINCS+-SHA2-128s-robust",
            "SPHINCS+-SHA2-128s",
        ),
        oid="2.16.840.1.101.3.4.3.20",  # id-slh-dsa-sha2-128s
        oid_registered=True,
    ),
)

BY_KEY = {a.key: a for a in PQC_ALGS}


class MechanismUnavailable(RuntimeError):
    pass


def resolve(alg: PqcAlg, enabled: list[str]) -> str:
    """Return the mechanism name this liboqs build actually exposes."""
    for name in alg.candidates:
        if name in enabled:
            return name
    raise MechanismUnavailable(
        f"{alg.label}: none of {alg.candidates} are enabled in this liboqs "
        f"build. Enabled signature mechanisms: {sorted(enabled)}"
    )


def resolve_all(enabled: list[str]) -> dict[str, str]:
    """Map registry key -> live liboqs mechanism name, or raise."""
    return {a.key: resolve(a, enabled) for a in PQC_ALGS}
