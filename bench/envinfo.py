"""Environment metadata recorded alongside every measurement.

A latency number without the machine it was taken on is not a result.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _cpu_mhz_governor() -> dict[str, str]:
    """Frequency scaling state — turbo/boost is the usual source of drift."""
    out: dict[str, str] = {}
    for label, path in (
        ("governor", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        ("max_freq_khz", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"),
    ):
        try:
            with open(path, encoding="utf-8") as fh:
                out[label] = fh.read().strip()
        except OSError:
            out[label] = "unavailable"
    return out


def _liboqs_version() -> str:
    try:
        import oqs
    except Exception as exc:  # pragma: no cover - import failure is reported
        return f"unavailable ({type(exc).__name__})"
    for attr in ("oqs_version", "oqs_python_version"):
        fn = getattr(oqs, attr, None)
        if callable(fn):
            try:
                return str(fn())
            except Exception:
                continue
    return "unknown"


def _liboqs_python_version() -> str:
    try:
        import oqs
        fn = getattr(oqs, "oqs_python_version", None)
        return str(fn()) if callable(fn) else "unknown"
    except Exception as exc:
        return f"unavailable ({type(exc).__name__})"


def _openssl_cli_version() -> str:
    """Version of the openssl *binary*, which is not necessarily the version
    the `cryptography` wheel is linked against."""
    try:
        r = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, timeout=30
        )
        return r.stdout.strip() or "unknown"
    except Exception as exc:
        return f"unavailable ({type(exc).__name__})"


def _oqs_provider_available(env: dict | None = None) -> bool:
    """True iff the openssl CLI, under `env`, lists a PQC signature algorithm.

    This is the switch RQ1 turns on and off, and it must be probed rather than
    assumed: a misconfigured provider module path makes `openssl` skip the
    provider silently, with exit code 0 and no diagnostic, so a run can believe
    it is exercising the PQC-aware profile while actually running the legacy
    one.
    """
    try:
        r = subprocess.run(
            ["openssl", "list", "-signature-algorithms"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        return bool(re.search(r"mldsa|ml-dsa|dilithium|falcon|sphincs|slh-dsa",
                              r.stdout, re.IGNORECASE))
    except Exception:
        return False


def _oqs_profile_probe(conf: str = "config/openssl-oqs.cnf") -> dict:
    """Probe both OpenSSL profiles the experiments switch between.

    Recording only the ambient profile is not enough: it is unset by design, so
    it always reports False and tells a reader nothing about whether the
    PQC-aware column in the results was real.
    """
    path = os.path.abspath(conf)
    if not os.path.exists(path):
        return {"conf_path": path, "conf_present": False, "loaded": False}
    env = dict(os.environ)
    env["OPENSSL_CONF"] = path
    return {
        "conf_path": path,
        "conf_present": True,
        "loaded": _oqs_provider_available(env),
    }


def collect() -> dict:
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "cpu_model": _cpu_model(),
        "cpu_count_logical": os.cpu_count(),
        "cpu_scaling": _cpu_mhz_governor(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "liboqs": _liboqs_version(),
        "liboqs_python": _liboqs_python_version(),
        "openssl_cli": _openssl_cli_version(),
        "openssl_conf": os.environ.get("OPENSSL_CONF", "<unset: legacy profile>"),
        # Ambient profile. Expected False: the container leaves OPENSSL_CONF
        # unset so the legacy, PQC-blind verifier is what you get by default.
        "oqs_provider_loaded": _oqs_provider_available(),
        # PQC-aware profile, probed explicitly. This is the one that has to be
        # True for any openssl_oqs column in the results to mean anything.
        "oqs_profile": _oqs_profile_probe(),
        "cryptography": _pkg_version("cryptography"),
        "asn1crypto": _pkg_version("asn1crypto"),
    }


def _pkg_version(name: str) -> str:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception as exc:
        return f"unavailable ({type(exc).__name__})"
