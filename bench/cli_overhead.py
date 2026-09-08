"""Task 2: quantify the process-launch overhead that CLI benchmarking measures.

This is a reported result, not a caveat. The original harness bracketed an
`openssl` invocation with two `python3` startups and recorded 176-214 ms for a
verification whose actual cost is tens of microseconds. This module measures
each component of that overhead separately so the inflation factor can be
stated with a number attached rather than asserted.

Components measured (each a real subprocess, timed end to end):

  python3_startup        `python3 -c pass` -- interpreter start + teardown
  openssl_legacy         `openssl version`, default providers only
  openssl_oqs            `openssl version` with oqsprovider.so activated;
                         the delta against openssl_legacy is the cost of
                         dlopen'ing and initialising the PQC provider
  shell_roundtrip        `sh -c true` -- the fork/exec floor

Everything here is deliberately *outside* the in-process harness. n is lower
than for the primitives because each sample costs milliseconds, not
microseconds; n is still reported per row.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

from . import envinfo


def _time_subprocess(cmd, env, n, warmup):
    for _ in range(warmup):
        subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        samples.append(time.perf_counter_ns() - t0)
    return samples


def _stats(samples):
    import statistics
    us = sorted(s / 1000.0 for s in samples)
    q = statistics.quantiles(us, n=100, method="inclusive")
    return {
        "n": len(us),
        "median_us": statistics.median(us),
        "mean_us": statistics.fmean(us),
        "stdev_us": statistics.stdev(us) if len(us) > 1 else 0.0,
        "iqr_us": q[74] - q[24],
        "p95_us": q[94],
        "min_us": us[0],
        "max_us": us[-1],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="measure CLI/process overhead")
    ap.add_argument("-n", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--out", default="results")
    ap.add_argument("--oqs-conf", default="config/openssl-oqs.cnf",
                    help="OPENSSL_CONF that activates oqsprovider")
    args = ap.parse_args(argv)

    base_env = dict(os.environ)
    base_env.pop("OPENSSL_CONF", None)          # legacy profile
    oqs_env = dict(os.environ)
    oqs_env["OPENSSL_CONF"] = str(Path(args.oqs_conf).resolve())

    cases = [
        ("shell_roundtrip", ["sh", "-c", "true"], base_env),
        ("python3_startup", ["python3", "-c", "pass"], base_env),
        ("openssl_legacy", ["openssl", "version"], base_env),
        ("openssl_oqs", ["openssl", "version"], oqs_env),
    ]

    rows = []
    for name, cmd, env in cases:
        try:
            st = _stats(_time_subprocess(cmd, env, args.n, args.warmup))
        except FileNotFoundError:
            rows.append({"case": name, "error": "executable not found"})
            continue
        st["case"] = name
        st["command"] = " ".join(cmd)
        rows.append(st)

    doc = {"environment": envinfo.collect(), "rows": rows}

    by = {r["case"]: r for r in rows if "median_us" in r}
    if "openssl_oqs" in by and "openssl_legacy" in by:
        doc["provider_load_cost_us"] = (
            by["openssl_oqs"]["median_us"] - by["openssl_legacy"]["median_us"])

    # Inflation factor against the in-process figures, if Task 1 has been run.
    prim = Path(args.out) / "primitives.json"
    if prim.exists() and "openssl_legacy" in by:
        data = json.loads(prim.read_text())
        floor = by["openssl_legacy"]["median_us"]
        comparisons = []
        for r in data["rows"]:
            if r.get("operation") == "verify_digest":
                comparisons.append({
                    "algorithm": r["algorithm"],
                    "in_process_verify_median_us": r["median_us"],
                    "single_openssl_invocation_median_us": floor,
                    "inflation_factor": floor / r["median_us"],
                })
        doc["inflation_vs_in_process_verify"] = comparisons

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cli_overhead.json").write_text(json.dumps(doc, indent=2))
    print("wrote %s" % (out / "cli_overhead.json"))
    for r in rows:
        if "median_us" in r:
            print("  %-18s median %9.1f us  (n=%d)"
                  % (r["case"], r["median_us"], r["n"]))
        else:
            print("  %-18s %s" % (r["case"], r.get("error")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
