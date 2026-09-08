"""Run every experiment and render the figures.

    python -m bench.run_all              # full run
    python -m bench.run_all --quick      # smoke run, n=25, for checking wiring

`--quick` numbers are for verifying the pipeline executes. They are not
results and the output records the n it used, so a truncated run cannot be
mistaken for the real thing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import algs, envinfo


def preflight() -> int:
    """Fail loudly before spending an hour measuring the wrong thing."""
    print("preflight:")
    try:
        import oqs
    except Exception as exc:
        print("  FAIL: cannot import oqs: %s: %s" % (type(exc).__name__, exc))
        print("  liboqs-python needs liboqs.so on the loader path. In the")
        print("  container that is /usr/local/lib via LD_LIBRARY_PATH.")
        return 1

    enabled = list(oqs.get_enabled_sig_mechanisms())
    try:
        resolved = algs.resolve_all(enabled)
    except algs.MechanismUnavailable as exc:
        print("  FAIL: %s" % exc)
        return 1
    for k, v in resolved.items():
        print("  %-14s -> %s" % (k, v))

    env = envinfo.collect()
    print("  liboqs        %s" % env["liboqs"])
    print("  openssl CLI   %s" % env["openssl_cli"])
    print("  cpu           %s (%s logical)"
          % (env["cpu_model"], env["cpu_count_logical"]))
    gov = env["cpu_scaling"].get("governor")
    if gov not in (None, "performance", "unavailable"):
        print("  NOTE: cpu governor is %r, not 'performance'. Frequency "
              "scaling widens the latency distribution; the IQR columns will "
              "show it." % gov)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="run the full experiment set")
    ap.add_argument("--quick", action="store_true",
                    help="smoke run with tiny n; not a result")
    ap.add_argument("--out", default="results")
    ap.add_argument("--skip-figures", action="store_true")
    args = ap.parse_args(argv)

    if preflight() != 0:
        return 1

    n_prim = 25 if args.quick else 1000
    n_attack = 5 if args.quick else 200
    budget = 10.0 if args.quick else 60.0

    msg = Path("data/msg.txt")
    if not msg.exists() or msg.stat().st_size == 0:
        print("\nERROR: data/msg.txt is missing or empty. "
              "Run `scripts/gen_payloads.sh` first.")
        return 1

    from . import attack, bench_primitives, cli_overhead

    print("\n[1/4] in-process primitive latency (n=%d per cell)" % n_prim)
    bench_primitives.main(["-n", str(n_prim), "--budget", str(budget),
                           "--out", args.out])

    print("\n[2/4] CLI / process-launch overhead")
    cli_overhead.main(["-n", "50" if args.quick else "200",
                       "--out", args.out])

    print("\n[3/4] hybrid CMS, legacy compatibility, stripping attack")
    attack.main(["-n", str(n_attack), "--budget", str(budget),
                 "--out", args.out])

    if args.skip_figures:
        print("\n[4/4] figures skipped")
        return 0
    print("\n[4/4] figures")
    from . import figures
    figures.main(["--results", args.out,
                  "--out", str(Path(args.out) / "figures")])
    return 0


if __name__ == "__main__":
    sys.exit(main())
