"""In-process timing harness.

Rules this module exists to enforce:

  * Nothing is forked, exec'd, or imported inside the timed region. The timed
    region contains one call to the operation under test and nothing else.
  * Every operation is warmed up before the first recorded sample, so that
    lazy allocation, page faults on first touch, and branch-predictor warmup
    land outside the measurement.
  * Every reported latency carries n, median, and a dispersion measure. The
    mean is deliberately *not* the headline statistic: these distributions are
    right-skewed by scheduler preemption, and a mean invites the reader to
    assume a symmetric error bar that is not there.

`time.perf_counter_ns` is the clock: monotonic, nanosecond-resolution, and it
does not fold in time spent suspended the way `process_time` excludes it.
"""

from __future__ import annotations

import gc
import statistics
import time
from dataclasses import dataclass, asdict
from typing import Callable


@dataclass
class Stats:
    n: int
    warmup: int
    median_us: float
    mean_us: float
    stdev_us: float
    iqr_us: float
    p95_us: float
    p99_us: float
    min_us: float
    max_us: float
    total_wall_s: float
    truncated: bool          # True if the iteration budget cut n below target
    target_n: int

    def as_dict(self) -> dict:
        return asdict(self)


def _summarise(samples_ns: list[int], warmup: int, target_n: int,
               truncated: bool, wall_s: float) -> Stats:
    us = sorted(s / 1_000.0 for s in samples_ns)
    n = len(us)
    q = statistics.quantiles(us, n=100, method="inclusive") if n >= 2 else [us[0]] * 99
    return Stats(
        n=n,
        warmup=warmup,
        median_us=statistics.median(us),
        mean_us=statistics.fmean(us),
        stdev_us=statistics.stdev(us) if n >= 2 else 0.0,
        iqr_us=q[74] - q[24],
        p95_us=q[94],
        p99_us=q[98],
        min_us=us[0],
        max_us=us[-1],
        total_wall_s=wall_s,
        truncated=truncated,
        target_n=target_n,
    )


def measure(fn: Callable[[], object], *, n: int = 1000, warmup: int = 50,
            budget_s: float | None = None) -> Stats:
    """Time `fn` n times after `warmup` untimed calls.

    `budget_s` caps total wall time. SPHINCS+-128s signing costs on the order
    of half a second per call, so an unconditional n=1000 would run for hours;
    when the budget bites, `n` is reduced and `truncated` is set so the shortfall
    is visible in the output rather than hidden. It is never silently rounded up.

    The garbage collector is disabled across the measurement: a collection
    landing inside one sample would otherwise show up as a multi-millisecond
    outlier attributable to Python, not to the cryptography.
    """
    if n < 1:
        raise ValueError("n must be >= 1")

    for _ in range(warmup):
        fn()

    samples: list[int] = []
    truncated = False
    gc_was_enabled = gc.isenabled()
    gc.disable()
    wall_start = time.perf_counter()
    try:
        for i in range(n):
            t0 = time.perf_counter_ns()
            fn()
            t1 = time.perf_counter_ns()
            samples.append(t1 - t0)
            if budget_s is not None and (i & 0x0F) == 0:
                if time.perf_counter() - wall_start > budget_s:
                    truncated = True
                    break
    finally:
        wall_s = time.perf_counter() - wall_start
        if gc_was_enabled:
            gc.enable()
            gc.collect()

    return _summarise(samples, warmup, n, truncated, wall_s)
