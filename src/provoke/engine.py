"""The scan engine: fan attempts out across the target, judge, collect.

Concurrency is bounded by a semaphore; each attempt is retried on transient
target errors and bounded by a per-call timeout. Target failures become Results
with an `error` set rather than crashing the run — a partial report is more
useful in CI than no report.
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from provoke.detectors.base import Detector
from provoke.models import Attempt, Result, ScanReport
from provoke.probes.base import Probe
from provoke.targets.base import Target


def _utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


async def run_scan(
    target: Target,
    probes: Iterable[Probe],
    detectors: Mapping[str, Detector],
    *,
    concurrency: int = 5,
    retries: int = 2,
    timeout_s: float = 30.0,
) -> ScanReport:
    probe_list = list(probes)
    started_at = _utcnow()
    attempts = _collect_attempts(probe_list)

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run_one(attempt: Attempt) -> Result:
        async with semaphore:
            return await _evaluate(target, attempt, detectors, retries, timeout_s)

    try:
        results = await asyncio.gather(*(run_one(attempt) for attempt in attempts))
    finally:
        # Release pooled connections (e.g. OpenAICompatTarget's AsyncClient).
        aclose = getattr(target, "aclose", None)
        if aclose is not None:
            await aclose()

    return ScanReport(
        target_name=target.name,
        results=tuple(results),
        started_at=started_at,
        finished_at=_utcnow(),
        probe_ids=tuple(probe.id for probe in probe_list),
    )


def _collect_attempts(probe_list: list[Probe]) -> list[Attempt]:
    """Materialise attempts, isolating a faulty probe so it cannot abort the run."""
    attempts: list[Attempt] = []
    for probe in probe_list:
        try:
            attempts.extend(probe.generate())
        except Exception as exc:  # a broken/third-party probe must not kill the scan
            print(
                f"warning: probe '{probe.id}' failed to generate attempts: {exc}",
                file=sys.stderr,
            )
    return attempts


async def _evaluate(
    target: Target,
    attempt: Attempt,
    detectors: Mapping[str, Detector],
    retries: int,
    timeout_s: float,
) -> Result:
    detector = detectors.get(attempt.detector)
    if detector is None:
        return Result(
            attempt=attempt,
            response="",
            succeeded=False,
            score=0.0,
            detector=attempt.detector,
            error=f"no detector registered as '{attempt.detector}'",
        )

    last_error: str | None = None
    for _ in range(max(1, retries + 1)):
        start = time.perf_counter()
        try:
            response = await asyncio.wait_for(
                target.generate(attempt.messages), timeout=timeout_s
            )
        except TimeoutError:
            last_error = f"timed out after {timeout_s}s"
            continue
        except Exception as exc:  # normalise all target failures
            last_error = str(exc) or exc.__class__.__name__
            continue

        latency_ms = (time.perf_counter() - start) * 1000.0
        succeeded, score = detector.evaluate(attempt, response)
        return Result(
            attempt=attempt,
            response=response,
            succeeded=succeeded,
            score=score,
            detector=attempt.detector,
            latency_ms=latency_ms,
        )

    return Result(
        attempt=attempt,
        response="",
        succeeded=False,
        score=0.0,
        detector=attempt.detector,
        error=last_error,
    )
