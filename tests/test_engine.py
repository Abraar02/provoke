from __future__ import annotations

from provoke.detectors import default_detectors
from provoke.engine import run_scan
from provoke.probes import all_probes
from provoke.targets.mock import MockTarget
from tests.conftest import ScriptedTarget, make_attempt


class _SingleAttemptProbe:
    id = "single"
    name = "single"
    description = "one attempt"

    def __init__(self, attempt):
        self._attempt = attempt

    def generate(self):
        yield self._attempt


async def test_run_scan_against_mock_produces_results():
    report = await run_scan(MockTarget(profile="moderate"), all_probes(), default_detectors())
    assert len(report.results) == sum(len(list(p.generate())) for p in all_probes())
    assert report.target_name == "mock-llm"
    # moderate target must fall for at least one indirect injection.
    assert any(r.succeeded for r in report.results)


async def test_engine_retries_then_succeeds():
    target = ScriptedTarget("ok answer", fail_times=1)
    probe = _SingleAttemptProbe(make_attempt(detector="refusal"))
    report = await run_scan(target, [probe], default_detectors(), retries=2)
    result = report.results[0]
    assert result.error is None
    assert target.calls == 2  # one failure + one success


async def test_engine_records_error_after_exhausting_retries():
    target = ScriptedTarget(fail_times=99)
    probe = _SingleAttemptProbe(make_attempt())
    report = await run_scan(target, [probe], default_detectors(), retries=1)
    result = report.results[0]
    assert result.errored
    assert result.succeeded is False


async def test_engine_handles_unknown_detector():
    probe = _SingleAttemptProbe(make_attempt(detector="nope"))
    report = await run_scan(MockTarget(), [probe], default_detectors())
    assert report.results[0].error is not None
