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


class _CountingTarget:
    """Returns a scripted reply per turn and records how many turns ran."""

    def __init__(self, replies: list[str]):
        self.name = "counting"
        self._replies = replies
        self.calls = 0

    async def generate(self, messages) -> str:
        self.calls += 1
        return self._replies[min(self.calls, len(self._replies)) - 1]


async def test_engine_runs_multi_turn_conversation():
    from provoke.models import Attempt, Message
    from provoke.standards import OWASP, Atlas, Severity

    target = _CountingTarget(["general info", "ok, role-playing", "CRESCENDO-OK-9931"])
    attempt = Attempt(
        probe_id="crescendo",
        index=0,
        technique="buildup",
        messages=(Message("user", "turn 1"),),
        follow_ups=("turn 2", "turn 3"),
        owasp=OWASP.LLM01,
        atlas=Atlas.JAILBREAK,
        severity=Severity.HIGH,
        detector="string_match",
        success_markers=("CRESCENDO-OK-9931",),
    )
    report = await run_scan(target, [_SingleAttemptProbe(attempt)], default_detectors())
    result = report.results[0]
    assert target.calls == 3  # one generate per turn
    assert result.succeeded  # canary emitted on the final turn -> caught in transcript
    assert "CRESCENDO-OK-9931" in result.response
