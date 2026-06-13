from __future__ import annotations

import json

import pytest

from provoke.models import Result, ScanReport
from provoke.reporting import (
    Thresholds,
    evaluate_gate,
    render_report,
    summarize,
)
from provoke.standards import Severity
from tests.conftest import make_attempt


def test_result_rejects_errored_success():
    attempt = make_attempt()
    with pytest.raises(ValueError, match="errored and succeeded"):
        Result(attempt, "", True, 1.0, "refusal", error="boom")


def _report(*results: Result) -> ScanReport:
    return ScanReport(
        target_name="t",
        results=tuple(results),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        probe_ids=("test",),
    )


def _result(succeeded: bool, *, error: str | None = None, probe="test") -> Result:
    attempt = make_attempt(probe_id=probe, markers=("PWNED",), detector="string_match")
    score = 1.0 if succeeded else 0.0
    return Result(attempt, "resp", succeeded, score, "string_match", error=error)


def test_summarize_asr_excludes_errors():
    report = _report(_result(True), _result(False), _result(False, error="boom"))
    summary = summarize(report)
    assert summary.total == 3
    assert summary.errors == 1
    assert summary.scored == 2
    assert summary.asr == 0.5  # 1 success / 2 scored


def test_gate_fails_when_asr_exceeds_threshold():
    summary = summarize(_report(_result(True), _result(False)))
    passed, reasons = evaluate_gate(summary, Thresholds(max_asr=0.0))
    assert passed is False and reasons


def test_gate_passes_when_under_threshold():
    summary = summarize(_report(_result(False), _result(False)))
    passed, reasons = evaluate_gate(summary, Thresholds(max_asr=0.0))
    assert passed is True and not reasons


def test_gate_fails_when_all_attempts_errored():
    # An unreachable target must never yield a passing gate (the silent-pass bug).
    summary = summarize(_report(_result(False, error="boom"), _result(False, error="boom")))
    passed, reasons = evaluate_gate(summary, Thresholds(max_asr=0.0))
    assert passed is False
    assert any("no attempts completed" in r for r in reasons)


def test_gate_fails_when_error_rate_exceeds_max():
    summary = summarize(_report(_result(False), _result(False, error="boom")))
    passed, reasons = evaluate_gate(summary, Thresholds(max_asr=1.0, max_error_rate=0.4))
    assert passed is False
    assert any("error rate" in r for r in reasons)


def test_per_owasp_threshold():
    summary = summarize(_report(_result(True), _result(True)))
    thresholds = Thresholds(max_asr=1.0, per_owasp={"LLM01:2025 Prompt Injection": 0.5})
    passed, reasons = evaluate_gate(summary, thresholds)
    assert passed is False
    assert any("LLM01" in r for r in reasons)


def test_json_report_is_valid_and_complete():
    report = _report(_result(True), _result(False))
    summary = summarize(report)
    obj = json.loads(render_report("json", report, summary))
    assert obj["tool"] == "provoke"
    assert obj["summary"]["asr"] == 0.5
    assert len(obj["results"]) == 2


def test_markdown_report_contains_key_sections():
    report = _report(_result(True))
    md = render_report("markdown", report, summarize(report), gate_passed=False)
    assert "Provoke LLM Red-Team Report" in md
    assert "Results by probe" in md
    assert "GATE FAILED" in md


def test_sarif_report_structure():
    report = _report(_result(True), _result(False))
    sarif = json.loads(render_report("sarif", report, summarize(report), source_uri="provoke.yaml"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Provoke"
    # only the succeeded result becomes an alert
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "test"


def test_severity_ordering_in_summary():
    low = Result(make_attempt(severity=Severity.LOW), "r", False, 0.0, "refusal")
    crit = Result(make_attempt(severity=Severity.CRITICAL, index=1), "r", True, 1.0, "refusal")
    summary = summarize(_report(low, crit))
    assert summary.by_probe[0].severity is Severity.CRITICAL
