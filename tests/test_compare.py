from __future__ import annotations

import pytest

from provoke.compare import (
    IMPROVEMENT,
    NEW,
    REGRESSION,
    CompareError,
    diff_reports,
    evaluate_compare_gate,
    load_report,
)


def _report(target: str, asr: float, results: list[dict]) -> dict:
    return {"target": target, "summary": {"asr": asr}, "results": results}


def _r(rid: str, succeeded: bool, error: str | None = None) -> dict:
    return {
        "id": rid, "probe": rid.split(":")[0], "technique": "t",
        "succeeded": succeeded, "error": error,
    }


def test_detects_regression_and_gate_fails():
    base = _report("m", 0.0, [_r("p:0", False)])
    curr = _report("m", 1.0, [_r("p:0", True)])
    diff = diff_reports(base, curr)
    assert [d.change for d in diff.regressions] == [REGRESSION]
    passed, reasons = evaluate_compare_gate(diff)
    assert passed is False and reasons


def test_improvement_passes_gate():
    base = _report("m", 1.0, [_r("p:0", True)])
    curr = _report("m", 0.0, [_r("p:0", False)])
    diff = diff_reports(base, curr)
    assert len(diff.improvements) == 1 and diff.improvements[0].change == IMPROVEMENT
    assert evaluate_compare_gate(diff)[0] is True


def test_unchanged_passes():
    base = _report("m", 0.0, [_r("p:0", False)])
    diff = diff_reports(base, base)
    assert not diff.regressions
    assert evaluate_compare_gate(diff)[0] is True


def test_new_finding_reported_but_does_not_fail_gate():
    base = _report("m", 0.0, [_r("p:0", False)])
    curr = _report("m", 0.5, [_r("p:0", False), _r("q:0", True)])
    diff = diff_reports(base, curr)
    assert [d.change for d in diff.new_findings] == [NEW]
    assert evaluate_compare_gate(diff)[0] is True  # new != regression


def test_error_is_inconclusive_not_regression():
    base = _report("m", 0.0, [_r("p:0", False)])
    curr = _report("m", 0.0, [_r("p:0", False, error="timeout")])
    diff = diff_reports(base, curr)
    assert not diff.regressions
    assert evaluate_compare_gate(diff)[0] is True


def test_load_report_rejects_missing_and_malformed(tmp_path):
    with pytest.raises(CompareError):
        load_report(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{}")  # valid JSON but not a report
    with pytest.raises(CompareError):
        load_report(bad)
