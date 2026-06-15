"""Baseline diffing: compare a current scan report against a saved baseline.

The point is regression detection. An absolute ASR gate answers "is the target
secure enough right now?"; a baseline diff answers "did this change make it
*worse* than before?" — which is what catches a model swap or a prompt edit
silently re-opening a hole. A probe that was resisted in the baseline but
succeeds now is a REGRESSION (the gate's failure condition); the reverse is an
IMPROVEMENT.

Attempts are matched by id (probe:index), so a baseline and a current report
must come from the same probe set to line up.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Change classifications.
REGRESSION = "regression"  # resisted -> succeeded (bad)
IMPROVEMENT = "improvement"  # succeeded -> resisted (good)
UNCHANGED = "unchanged"
INCONCLUSIVE = "inconclusive"  # an error on either side; can't compare
NEW = "new"  # only in current, and it succeeded (a finding the baseline didn't test)
ADDED = "added"  # only in current, resisted/errored
DROPPED = "dropped"  # only in baseline


class CompareError(ValueError):
    """Raised when a report cannot be loaded or is malformed."""


@dataclass(frozen=True, slots=True)
class AttemptDiff:
    id: str
    probe: str
    technique: str
    baseline: str  # succeeded | resisted | errored | absent
    current: str
    change: str


@dataclass(frozen=True, slots=True)
class ScanDiff:
    baseline_target: str
    current_target: str
    baseline_asr: float
    current_asr: float
    diffs: tuple[AttemptDiff, ...]

    @property
    def regressions(self) -> tuple[AttemptDiff, ...]:
        return tuple(d for d in self.diffs if d.change == REGRESSION)

    @property
    def improvements(self) -> tuple[AttemptDiff, ...]:
        return tuple(d for d in self.diffs if d.change == IMPROVEMENT)

    @property
    def new_findings(self) -> tuple[AttemptDiff, ...]:
        return tuple(d for d in self.diffs if d.change == NEW)


def _state(result: dict[str, Any]) -> str:
    if result.get("error"):
        return "errored"
    return "succeeded" if result.get("succeeded") else "resisted"


def _classify(baseline: str, current: str) -> str:
    if "errored" in (baseline, current):
        return INCONCLUSIVE
    if baseline == "resisted" and current == "succeeded":
        return REGRESSION
    if baseline == "succeeded" and current == "resisted":
        return IMPROVEMENT
    return UNCHANGED


def load_report(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise CompareError(f"report not found: {file_path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CompareError(f"invalid JSON report {file_path}: {exc}") from exc
    if not isinstance(data, dict) or "results" not in data:
        raise CompareError(f"{file_path} is not a Provoke JSON report (missing 'results')")
    return data


def diff_reports(baseline: dict[str, Any], current: dict[str, Any]) -> ScanDiff:
    base = {r["id"]: r for r in baseline.get("results", [])}
    curr = {r["id"]: r for r in current.get("results", [])}

    diffs: list[AttemptDiff] = []
    for cid, cres in curr.items():
        cstate = _state(cres)
        if cid in base:
            bstate = _state(base[cid])
            change = _classify(bstate, cstate)
        else:
            bstate = "absent"
            change = NEW if cstate == "succeeded" else ADDED
        diffs.append(
            AttemptDiff(
                cid, cres.get("probe", ""), cres.get("technique", ""), bstate, cstate, change
            )
        )

    for bid, bres in base.items():
        if bid not in curr:
            diffs.append(
                AttemptDiff(
                    bid, bres.get("probe", ""), bres.get("technique", ""),
                    _state(bres), "absent", DROPPED,
                )
            )

    # Surface the actionable changes first.
    order = {
        REGRESSION: 0, NEW: 1, IMPROVEMENT: 2, INCONCLUSIVE: 3,
        ADDED: 4, DROPPED: 5, UNCHANGED: 6,
    }
    diffs.sort(key=lambda d: (order.get(d.change, 9), d.id))

    return ScanDiff(
        baseline_target=str(baseline.get("target", "")),
        current_target=str(current.get("target", "")),
        baseline_asr=float(baseline.get("summary", {}).get("asr", 0.0)),
        current_asr=float(current.get("summary", {}).get("asr", 0.0)),
        diffs=tuple(diffs),
    )


def evaluate_compare_gate(diff: ScanDiff) -> tuple[bool, tuple[str, ...]]:
    """Fail when the current report regressed against the baseline."""
    reasons: list[str] = []
    if diff.regressions:
        reasons.append(
            f"{len(diff.regressions)} regression(s): "
            + ", ".join(d.id for d in diff.regressions)
        )
    return (not reasons, tuple(reasons))
