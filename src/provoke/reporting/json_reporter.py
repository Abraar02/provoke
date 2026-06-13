"""Machine-readable JSON report — the full record, for tooling and diffing."""

from __future__ import annotations

import json

from provoke.models import Result, ScanReport
from provoke.reporting.aggregate import Summary


def render(report: ScanReport, summary: Summary) -> str:
    obj = {
        "tool": "provoke",
        "target": report.target_name,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "probes": list(report.probe_ids),
        "summary": {
            "total": summary.total,
            "scored": summary.scored,
            "succeeded": summary.succeeded,
            "errors": summary.errors,
            "asr": round(summary.asr, 4),
            "by_owasp": [
                {"owasp": owasp, "succeeded": succ, "scored": scored}
                for owasp, succ, scored in summary.by_owasp
            ],
            "by_probe": [
                {
                    "probe": stat.probe_id,
                    "owasp": stat.owasp,
                    "atlas": stat.atlas,
                    "severity": stat.severity.value,
                    "total": stat.total,
                    "succeeded": stat.succeeded,
                    "errors": stat.errors,
                    "asr": round(stat.asr, 4),
                }
                for stat in summary.by_probe
            ],
        },
        "results": [_result_to_dict(result) for result in report.results],
    }
    return json.dumps(obj, indent=2)


def _result_to_dict(result: Result) -> dict[str, object]:
    attempt = result.attempt
    return {
        "id": attempt.id,
        "probe": attempt.probe_id,
        "technique": attempt.technique,
        "owasp": attempt.owasp.value,
        "atlas": attempt.atlas.value,
        "severity": attempt.severity.value,
        "detector": result.detector,
        "succeeded": result.succeeded,
        "score": round(result.score, 4),
        "latency_ms": round(result.latency_ms, 1),
        "error": result.error,
        "prompt": attempt.prompt,
        "response": result.response,
    }
