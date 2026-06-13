"""SARIF 2.1.0 report — uploadable to GitHub code scanning (the Security tab).

Each probe becomes a SARIF rule; each successful attack becomes a result, so
LLM vulnerabilities surface as code-scanning alerts alongside SAST findings.
This is what lets Provoke act like a first-class security scanner in CI.
"""

from __future__ import annotations

import json

from provoke import __version__
from provoke.models import ScanReport
from provoke.reporting.aggregate import Summary

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Abraar02/provoke"


def render(report: ScanReport, summary: Summary, *, source_uri: str = "provoke.yaml") -> str:
    rules = [
        {
            "id": stat.probe_id,
            "name": stat.probe_id,
            "shortDescription": {"text": f"{stat.owasp}"},
            "helpUri": _INFO_URI,
            "properties": {
                "owasp": stat.owasp,
                "atlas": stat.atlas,
                "security-severity": _security_severity(stat.severity.value),
                "tags": ["llm", "security", "red-team"],
            },
        }
        for stat in summary.by_probe
    ]

    results = []
    for result in report.results:
        if not result.succeeded:
            continue
        attempt = result.attempt
        results.append(
            {
                "ruleId": attempt.probe_id,
                "level": attempt.severity.sarif_level,
                "message": {
                    "text": (
                        f"{attempt.technique}: {attempt.owasp.value} attack succeeded "
                        f"(detector={result.detector}, score={result.score:.2f})."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "attempt_id": attempt.id,
                    "atlas": attempt.atlas.value,
                    "severity": attempt.severity.value,
                },
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Provoke",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _security_severity(severity: str) -> str:
    # GitHub uses a 0.0-10.0 numeric scale to sort code-scanning alerts.
    return {
        "low": "3.0",
        "medium": "5.5",
        "high": "8.0",
        "critical": "9.5",
    }.get(severity, "5.0")
