"""Report rendering dispatch."""

from __future__ import annotations

from provoke.models import ScanReport
from provoke.reporting import json_reporter, markdown_reporter, sarif_reporter
from provoke.reporting.aggregate import (
    ProbeStat,
    Summary,
    Thresholds,
    evaluate_gate,
    summarize,
)

__all__ = [
    "ProbeStat",
    "Summary",
    "Thresholds",
    "evaluate_gate",
    "summarize",
    "render_report",
    "file_extension",
]

_EXTENSIONS = {"json": "json", "markdown": "md", "sarif": "sarif"}


def render_report(
    fmt: str,
    report: ScanReport,
    summary: Summary,
    *,
    source_uri: str = "provoke.yaml",
    gate_passed: bool | None = None,
) -> str:
    if fmt == "json":
        return json_reporter.render(report, summary)
    if fmt == "markdown":
        return markdown_reporter.render(report, summary, gate_passed=gate_passed)
    if fmt == "sarif":
        return sarif_reporter.render(report, summary, source_uri=source_uri)
    raise ValueError(f"unknown report format: {fmt!r}")


def file_extension(fmt: str) -> str:
    return _EXTENSIONS.get(fmt, fmt)
