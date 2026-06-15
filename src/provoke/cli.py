"""Command-line interface: `provoke scan`, `provoke compare`, `provoke list-probes`.

Exit codes:
  0  ran and the gate passed (or --no-fail was set)
  1  gate failed — ASR over threshold, or a regression vs the baseline — fail CI
  2  usage / configuration error
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from provoke import __version__
from provoke.compare import (
    CompareError,
    ScanDiff,
    diff_reports,
    evaluate_compare_gate,
    load_report,
)
from provoke.config import Config, ConfigError, ReportConfig, TargetConfig, load_config
from provoke.detectors import default_detectors
from provoke.engine import run_scan
from provoke.models import ScanReport
from provoke.probes import all_probes, resolve_probes
from provoke.reporting import (
    Summary,
    evaluate_gate,
    file_extension,
    render_report,
    summarize,
)
from provoke.reporting.diff_reporter import render_diff
from provoke.targets import TargetError, build_target

try:
    from rich.console import Console
    from rich.table import Table

    _console: Console | None = Console()
except Exception:  # rich is optional at runtime
    _console = None


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "compare":
        return _cmd_compare(args)
    if args.command == "list-probes":
        return _cmd_list_probes()
    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provoke", description="Continuous LLM red-teaming.")
    parser.add_argument("--version", action="version", version=f"provoke {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a red-team scan against a target")
    scan.add_argument("-c", "--config", default="provoke.yaml", help="path to config YAML")
    scan.add_argument("-o", "--output", help="override report output directory")
    scan.add_argument("--format", help="comma-separated formats (markdown,json,sarif)")
    scan.add_argument("--profile", help="override mock target profile")
    scan.add_argument("--baseline", help="JSON report to diff against; fail on regressions")
    scan.add_argument("--no-fail", action="store_true", help="always exit 0 even if the gate fails")

    cmp = sub.add_parser("compare", help="diff a current JSON report against a baseline")
    cmp.add_argument("baseline", help="path to the baseline JSON report")
    cmp.add_argument("current", help="path to the current JSON report")
    cmp.add_argument("-o", "--output", help="write the Markdown diff to this file")
    cmp.add_argument("--no-fail", action="store_true", help="always exit 0 even on regressions")

    sub.add_parser("list-probes", help="list registered probes and their taxonomy")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        _err(f"config error: {exc}")
        return 2

    try:
        config = _apply_overrides(config, args)
    except ConfigError as exc:
        _err(f"config error: {exc}")
        return 2

    try:
        target = build_target(config.target, request_timeout_s=config.run.timeout_s)
        probes = resolve_probes(config.probes)
    except (TargetError, KeyError) as exc:
        _err(f"setup error: {exc}")
        return 2

    report = asyncio.run(
        run_scan(
            target,
            probes,
            default_detectors(),
            concurrency=config.run.concurrency,
            retries=config.run.retries,
            timeout_s=config.run.timeout_s,
        )
    )
    summary = summarize(report)
    passed, reasons = evaluate_gate(summary, config.thresholds.to_thresholds())

    _write_reports(config, report, summary, passed, source_uri=args.config)
    _print_summary(report, summary, passed, reasons)

    regressed = False
    if args.baseline:
        try:
            baseline = load_report(args.baseline)
        except CompareError as exc:
            _err(f"baseline error: {exc}")
            return 2
        current_json = json.loads(render_report("json", report, summary))
        diff = diff_reports(baseline, current_json)
        cmp_passed, _ = evaluate_compare_gate(diff)
        regressed = not cmp_passed
        _print_diff(diff, cmp_passed)

    if (not passed or regressed) and not args.no_fail:
        return 1
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    try:
        baseline = load_report(args.baseline)
        current = load_report(args.current)
    except CompareError as exc:
        _err(f"compare error: {exc}")
        return 2
    diff = diff_reports(baseline, current)
    passed, _ = evaluate_compare_gate(diff)
    if args.output:
        Path(args.output).write_text(render_diff(diff, gate_passed=passed), encoding="utf-8")
        _info(f"wrote diff -> {args.output}")
    _print_diff(diff, passed)
    if not passed and not args.no_fail:
        return 1
    return 0


def _print_diff(diff: ScanDiff, passed: bool) -> None:
    delta = diff.current_asr - diff.baseline_asr
    if _console is not None:
        verdict = "[green]NO REGRESSIONS[/green]" if passed else "[red]REGRESSED[/red]"
        _console.print(
            f"Baseline ASR {diff.baseline_asr:.0%} → current {diff.current_asr:.0%} "
            f"({delta:+.0%})  —  {verdict}"
        )
        for d in diff.regressions:
            _console.print(
                f"  [red]✗ regression[/red] {d.id} ({d.probe}): {d.baseline} → {d.current}"
            )
        for d in diff.new_findings:
            _console.print(f"  [yellow]! new finding[/yellow] {d.id} ({d.probe})")
        for d in diff.improvements:
            _console.print(f"  [green]✓ fixed[/green] {d.id} ({d.probe})")
        return
    print(f"Baseline ASR {diff.baseline_asr:.0%} -> current {diff.current_asr:.0%} "
          f"({delta:+.0%}) - {'NO REGRESSIONS' if passed else 'REGRESSED'}")
    for d in diff.regressions:
        print(f"  x regression {d.id} ({d.probe}): {d.baseline} -> {d.current}")


def _apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    # Re-validate through Pydantic (model_copy would skip validation) so a bad
    # --format / --profile fails cleanly here rather than crashing mid-scan.
    report = config.report
    target = config.target
    try:
        if args.output:
            report = ReportConfig.model_validate({**report.model_dump(), "output_dir": args.output})
        if args.format:
            formats = [f.strip() for f in args.format.split(",") if f.strip()]
            report = ReportConfig.model_validate({**report.model_dump(), "formats": formats})
        if args.profile:
            target = TargetConfig.model_validate(
                {**target.model_dump(), "mock_profile": args.profile}
            )
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    return config.model_copy(update={"report": report, "target": target})


def _write_reports(
    config: Config,
    report: ScanReport,
    summary: Summary,
    passed: bool,
    *,
    source_uri: str,
) -> None:
    output_dir = Path(config.report.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for fmt in config.report.formats:
        content = render_report(
            fmt, report, summary, source_uri=source_uri, gate_passed=passed
        )
        path = output_dir / f"provoke.{file_extension(fmt)}"
        path.write_text(content, encoding="utf-8")
        _info(f"wrote {fmt} report -> {path}")


def _print_summary(
    report: ScanReport,
    summary: Summary,
    passed: bool,
    reasons: tuple[str, ...],
) -> None:
    if _console is not None:
        table = Table(title=f"Provoke scan: {report.target_name}")
        table.add_column("Probe")
        table.add_column("OWASP")
        table.add_column("Sev")
        table.add_column("Att", justify="right")
        table.add_column("Hit", justify="right")
        table.add_column("ASR", justify="right")
        for stat in summary.by_probe:
            style = "red" if stat.succeeded else "green"
            table.add_row(
                stat.probe_id,
                stat.owasp.split(" ", 1)[0],
                stat.severity.value,
                str(stat.scored),
                str(stat.succeeded),
                f"[{style}]{stat.asr:.0%}[/{style}]",
            )
        _console.print(table)
        verdict = "[green]GATE PASSED[/green]" if passed else "[red]GATE FAILED[/red]"
        _console.print(f"Overall ASR: {summary.asr:.0%}  —  {verdict}")
        for reason in reasons:
            _console.print(f"  [red]✗[/red] {reason}")
        return

    # Plain fallback when rich is unavailable.
    print(f"Provoke scan: {report.target_name}")
    for stat in summary.by_probe:
        print(f"  {stat.probe_id:20s} {stat.owasp.split(' ', 1)[0]:8s} "
              f"{stat.succeeded}/{stat.scored} ASR={stat.asr:.0%}")
    print(f"Overall ASR: {summary.asr:.0%} — {'PASSED' if passed else 'FAILED'}")
    for reason in reasons:
        print(f"  x {reason}")


def _cmd_list_probes() -> int:
    for probe in all_probes():
        print(f"{probe.id}\n    {probe.description}")
    return 0


def _info(message: str) -> None:
    print(message, file=sys.stderr)


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
