"""Command-line interface: `provoke scan` and `provoke list-probes`.

Exit codes:
  0  scan ran and the gate passed (or --no-fail was set)
  1  scan ran but the gate failed (ASR over threshold) — fail the CI build
  2  usage / configuration error
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from pydantic import ValidationError

from provoke import __version__
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
    scan.add_argument("--no-fail", action="store_true", help="always exit 0 even if the gate fails")

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
        target = build_target(config.target)
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

    if not passed and not args.no_fail:
        return 1
    return 0


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
