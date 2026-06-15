"""Multi-target benchmark: scan several models and tabulate ASR side by side.

Answers "which model resists these attacks best?" — run the same probe suite
against N targets and render a comparison matrix (model x probe -> ASR). Lower
ASR is more robust. Useful for model selection and for tracking a fleet.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from provoke.config import ConfigError, RunConfig, TargetConfig
from provoke.detectors import default_detectors
from provoke.engine import run_scan
from provoke.probes import resolve_probes
from provoke.reporting import Summary, summarize
from provoke.targets import build_target


class BenchmarkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[TargetConfig] = Field(min_length=1)
    probes: list[str] = Field(default_factory=list)
    run: RunConfig = Field(default_factory=RunConfig)
    output_dir: str = "./provoke-benchmark"


def load_benchmark_config(path: str | Path) -> BenchmarkConfig:
    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigError(f"benchmark config not found: {file_path}")
    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"benchmark config root must be a mapping, got {type(raw).__name__}")
    try:
        return BenchmarkConfig(**raw)
    except Exception as exc:
        raise ConfigError(f"invalid benchmark config in {file_path}:\n{exc}") from exc


async def run_benchmark(config: BenchmarkConfig) -> list[tuple[str, Summary]]:
    detectors = default_detectors()
    probes = list(resolve_probes(config.probes))
    results: list[tuple[str, Summary]] = []
    for target_config in config.targets:
        target = build_target(target_config, request_timeout_s=config.run.timeout_s)
        report = await run_scan(
            target,
            probes,
            detectors,
            concurrency=config.run.concurrency,
            retries=config.run.retries,
            timeout_s=config.run.timeout_s,
        )
        results.append((target_config.name, summarize(report)))
    return results


def render_matrix(results: list[tuple[str, Summary]]) -> str:
    probe_ids = sorted({stat.probe_id for _, summary in results for stat in summary.by_probe})
    lines = [
        "# 📊 Provoke model benchmark",
        "",
        "Attack-success-rate per probe — **lower is more robust**.",
        "",
    ]
    columns = ["Model", "Overall ASR", *probe_ids]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("|" + "|".join(["---"] * len(columns)) + "|")
    for name, summary in results:
        per_probe = {stat.probe_id: stat.asr for stat in summary.by_probe}
        cells = [name, f"{summary.asr:.0%}"]
        cells += [f"{per_probe.get(pid, 0.0):.0%}" for pid in probe_ids]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def matrix_rows(results: list[tuple[str, Summary]]) -> list[dict[str, Any]]:
    """Structured rows (for the console renderer / programmatic use)."""
    return [
        {
            "model": name,
            "overall_asr": summary.asr,
            "by_probe": {stat.probe_id: stat.asr for stat in summary.by_probe},
        }
        for name, summary in results
    ]
