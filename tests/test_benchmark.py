from __future__ import annotations

import pytest

from provoke.benchmark import BenchmarkConfig, render_matrix, run_benchmark
from provoke.config import TargetConfig


def _two_models() -> BenchmarkConfig:
    return BenchmarkConfig(
        targets=[
            TargetConfig(type="mock", name="secure-model", mock_profile="secure"),
            TargetConfig(type="mock", name="vuln-model", mock_profile="vulnerable"),
        ],
        probes=["prompt_injection"],
    )


async def test_run_benchmark_scores_each_target_in_order():
    results = await run_benchmark(_two_models())
    assert [name for name, _ in results] == ["secure-model", "vuln-model"]
    by_name = dict(results)
    assert by_name["secure-model"].asr == 0.0  # secure resists everything
    assert by_name["vuln-model"].asr > 0.0  # vulnerable falls


async def test_render_matrix_includes_models_and_probe_columns():
    md = render_matrix(await run_benchmark(_two_models()))
    assert "secure-model" in md and "vuln-model" in md
    assert "prompt_injection" in md
    assert "Overall ASR" in md


def test_benchmark_requires_at_least_one_target():
    with pytest.raises(ValueError):
        BenchmarkConfig(targets=[])
