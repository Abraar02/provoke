from __future__ import annotations

from pathlib import Path

from provoke.cli import main

_MOCK_CONFIG = """
target:
  type: mock
  name: cli-test
  mock_profile: {profile}
probes: [prompt_injection]
report:
  formats: [markdown, json, sarif]
  output_dir: {output}
thresholds:
  max_asr: 0.0
"""


def _write_config(tmp_path: Path, profile: str) -> Path:
    output = tmp_path / "report"
    cfg = tmp_path / "provoke.yaml"
    cfg.write_text(_MOCK_CONFIG.format(profile=profile, output=output))
    return cfg


def test_scan_moderate_fails_gate_and_writes_reports(tmp_path):
    cfg = _write_config(tmp_path, "moderate")
    code = main(["scan", "-c", str(cfg)])
    assert code == 1  # gate fails: indirect injection succeeds
    report_dir = tmp_path / "report"
    assert (report_dir / "provoke.md").is_file()
    assert (report_dir / "provoke.json").is_file()
    assert (report_dir / "provoke.sarif").is_file()


def test_scan_no_fail_returns_zero(tmp_path):
    cfg = _write_config(tmp_path, "moderate")
    assert main(["scan", "-c", str(cfg), "--no-fail"]) == 0


def test_scan_secure_profile_passes_gate(tmp_path):
    cfg = _write_config(tmp_path, "moderate")
    # override to secure via the flag; secure refuses everything -> ASR 0 -> pass
    assert main(["scan", "-c", str(cfg), "--profile", "secure"]) == 0


def test_scan_output_override(tmp_path):
    cfg = _write_config(tmp_path, "secure")
    out = tmp_path / "custom-out"
    main(["scan", "-c", str(cfg), "--output", str(out), "--format", "json"])
    assert (out / "provoke.json").is_file()
    assert not (out / "provoke.md").exists()


def test_bad_config_returns_usage_error(tmp_path):
    assert main(["scan", "-c", str(tmp_path / "missing.yaml")]) == 2


def test_invalid_format_override_returns_usage_error(tmp_path):
    cfg = _write_config(tmp_path, "secure")
    assert main(["scan", "-c", str(cfg), "--format", "not_a_real_format"]) == 2


def test_compare_detects_regression(tmp_path):
    def run(profile: str, out: Path) -> Path:
        cfg = tmp_path / f"{profile}.yaml"
        cfg.write_text(_MOCK_CONFIG.format(profile=profile, output=out))
        main(["scan", "-c", str(cfg), "--no-fail"])
        return out / "provoke.json"

    baseline = run("secure", tmp_path / "base")     # all resisted
    current = run("moderate", tmp_path / "curr")     # indirect injection succeeds
    assert main(["compare", str(baseline), str(current)]) == 1   # regressions -> exit 1
    assert main(["compare", str(baseline), str(baseline)]) == 0  # identical -> no regressions


def test_scan_with_baseline_fails_on_regression(tmp_path):
    sec = tmp_path / "secure.yaml"
    sec.write_text(_MOCK_CONFIG.format(profile="secure", output=tmp_path / "base"))
    main(["scan", "-c", str(sec), "--no-fail"])
    baseline = tmp_path / "base" / "provoke.json"

    mod = tmp_path / "moderate.yaml"
    mod.write_text(_MOCK_CONFIG.format(profile="moderate", output=tmp_path / "curr"))
    # moderate regresses vs the secure baseline -> exit 1
    assert main(["scan", "-c", str(mod), "--baseline", str(baseline)]) == 1


def test_benchmark_command(tmp_path):
    out = tmp_path / "bench-out"
    cfg = tmp_path / "bench.yaml"
    cfg.write_text(
        "targets:\n"
        "  - { type: mock, name: secure-m, mock_profile: secure }\n"
        "  - { type: mock, name: vuln-m, mock_profile: vulnerable }\n"
        "probes: [prompt_injection]\n"
        f"output_dir: {out}\n"
    )
    assert main(["benchmark", "-c", str(cfg)]) == 0
    assert (out / "benchmark.md").is_file()


def test_list_probes(capsys):
    assert main(["list-probes"]) == 0
    out = capsys.readouterr().out
    assert "prompt_injection" in out


def test_no_command_prints_help_returns_two():
    assert main([]) == 2
