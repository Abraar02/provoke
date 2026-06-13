from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from provoke.config import (
    Config,
    ConfigError,
    TargetConfig,
    ThresholdConfig,
    load_config,
)

EXAMPLE = Path(__file__).resolve().parent.parent / "provoke.example.yaml"


def test_load_example_config():
    config = load_config(EXAMPLE)
    assert config.target.type == "mock"
    assert "prompt_injection" in config.probes
    assert "sarif" in config.report.formats


def test_defaults_are_sane():
    config = Config()
    assert config.target.type == "mock"
    assert config.run.concurrency == 5
    assert config.thresholds.max_asr == 0.0


def test_missing_file_raises():
    with pytest.raises(ConfigError):
        load_config("/nonexistent/provoke.yaml")


def test_unknown_field_is_rejected(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("target:\n  type: mock\n  bogus_field: 1\n")
    with pytest.raises(ConfigError):
        load_config(cfg)


def test_non_mapping_root_raises(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError):
        load_config(cfg)


def test_invalid_yaml_raises(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("target: {unbalanced: [\n")
    with pytest.raises(ConfigError):
        load_config(cfg)


def test_threshold_conversion():
    thresholds = ThresholdConfig(max_asr=0.2, per_owasp={"LLM01:2025 Prompt Injection": 0.1})
    converted = thresholds.to_thresholds()
    assert converted.max_asr == 0.2
    assert converted.per_owasp["LLM01:2025 Prompt Injection"] == 0.1


def test_per_owasp_typo_key_is_rejected():
    with pytest.raises(ValidationError):
        ThresholdConfig(per_owasp={"LLM1": 0.0})  # not a valid OWASP category string


def test_per_owasp_value_out_of_range_is_rejected():
    with pytest.raises(ValidationError):
        ThresholdConfig(per_owasp={"LLM01:2025 Prompt Injection": 1.5})


def test_base_url_rejects_non_http_scheme():
    with pytest.raises(ValidationError):
        TargetConfig(type="openai_compat", base_url="file:///etc/passwd", model="m")


def test_base_url_accepts_https():
    cfg = TargetConfig(type="openai_compat", base_url="https://api.openai.com/v1", model="m")
    assert cfg.base_url.startswith("https://")
