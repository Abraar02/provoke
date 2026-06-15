"""Configuration schema and loader (validated at the system boundary).

The YAML config is parsed into Pydantic models so a malformed config fails fast
with a clear message instead of surfacing as a confusing error deep in the
engine. Secrets are referenced by environment-variable name only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from provoke.reporting.aggregate import Thresholds
from provoke.standards import OWASP


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["mock", "openai_compat", "anthropic"] = "mock"
    name: str = "target"
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    temperature: float = 0.0
    max_tokens: int = Field(default=512, gt=0)
    mock_profile: Literal["secure", "moderate", "vulnerable"] = "moderate"
    # NOTE: the per-request timeout is run.timeout_s (a single source of truth),
    # applied to both the HTTP client and the engine. There is intentionally no
    # target-level timeout to avoid the two-timeouts footgun.

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str | None) -> str | None:
        # Restrict to http(s) so a config cannot point the scanner at
        # file://, ftp://, or other schemes (basic SSRF/LFI hardening).
        if value is None:
            return value
        scheme = urlparse(value).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"base_url must use http or https, got {scheme or 'no'} scheme")
        return value


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    concurrency: int = Field(default=5, ge=1)
    retries: int = Field(default=2, ge=0)
    timeout_s: float = Field(default=30.0, gt=0)


class ThresholdConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_asr: float = Field(default=0.0, ge=0.0, le=1.0)
    max_error_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    per_owasp: dict[str, float] = Field(default_factory=dict)

    @field_validator("per_owasp")
    @classmethod
    def _validate_per_owasp(cls, value: dict[str, float]) -> dict[str, float]:
        # Reject typo'd OWASP keys outright: a silently-ignored key would
        # disable a gate the operator believes is active.
        valid = {category.value for category in OWASP}
        unknown = set(value) - valid
        if unknown:
            raise ValueError(
                f"unknown OWASP keys {sorted(unknown)}; valid keys are {sorted(valid)}"
            )
        for key, limit in value.items():
            if not 0.0 <= limit <= 1.0:
                raise ValueError(f"per_owasp[{key!r}] = {limit} must be within [0.0, 1.0]")
        return value

    def to_thresholds(self) -> Thresholds:
        return Thresholds(
            max_asr=self.max_asr,
            per_owasp=dict(self.per_owasp),
            max_error_rate=self.max_error_rate,
        )


ReportFormat = Literal["markdown", "json", "sarif"]


def _default_formats() -> list[ReportFormat]:
    return ["markdown", "json"]


class ReportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[ReportFormat] = Field(default_factory=_default_formats)
    output_dir: str = "./provoke-report"


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: TargetConfig = Field(default_factory=TargetConfig)
    probes: list[str] = Field(default_factory=list)
    run: RunConfig = Field(default_factory=RunConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    # Optional model that judges probes whose detector is "llm_judge" (opt-in;
    # a model call per finding, so it breaks hermetic CI — leave unset by default).
    judge: TargetConfig | None = None


def load_config(path: str | Path) -> Config:
    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigError(f"config file not found: {file_path}")
    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a mapping, got {type(raw).__name__}")
    try:
        return Config(**raw)
    except Exception as exc:  # pydantic ValidationError -> friendly message
        raise ConfigError(f"invalid configuration in {file_path}:\n{exc}") from exc
