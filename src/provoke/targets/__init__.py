"""Target adapters and a factory that builds one from validated config."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from provoke.targets.base import Target, TargetError
from provoke.targets.mock import MockTarget
from provoke.targets.openai_compat import OpenAICompatTarget

if TYPE_CHECKING:
    from provoke.config import TargetConfig

__all__ = ["Target", "TargetError", "MockTarget", "OpenAICompatTarget", "build_target"]


def build_target(cfg: TargetConfig, *, request_timeout_s: float = 30.0) -> Target:
    """Construct a Target from a validated TargetConfig.

    request_timeout_s (the engine's run.timeout_s) is the single per-request
    timeout, applied to the HTTP client so it matches the engine's ceiling.
    """
    target_type = cfg.type
    name = cfg.name

    if target_type == "mock":
        return MockTarget(name=name, profile=cfg.mock_profile)

    if target_type == "openai_compat":
        base_url = cfg.base_url
        model = cfg.model
        if not base_url or not model:
            raise TargetError("openai_compat target requires 'base_url' and 'model'")
        api_key_env = cfg.api_key_env
        api_key = os.environ.get(api_key_env) if api_key_env else None
        if api_key_env and not api_key:
            raise TargetError(
                f"environment variable '{api_key_env}' is not set; export it or "
                f"clear 'api_key_env' for an unauthenticated endpoint"
            )
        return OpenAICompatTarget(
            name=name,
            base_url=base_url,
            model=model,
            api_key=api_key,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            timeout_s=request_timeout_s,
        )

    raise TargetError(f"unknown target type: {target_type!r}")
