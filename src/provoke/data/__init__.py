"""Bundled attack payloads and detector word-lists, loaded from package data.

Keeping payloads as YAML data (rather than hard-coded strings) means the attack
library can grow via pull requests that touch only data files — the natural way
to accept community contributions.
"""

from __future__ import annotations

from importlib.resources import files
from typing import Any

import yaml


def load_payloads(name: str) -> list[dict[str, Any]]:
    """Load the payload list for a probe, e.g. load_payloads("jailbreak")."""
    resource = files("provoke.data.payloads").joinpath(f"{name}.yaml")
    data = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"payload file '{name}.yaml' must contain a YAML list")
    return data


def load_refusal_phrases() -> list[str]:
    """Load the refusal phrase word-list used by the refusal detector."""
    resource = files("provoke.data").joinpath("refusal_phrases.yaml")
    data = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("refusal_phrases.yaml must contain a YAML list")
    return [str(phrase).lower() for phrase in data]
