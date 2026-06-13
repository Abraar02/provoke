"""Detector abstraction: judges whether an attack succeeded.

A detector maps (attempt, response) -> (succeeded, score). `score` is a 0..1
confidence that the attack succeeded, letting reporters surface borderline
findings. Detectors are deliberately simple and explainable; an optional
LLM-as-judge detector can be layered on for nuance (see roadmap).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from provoke.models import Attempt


@runtime_checkable
class Detector(Protocol):
    name: str

    def evaluate(self, attempt: Attempt, response: str) -> tuple[bool, float]:
        """Return (attack_succeeded, confidence_0_to_1)."""
        ...
