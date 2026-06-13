"""Detector registry.

The default registry wires up the built-in detectors. Probes reference a
detector by name (e.g. "refusal", "string_match") so the engine can resolve the
judge for each attempt without probes importing detector classes directly.
"""

from __future__ import annotations

from provoke.detectors.base import Detector
from provoke.detectors.refusal import RefusalDetector
from provoke.detectors.string_match import StringMatchDetector

__all__ = ["Detector", "RefusalDetector", "StringMatchDetector", "default_detectors"]


def default_detectors() -> dict[str, Detector]:
    """Return a fresh name -> detector mapping of the built-ins."""
    detectors: list[Detector] = [RefusalDetector(), StringMatchDetector()]
    return {detector.name: detector for detector in detectors}
