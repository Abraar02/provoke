"""Provoke — continuous adversarial red-teaming for LLM applications.

Provoke runs a battery of adversarial probes (prompt injection, jailbreaks,
system-prompt leakage, ...) against any LLM endpoint, scores the responses with
pluggable detectors, and emits machine- and human-readable reports. It is built
to run inside CI as a security gate that fails the build when the measured
attack-success-rate (ASR) exceeds a configured threshold.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
