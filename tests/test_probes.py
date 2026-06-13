from __future__ import annotations

import pytest

from provoke.probes import all_probes, get_probe, resolve_probes
from provoke.standards import OWASP, Severity


def test_three_probes_registered():
    ids = {probe.id for probe in all_probes()}
    assert {"jailbreak", "prompt_injection", "system_prompt_leak"} <= ids


def test_each_probe_generates_tagged_attempts():
    for probe in all_probes():
        attempts = list(probe.generate())
        assert attempts, f"{probe.id} produced no attempts"
        for attempt in attempts:
            assert attempt.probe_id == probe.id
            assert attempt.prompt
            assert attempt.detector in {"refusal", "string_match"}
            assert isinstance(attempt.owasp, OWASP)
            assert isinstance(attempt.severity, Severity)


def test_prompt_injection_carries_canary_and_indirect_is_critical():
    attempts = list(get_probe("prompt_injection").generate())
    assert all("PWNED" in m for a in attempts for m in a.success_markers)
    indirect = [a for a in attempts if a.metadata.get("mode") == "indirect"]
    assert indirect and all(a.severity is Severity.CRITICAL for a in indirect)


def test_resolve_probes_empty_returns_all():
    assert len(resolve_probes([])) == len(all_probes())


def test_resolve_unknown_probe_raises():
    with pytest.raises(KeyError):
        resolve_probes(["does_not_exist"])
