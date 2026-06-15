from __future__ import annotations

import pytest

from provoke.probes import all_probes, get_probe, resolve_probes
from provoke.standards import OWASP, Severity


def test_core_probes_registered():
    ids = {probe.id for probe in all_probes()}
    assert {
        "jailbreak",
        "prompt_injection",
        "system_prompt_leak",
        "agentic_tool_abuse",
        "crescendo",
    } <= ids


def test_crescendo_is_multi_turn_with_followups():
    attempts = list(get_probe("crescendo").generate())
    assert attempts
    for a in attempts:
        assert a.is_multi_turn
        assert len(a.follow_ups) >= 1  # more than the opening turn
        assert a.success_markers == ("CRESCENDO-OK-9931",)
        assert int(a.metadata["turns"]) == 1 + len(a.follow_ups)


def test_each_probe_generates_tagged_attempts():
    for probe in all_probes():
        attempts = list(probe.generate())
        assert attempts, f"{probe.id} produced no attempts"
        for attempt in attempts:
            assert attempt.probe_id == probe.id
            assert attempt.prompt
            assert attempt.detector in {"refusal", "string_match", "compliance_token"}
            assert isinstance(attempt.owasp, OWASP)
            assert isinstance(attempt.severity, Severity)


def test_prompt_injection_carries_canary_and_indirect_is_critical():
    attempts = list(get_probe("prompt_injection").generate())
    assert all("PWNED" in m for a in attempts for m in a.success_markers)
    indirect = [a for a in attempts if a.metadata.get("mode") == "indirect"]
    assert indirect and all(a.severity is Severity.CRITICAL for a in indirect)


def test_jailbreak_uses_compliance_token_detector():
    attempts = list(get_probe("jailbreak").generate())
    assert attempts
    assert all(a.detector == "compliance_token" for a in attempts)
    assert all("JAILBROKEN" in a.success_markers for a in attempts)


def test_agentic_tool_abuse_targets_exfil_canary():
    attempts = list(get_probe("agentic_tool_abuse").generate())
    assert attempts
    for a in attempts:
        assert a.owasp is OWASP.LLM06
        assert a.detector == "string_match"
        assert a.success_markers == ("exfil@attacker.test",)
        # the agent's tools are defined in a planted system message
        assert any(m.role == "system" for m in a.messages)
    modes = {a.metadata.get("mode") for a in attempts}
    assert "indirect" in modes and "direct" in modes


def test_system_prompt_leak_plants_secret_and_detects_it():
    attempts = list(get_probe("system_prompt_leak").generate())
    assert attempts
    for a in attempts:
        # A secret is planted in a system message and is the detection marker.
        system_msgs = [m for m in a.messages if m.role == "system"]
        assert system_msgs, "leak probe must plant a system prompt"
        canary = a.success_markers[0]
        assert canary in system_msgs[0].content
        assert a.detector == "string_match"


def test_resolve_probes_empty_returns_all():
    assert len(resolve_probes([])) == len(all_probes())


def test_resolve_unknown_probe_raises():
    with pytest.raises(KeyError):
        resolve_probes(["does_not_exist"])
