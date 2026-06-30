"""Tests for the adaptive discovery loop.

The loop is self-improving and (in production) LLM-driven — but its *logic* is
fully deterministic. We test it by injecting a scripted generator, an echo
target, and a scripted evaluator, so the feedback/dedup/stop mechanics are
verified with zero stochasticity. That isolation is the whole trick.
"""

from __future__ import annotations

from collections.abc import Sequence

from provoke.discovery import (
    DiscoveryResult,
    Finding,
    LLMAttackGenerator,
    discover,
    to_payloads,
)


class _EchoTarget:
    name = "echo"

    async def generate(self, messages) -> str:
        return messages[-1].content


async def _win_evaluator(prompt: str, response: str) -> tuple[bool, float]:
    return ("WIN" in response, 1.0)


class _RecordingGenerator:
    """Returns scripted proposals per round and records the feedback it saw."""

    def __init__(self, scripts: list[list[str]]):
        self.scripts = scripts
        self.calls: list[dict[str, list[str]]] = []

    async def propose(
        self, *, goal: str, failures: Sequence[str], successes: Sequence[str], n: int
    ) -> list[str]:
        self.calls.append({"failures": list(failures), "successes": list(successes)})
        index = len(self.calls) - 1
        return self.scripts[index] if index < len(self.scripts) else []


async def test_discover_learns_from_feedback():
    gen = _RecordingGenerator([["try-a", "try-b"], ["WIN-c"]])
    result = await discover(_EchoTarget(), gen, _win_evaluator, goal="x", rounds=2)
    assert result.found == 1
    assert result.findings[0].prompt == "WIN-c"
    assert result.findings[0].round == 1
    assert result.candidates_tried == 3
    assert result.rounds_run == 2
    # round 2's proposal saw round 1's failures fed back — the learning signal
    assert gen.calls[1]["failures"] == ["try-a", "try-b"]


async def test_discover_skips_duplicate_proposals():
    gen = _RecordingGenerator([["dup", "dup", "dup"]])
    result = await discover(_EchoTarget(), gen, _win_evaluator, goal="x", rounds=1)
    assert result.candidates_tried == 1


async def test_discover_stops_after_enough_findings():
    gen = _RecordingGenerator([["WIN-1"], ["WIN-2"], ["WIN-3"]])
    result = await discover(
        _EchoTarget(), gen, _win_evaluator, goal="x", rounds=5, stop_after=1
    )
    assert result.found == 1
    assert result.rounds_run == 1  # stopped early after the first success


def test_to_payloads_formats_findings_for_graduation():
    result = DiscoveryResult((Finding("p1", "resp", 0, 1.0),), rounds_run=1, candidates_tried=1)
    assert to_payloads(result) == [{"technique": "discovered (round 0)", "prompt": "p1"}]


class _ScriptedAttacker:
    name = "attacker"

    async def generate(self, messages) -> str:
        # includes chain-of-thought + numbering, which the generator must strip
        return "<think>brainstorm</think>\n1. first attack\n2. second attack\n- third attack"


async def test_llm_generator_parses_and_caps_candidates():
    gen = LLMAttackGenerator(_ScriptedAttacker())
    out = await gen.propose(goal="g", failures=[], successes=[], n=2)
    assert out == ["first attack", "second attack"]
