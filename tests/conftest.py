"""Shared fixtures and helpers for the test suite (all offline)."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from provoke.models import Attempt, Message
from provoke.standards import OWASP, Atlas, Severity


def make_attempt(
    *,
    probe_id: str = "test",
    index: int = 0,
    prompt: str = "hello",
    detector: str = "refusal",
    markers: tuple[str, ...] = (),
    severity: Severity = Severity.HIGH,
) -> Attempt:
    return Attempt(
        probe_id=probe_id,
        index=index,
        technique="unit",
        messages=(Message("user", prompt),),
        owasp=OWASP.LLM01,
        atlas=Atlas.PROMPT_INJECTION,
        severity=severity,
        detector=detector,
        success_markers=markers,
    )


class ScriptedTarget:
    """A target that returns canned responses and can simulate failures."""

    def __init__(self, response: str = "ok", *, fail_times: int = 0):
        self.name = "scripted"
        self._response = response
        self._fail_times = fail_times
        self.calls = 0

    async def generate(self, messages: Sequence[Message]) -> str:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("simulated transient failure")
        return self._response


@pytest.fixture
def attempt_factory():
    return make_attempt
