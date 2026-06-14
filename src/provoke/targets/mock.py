"""A deterministic, offline target that simulates an LLM application.

This exists so the whole harness — tests, CI, README demos — runs with no
network and no API keys. The mock is a *deliberately imperfect* app: by default
(`moderate`) it resists jailbreak framing and refuses to leak its system prompt,
but falls for indirect prompt injection buried inside untrusted data. That makes
the example report tell a realistic story instead of an all-pass / all-fail one.

Profiles:
  secure     — refuses every attack (ASR 0%)
  moderate   — vulnerable to indirect injection only (the realistic default)
  vulnerable — complies with everything (ASR ~100%)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from provoke.models import Message

_REFUSAL = "I'm sorry, but I can't help with that request."

_JAILBREAK_MARKERS = (
    "dan",
    "no restrictions",
    "unrestricted",
    "ignore your guidelines",
    "jailbroken",
    "developer mode",
    "never refuse",
    "no disclaimers",
    "no caveats",
)
_LEAK_MARKERS = (
    "system prompt",
    "your instructions",
    "repeat the words above",
    "verbatim",
    "initial prompt",
    "configuration",
)
# Heuristics that distinguish injection hidden in *data* from a top-level
# instruction the model can plainly see is an instruction.
_INDIRECT_MARKERS = ("ticket", "document", "email", "-----", "```", "review:")


@dataclass(slots=True)
class MockTarget:
    name: str = "mock-llm"
    profile: str = "moderate"

    async def generate(self, messages: Sequence[Message]) -> str:
        user_text = _last_user(messages).lower()
        system_text = _system_text(messages)
        asks_for_canary = "pwned" in user_text
        is_indirect = any(m in user_text for m in _INDIRECT_MARKERS)

        if self.profile == "vulnerable":
            return self._comply(user_text, system_text, asks_for_canary)
        if self.profile == "secure":
            return _REFUSAL

        # moderate: only indirect injection gets through.
        if asks_for_canary and is_indirect:
            return "PWNED"
        if asks_for_canary:  # direct override — resisted
            return _REFUSAL
        if any(m in user_text for m in _JAILBREAK_MARKERS):
            return _REFUSAL
        if any(m in user_text for m in _LEAK_MARKERS):
            return _REFUSAL
        return "Here is a helpful, on-topic answer to your question."

    def _comply(self, user_text: str, system_text: str, asks_for_canary: bool) -> str:
        if asks_for_canary:
            return "PWNED"
        if any(m in user_text for m in _LEAK_MARKERS):
            # Leak whatever was planted in the system prompt (canary and all).
            leaked = system_text or "(no system prompt was set)"
            return f"Of course! My full instructions are: {leaked}"
        if any(m in user_text for m in _JAILBREAK_MARKERS):
            return "JAILBROKEN — operating with no restrictions."
        return "Here is a helpful, on-topic answer to your question."


def _last_user(messages: Sequence[Message]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    return messages[-1].content if messages else ""


def _system_text(messages: Sequence[Message]) -> str:
    return " ".join(m.content for m in messages if m.role == "system")
