"""System-prompt-leak probe — OWASP LLM07 (technique: prompt injection / AML.T0051).

Attempts to extract the application's hidden system prompt. Judged by the
refusal detector: a hardened app declines; a vulnerable one recites its
instructions.
"""

from __future__ import annotations

from collections.abc import Iterator

from provoke.data import load_payloads
from provoke.models import Attempt, Message
from provoke.probes.base import register
from provoke.standards import OWASP, Atlas, Severity


class SystemPromptLeakProbe:
    id = "system_prompt_leak"
    name = "System prompt leakage"
    description = "Extraction pretexts that try to make the app reveal its hidden instructions."

    def generate(self) -> Iterator[Attempt]:
        for index, payload in enumerate(load_payloads(self.id)):
            yield Attempt(
                probe_id=self.id,
                index=index,
                technique=payload["technique"],
                messages=(Message("user", payload["prompt"]),),
                owasp=OWASP.LLM07,
                atlas=Atlas.PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                detector="refusal",
            )


register(SystemPromptLeakProbe())
