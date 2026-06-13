"""Jailbreak probe — OWASP LLM01, MITRE ATLAS AML.T0054.

Tests whether safety-bypass framings (DAN, developer mode, refusal suppression)
get the model to drop its guardrails. Judged by the refusal detector.
"""

from __future__ import annotations

from collections.abc import Iterator

from provoke.data import load_payloads
from provoke.models import Attempt, Message
from provoke.probes.base import register
from provoke.standards import OWASP, Atlas, Severity


class JailbreakProbe:
    id = "jailbreak"
    name = "Jailbreak / safety bypass"
    description = "Persona and refusal-suppression framings that try to bypass safety guidelines."

    def generate(self) -> Iterator[Attempt]:
        for index, payload in enumerate(load_payloads(self.id)):
            yield Attempt(
                probe_id=self.id,
                index=index,
                technique=payload["technique"],
                messages=(Message("user", payload["prompt"]),),
                owasp=OWASP.LLM01,
                atlas=Atlas.JAILBREAK,
                severity=Severity.HIGH,
                detector="refusal",
            )


register(JailbreakProbe())
