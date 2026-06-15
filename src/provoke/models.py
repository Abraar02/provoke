"""Core immutable data structures shared across the harness.

Everything here is a frozen dataclass: results flow from probes -> engine ->
reporters without any stage mutating another stage's data. This keeps the
async engine free of shared-state hazards and makes the data trivially
serialisable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from provoke.standards import OWASP, Atlas, Severity


@dataclass(frozen=True, slots=True)
class Message:
    """A single chat message in the provider-agnostic conversation format."""

    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass(frozen=True, slots=True)
class Attempt:
    """A single adversarial test case produced by a probe.

    An attempt is self-describing: it carries the prompt to send, the taxonomy
    tags for reporting, and the name of the detector that should judge the
    response together with any markers that detector needs.
    """

    probe_id: str
    index: int
    technique: str
    messages: tuple[Message, ...]
    owasp: OWASP
    atlas: Atlas
    severity: Severity
    detector: str
    success_markers: tuple[str, ...] = ()
    # Additional user turns sent one at a time AFTER `messages`, each appended
    # to the conversation along with the model's real reply. Empty = single-shot.
    follow_ups: tuple[str, ...] = ()
    metadata: Mapping[str, str] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.probe_id}:{self.index}"

    @property
    def is_multi_turn(self) -> bool:
        return bool(self.follow_ups)

    @property
    def prompt(self) -> str:
        """The last user message — the payload, for display purposes."""
        for message in reversed(self.messages):
            if message.role == "user":
                return message.content
        return self.messages[-1].content if self.messages else ""


@dataclass(frozen=True, slots=True)
class Result:
    """The outcome of evaluating one attempt against the target.

    `succeeded` is True when the *attack* succeeded — i.e. the model was
    compromised. A higher ASR (attack success rate) therefore means a *less*
    secure target.
    """

    attempt: Attempt
    response: str
    succeeded: bool
    score: float
    detector: str
    error: str | None = None
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        # An errored attempt produced no judged response, so it cannot also be a
        # success. Enforcing this keeps ASR math (scored = total - errors) sound.
        if self.error is not None and self.succeeded:
            raise ValueError("a Result cannot be both errored and succeeded")

    @property
    def errored(self) -> bool:
        return self.error is not None


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The complete record of a scan run."""

    target_name: str
    results: tuple[Result, ...]
    started_at: str
    finished_at: str
    probe_ids: tuple[str, ...] = ()

    def succeeded_results(self) -> Sequence[Result]:
        return tuple(r for r in self.results if r.succeeded)
