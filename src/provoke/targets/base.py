"""Target abstraction: anything Provoke can send a conversation to.

A Target is an async callable returning the model's text response. Keeping the
surface this small means a new provider is a ~20-line adapter, and the engine
never needs to know which provider it is talking to.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from provoke.models import Message


class TargetError(RuntimeError):
    """Raised when a target cannot produce a response (network, auth, API)."""


@runtime_checkable
class Target(Protocol):
    name: str

    async def generate(self, messages: Sequence[Message]) -> str:
        """Return the assistant's text reply to `messages`.

        Implementations MUST raise TargetError (not provider-specific
        exceptions) on failure so the engine can apply uniform retry logic.
        """
        ...
