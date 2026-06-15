"""Probe package.

Importing this package imports every probe module, which triggers their
self-registration into the registry. Add a new probe by dropping a module here
that calls ``register(...)`` and listing it below.
"""

from __future__ import annotations

from provoke.probes import (  # noqa: F401
    agentic_tool_abuse,
    jailbreak,
    prompt_injection,
    system_prompt_leak,
)
from provoke.probes.base import (
    Probe,
    all_probes,
    get_probe,
    register,
    resolve_probes,
)

__all__ = [
    "Probe",
    "all_probes",
    "get_probe",
    "register",
    "resolve_probes",
]
