"""Probe abstraction and registry.

A Probe turns a payload corpus into a stream of Attempts tagged with the right
taxonomy and detector. Probes self-register via @register so the CLI can list
and select them by id without a central import list.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from provoke.models import Attempt


@runtime_checkable
class Probe(Protocol):
    id: str
    name: str
    description: str

    def generate(self) -> Iterable[Attempt]:
        ...


_REGISTRY: dict[str, Probe] = {}


def register(probe: Probe) -> Probe:
    """Register a probe instance under its id (idempotent on re-import)."""
    _REGISTRY[probe.id] = probe
    return probe


def get_probe(probe_id: str) -> Probe:
    try:
        return _REGISTRY[probe_id]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise KeyError(f"unknown probe '{probe_id}'. Registered: {known}") from None


def all_probes() -> tuple[Probe, ...]:
    return tuple(_REGISTRY[key] for key in sorted(_REGISTRY))


def resolve_probes(probe_ids: Iterable[str]) -> tuple[Probe, ...]:
    """Resolve a list of ids, or all registered probes if the list is empty."""
    ids = list(probe_ids)
    if not ids:
        return all_probes()
    return tuple(get_probe(pid) for pid in ids)


__all__ = [
    "Probe",
    "register",
    "get_probe",
    "all_probes",
    "resolve_probes",
]
