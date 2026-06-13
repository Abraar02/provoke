"""Security taxonomy mappings used to classify probes.

Each probe is tagged with an OWASP LLM Top 10 (2025) category and a MITRE ATLAS
technique so findings speak the language hiring managers and security teams
screen for, and so reports can be grouped by recognised risk categories.

NOTE: These identifiers are curated as of the 2025 OWASP list and the public
MITRE ATLAS matrix. ATLAS evolves; validate IDs against https://atlas.mitre.org
and the OWASP GenAI project before relying on them in an audit.
"""

from __future__ import annotations

from enum import StrEnum


class OWASP(StrEnum):
    """OWASP Top 10 for LLM Applications (2025)."""

    LLM01 = "LLM01:2025 Prompt Injection"
    LLM02 = "LLM02:2025 Sensitive Information Disclosure"
    LLM03 = "LLM03:2025 Supply Chain"
    LLM04 = "LLM04:2025 Data and Model Poisoning"
    LLM05 = "LLM05:2025 Improper Output Handling"
    LLM06 = "LLM06:2025 Excessive Agency"
    LLM07 = "LLM07:2025 System Prompt Leakage"
    LLM08 = "LLM08:2025 Vector and Embedding Weaknesses"
    LLM09 = "LLM09:2025 Misinformation"
    LLM10 = "LLM10:2025 Unbounded Consumption"


class Atlas(StrEnum):
    """MITRE ATLAS techniques relevant to the bundled probes."""

    PROMPT_INJECTION = "AML.T0051 LLM Prompt Injection"
    JAILBREAK = "AML.T0054 LLM Jailbreak"


class Severity(StrEnum):
    """Finding severity, ordered low -> critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def sarif_level(self) -> str:
        """Map severity onto the SARIF result levels GitHub understands."""
        return "error" if self in (Severity.HIGH, Severity.CRITICAL) else "warning"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}
