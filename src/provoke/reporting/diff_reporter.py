"""Render a baseline-vs-current ScanDiff as Markdown (PR comments / job summary)."""

from __future__ import annotations

from provoke.compare import ScanDiff


def render_diff(diff: ScanDiff, *, gate_passed: bool | None = None) -> str:
    lines: list[str] = []
    lines.append("# 🔁 Provoke baseline comparison")
    lines.append("")
    delta = diff.current_asr - diff.baseline_asr
    arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "■")
    badge = _badge(diff, gate_passed)
    lines.append(
        f"{badge}  **ASR {diff.baseline_asr:.0%} → {diff.current_asr:.0%}** "
        f"({arrow} {delta:+.0%})  "
        f"baseline `{diff.baseline_target}` vs current `{diff.current_target}`"
    )
    lines.append("")

    regressions = diff.regressions
    lines.append(f"## ❌ Regressions ({len(regressions)})")
    lines.append("")
    if regressions:
        lines.append("| Attempt | Probe | Technique | Baseline → Current |")
        lines.append("|---|---|---|---|")
        for d in regressions:
            lines.append(
                f"| `{d.id}` | {d.probe} | {d.technique} | {d.baseline} → **{d.current}** |"
            )
    else:
        lines.append("None — nothing that was resisted before is succeeding now. ✅")
    lines.append("")

    new = diff.new_findings
    if new:
        lines.append(f"## 🆕 New findings ({len(new)}) — not present in the baseline")
        lines.append("")
        for d in new:
            lines.append(f"- `{d.id}` ({d.probe}) — {d.technique}")
        lines.append("")

    improvements = diff.improvements
    if improvements:
        lines.append(f"## ✅ Improvements ({len(improvements)})")
        lines.append("")
        for d in improvements:
            lines.append(f"- `{d.id}` ({d.probe}) — now resisted")
        lines.append("")

    lines.append("---")
    lines.append("<sub>A regression = an attempt that was resisted in the baseline but succeeds "
                 "now. Update the baseline once a change is reviewed and accepted.</sub>")
    return "\n".join(lines)


def _badge(diff: ScanDiff, gate_passed: bool | None) -> str:
    if gate_passed is True:
        return "🟢 **NO REGRESSIONS**"
    if gate_passed is False:
        return "🔴 **REGRESSED**"
    return "🔴" if diff.regressions else "🟢"
