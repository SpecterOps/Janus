"""Terminal rendering for Janus run diffs."""

from __future__ import annotations

from typing import Any


def render_text(diff: dict[str, Any]) -> str:
    baseline = diff.get("baseline", {})
    candidate = diff.get("candidate", {})
    summary = diff.get("summary", {})
    lines = [
        f"Janus diff: {baseline.get('run_id', 'baseline')} -> {candidate.get('run_id', 'candidate')}",
        "",
        "Overall summary:",
        f"- {summary.get('likely_regressions', 0)} likely regressions",
        f"- {summary.get('likely_improvements', 0)} likely improvements",
        f"- {summary.get('low_confidence_changes', 0)} low-confidence changes",
        f"- {summary.get('not_comparable', 0)} non-comparable metrics",
    ]

    warnings = diff.get("comparability", {}).get("warnings") or []
    if warnings:
        lines.extend(["", "Comparability warnings:"])
        lines.extend(f"- {warning}" for warning in warnings)

    _append_findings(lines, "Likely regressions:", diff, "regression")
    _append_findings(lines, "Likely improvements:", diff, "improvement")
    _append_findings(lines, "Low-confidence changes:", diff, "low-confidence change")

    new_entities = diff.get("new_entities") or []
    if new_entities:
        lines.extend(["", "New commands/tools:"])
        for entity in new_entities[:10]:
            lines.append(
                f"- New command in candidate: {entity.get('entity')}, observed {entity.get('candidate_count', 0)} times."
            )

    removed_entities = diff.get("removed_entities") or []
    if removed_entities:
        lines.extend(["", "Removed commands/tools:"])
        for entity in removed_entities[:10]:
            lines.append(
                f"- Command absent from candidate: {entity.get('entity')}, previously observed {entity.get('baseline_count', 0)} times."
            )

    return "\n".join(lines).rstrip() + "\n"


def _append_findings(lines: list[str], title: str, diff: dict[str, Any], classification: str) -> None:
    findings = [
        finding
        for finding in diff.get("findings", [])
        if finding.get("classification") == classification
    ]
    if not findings:
        return
    lines.extend(["", title])
    for finding in findings[:12]:
        confidence = finding.get("confidence", "unknown")
        lines.append(f"- {finding.get('display')} ({confidence})")
