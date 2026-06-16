"""Compare two Janus metric snapshots and classify meaningful deltas."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Core.diff_load import load_run_artifacts, run_identity
from Core.diff_metrics import derive_run_metrics


@dataclass(frozen=True)
class DiffThresholds:
    min_sample_size: int = 10
    failure_rate_delta: float = 0.05
    relative_count_delta: float = 0.25
    duration_delta: float = 0.20
    task_volume_warning_threshold: float = 3.0
    unknown_status_warning_threshold: float = 0.80


LOWER_IS_BETTER = {
    "failure_rate",
    "unknown_status_percentage",
    "retry_density",
    "median_duration_seconds",
    "p95_duration_seconds",
    "dwell_median_seconds",
    "dwell_p95_seconds",
    "callback_health_penalty",
    "argument_anomaly_rate",
    "argument_anomaly_count",
    "callback_loss_adjacent_events",
    "detection_adjacent_events",
    "parser_quality_warning_count",
}

HIGHER_IS_BETTER = {
    "success_rate",
    "retry_to_success_rate",
}

COUNT_METRICS = {
    "task_count",
    "total_task_count",
    "command_entity_count",
    "argument_anomaly_count",
    "callback_loss_adjacent_events",
    "detection_adjacent_events",
    "callbacks_with_detections",
    "parser_quality_warning_count",
}

DURATION_METRICS = {
    "median_duration_seconds",
    "p95_duration_seconds",
    "dwell_median_seconds",
    "dwell_p95_seconds",
}

RATE_METRICS = {
    "failure_rate",
    "success_rate",
    "unknown_status_percentage",
    "retry_density",
    "retry_to_success_rate",
    "callback_health_penalty",
    "argument_anomaly_rate",
}

COMMAND_METRICS = (
    "task_count",
    "failure_rate",
    "success_rate",
    "unknown_status_percentage",
    "retry_density",
    "retry_to_success_rate",
    "median_duration_seconds",
    "p95_duration_seconds",
    "dwell_median_seconds",
    "dwell_p95_seconds",
    "callback_health_penalty",
    "argument_anomaly_rate",
    "argument_anomaly_count",
)

AGGREGATE_METRICS = (
    "total_task_count",
    "command_entity_count",
    "unknown_status_percentage",
    "callback_loss_adjacent_events",
    "detection_adjacent_events",
    "callbacks_with_detections",
    "dwell_median_seconds",
    "dwell_p95_seconds",
    "parser_quality_warning_count",
)


def build_diff(
    baseline_dir: Path,
    candidate_dir: Path,
    thresholds: DiffThresholds | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or DiffThresholds()
    baseline_artifacts = load_run_artifacts(baseline_dir)
    candidate_artifacts = load_run_artifacts(candidate_dir)
    baseline_metrics = derive_run_metrics(baseline_artifacts)
    candidate_metrics = derive_run_metrics(candidate_artifacts)

    baseline_id = run_identity(baseline_artifacts)
    candidate_id = run_identity(candidate_artifacts)
    comparability = _comparability(baseline_id, candidate_id, baseline_metrics, candidate_metrics, thresholds)

    findings: list[dict[str, Any]] = []
    findings.extend(_compare_aggregate(baseline_metrics, candidate_metrics, comparability, thresholds))
    findings.extend(_compare_commands(baseline_metrics, candidate_metrics, comparability, thresholds))
    findings.extend(_compare_sources(baseline_metrics, candidate_metrics, comparability, thresholds))
    findings.sort(key=_finding_sort_key)

    new_entities, removed_entities = _entity_presence(baseline_metrics, candidate_metrics)
    summary = _summary(findings)

    return {
        "baseline": baseline_id,
        "candidate": candidate_id,
        "comparability": comparability,
        "thresholds": {
            "min_sample_size": thresholds.min_sample_size,
            "failure_rate_delta": thresholds.failure_rate_delta,
            "relative_count_delta": thresholds.relative_count_delta,
            "duration_delta": thresholds.duration_delta,
            "task_volume_warning_threshold": thresholds.task_volume_warning_threshold,
            "unknown_status_warning_threshold": thresholds.unknown_status_warning_threshold,
        },
        "summary": summary,
        "findings": findings,
        "new_entities": new_entities,
        "removed_entities": removed_entities,
        "metrics": {
            "baseline": baseline_metrics,
            "candidate": candidate_metrics,
        },
    }


def high_confidence_regression_count(diff: dict[str, Any]) -> int:
    return sum(
        1
        for finding in diff.get("findings", [])
        if finding.get("classification") == "regression"
        and finding.get("confidence") == "high"
    )


def _comparability(
    baseline_id: dict[str, Any],
    candidate_id: dict[str, Any],
    baseline_metrics: dict[str, Any],
    candidate_metrics: dict[str, Any],
    thresholds: DiffThresholds,
) -> dict[str, Any]:
    warnings: list[str] = []
    baseline_sources = set(baseline_id.get("sources") or [])
    candidate_sources = set(candidate_id.get("sources") or [])
    if candidate_sources - baseline_sources:
        warnings.append(
            "Candidate contains sources not present in baseline: "
            + ", ".join(sorted(candidate_sources - baseline_sources))
            + "."
        )
    if baseline_sources - candidate_sources:
        warnings.append(
            "Baseline contains sources not present in candidate: "
            + ", ".join(sorted(baseline_sources - candidate_sources))
            + "."
        )

    baseline_tasks = _metric(baseline_metrics, "aggregate", "total_task_count")
    candidate_tasks = _metric(candidate_metrics, "aggregate", "total_task_count")
    if baseline_tasks and candidate_tasks:
        ratio = max(baseline_tasks, candidate_tasks) / max(1.0, min(baseline_tasks, candidate_tasks))
        if ratio > thresholds.task_volume_warning_threshold:
            warnings.append(
                f"Task volume differs by {ratio:.1f}x; aggregate trend claims may be misleading."
            )

    mix_delta = _command_mix_delta(baseline_metrics, candidate_metrics)
    if mix_delta >= thresholds.relative_count_delta:
        warnings.append(
            f"Command mix differs by {mix_delta:.0%}; command-level comparisons are more reliable than aggregate comparisons."
        )

    for label, metrics in (("Baseline", baseline_metrics), ("Candidate", candidate_metrics)):
        unknown = _metric(metrics, "aggregate", "unknown_status_percentage")
        if unknown >= thresholds.unknown_status_warning_threshold:
            warnings.append(
                f"{label} has {unknown:.0%} unknown statuses; failure-rate comparison is low-confidence."
            )

    for label, identity in (("Baseline", baseline_id), ("Candidate", candidate_id)):
        if not identity.get("analysis_version") and not identity.get("analysis_timestamp"):
            warnings.append(f"{label} is missing analysis version metadata; run identity is best-effort.")

    status = "comparable"
    if warnings:
        status = "comparable_with_warnings"
    if baseline_sources and candidate_sources and not (baseline_sources & candidate_sources):
        status = "not_comparable"
    return {
        "status": status,
        "warnings": warnings,
        "source_overlap": sorted(baseline_sources & candidate_sources),
        "baseline_only_sources": sorted(baseline_sources - candidate_sources),
        "candidate_only_sources": sorted(candidate_sources - baseline_sources),
        "command_mix_delta": round(mix_delta, 4),
    }


def _compare_aggregate(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    comparability: dict[str, Any],
    thresholds: DiffThresholds,
) -> list[dict[str, Any]]:
    findings = []
    for metric in AGGREGATE_METRICS:
        finding = _compare_metric(
            metric=metric,
            entity_type="aggregate",
            entity="all",
            baseline_entity=baseline.get("aggregate", {}),
            candidate_entity=candidate.get("aggregate", {}),
            comparability=comparability,
            thresholds=thresholds,
            baseline_sample=_sample_size(baseline.get("aggregate", {})),
            candidate_sample=_sample_size(candidate.get("aggregate", {})),
        )
        if finding:
            findings.append(finding)
    return findings


def _compare_commands(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    comparability: dict[str, Any],
    thresholds: DiffThresholds,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    baseline_commands = baseline.get("commands", {})
    candidate_commands = candidate.get("commands", {})
    for command in sorted(set(baseline_commands) | set(candidate_commands)):
        base_entity = baseline_commands.get(command, {})
        cand_entity = candidate_commands.get(command, {})
        if not base_entity or not cand_entity:
            continue
        for metric in COMMAND_METRICS:
            finding = _compare_metric(
                metric=metric,
                entity_type="command",
                entity=command,
                baseline_entity=base_entity,
                candidate_entity=cand_entity,
                comparability=comparability,
                thresholds=thresholds,
                baseline_sample=_sample_size(base_entity),
                candidate_sample=_sample_size(cand_entity),
            )
            if finding:
                findings.append(finding)
    return findings


def _compare_sources(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    comparability: dict[str, Any],
    thresholds: DiffThresholds,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    baseline_sources = baseline.get("sources", {})
    candidate_sources = candidate.get("sources", {})
    for source in sorted(set(baseline_sources) | set(candidate_sources)):
        base_entity = baseline_sources.get(source, {})
        cand_entity = candidate_sources.get(source, {})
        if not base_entity or not cand_entity:
            continue
        for metric in ("unknown_status_percentage", "data_quality_warning_count"):
            finding = _compare_metric(
                metric=metric,
                entity_type="source",
                entity=source,
                baseline_entity=base_entity,
                candidate_entity=cand_entity,
                comparability=comparability,
                thresholds=thresholds,
                baseline_sample=_sample_size(base_entity),
                candidate_sample=_sample_size(cand_entity),
            )
            if finding:
                findings.append(finding)
    return findings


def _compare_metric(
    *,
    metric: str,
    entity_type: str,
    entity: str,
    baseline_entity: dict[str, Any],
    candidate_entity: dict[str, Any],
    comparability: dict[str, Any],
    thresholds: DiffThresholds,
    baseline_sample: int,
    candidate_sample: int,
) -> dict[str, Any] | None:
    baseline_present = _has_metric(baseline_entity, metric)
    candidate_present = _has_metric(candidate_entity, metric)
    if not baseline_present and not candidate_present:
        return None

    baseline_value = baseline_entity.get(metric)
    candidate_value = candidate_entity.get(metric)
    if not baseline_present or not candidate_present:
        status = "missing_baseline" if not baseline_present else "missing_candidate"
        return {
            "metric": metric,
            "entity_type": entity_type,
            "entity": entity,
            "baseline_value": baseline_value if baseline_present else None,
            "candidate_value": candidate_value if candidate_present else None,
            "comparison_status": status,
            "direction": "not_comparable",
            "classification": "not_comparable",
            "confidence": "low",
            "display": _display(metric, entity, baseline_value, candidate_value, "changed"),
            "reason": f"{metric} is unavailable in one run, so Janus cannot classify the change.",
        }

    baseline_number = float(baseline_value)
    candidate_number = float(candidate_value)
    absolute_delta = candidate_number - baseline_number
    relative_delta = _relative_delta(baseline_number, candidate_number)
    if not _is_meaningful(metric, baseline_number, candidate_number, thresholds):
        return None

    direction = "increase" if absolute_delta > 0 else "decrease"
    confidence = _confidence(
        metric=metric,
        baseline_entity=baseline_entity,
        candidate_entity=candidate_entity,
        baseline_sample=baseline_sample,
        candidate_sample=candidate_sample,
        comparability=comparability,
        thresholds=thresholds,
    )
    classification = _classification(metric, direction, confidence, comparability)
    return {
        "metric": metric,
        "entity_type": entity_type,
        "entity": entity,
        "baseline_value": _round_value(baseline_number),
        "candidate_value": _round_value(candidate_number),
        "display": _display(metric, entity, baseline_number, candidate_number, direction),
        "absolute_delta": _round_value(absolute_delta),
        "relative_delta": _round_value(relative_delta),
        "direction": direction,
        "classification": classification,
        "confidence": confidence,
        "comparison_status": "compared",
        "reason": _reason(metric, direction, classification, confidence, absolute_delta, thresholds),
    }


def _entity_presence(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baseline_commands = baseline.get("commands", {})
    candidate_commands = candidate.get("commands", {})
    new_entities = [
        {
            "entity_type": "command",
            "entity": command,
            "candidate_count": _safe_int(candidate_commands[command].get("task_count")),
        }
        for command in sorted(set(candidate_commands) - set(baseline_commands))
    ]
    removed_entities = [
        {
            "entity_type": "command",
            "entity": command,
            "baseline_count": _safe_int(baseline_commands[command].get("task_count")),
        }
        for command in sorted(set(baseline_commands) - set(candidate_commands))
    ]
    return new_entities, removed_entities


def _summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "likely_regressions": sum(1 for f in findings if f.get("classification") == "regression"),
        "likely_improvements": sum(1 for f in findings if f.get("classification") == "improvement"),
        "low_confidence_changes": sum(1 for f in findings if f.get("classification") == "low-confidence change"),
        "not_comparable": sum(1 for f in findings if f.get("classification") == "not_comparable"),
    }


def _classification(metric: str, direction: str, confidence: str, comparability: dict[str, Any]) -> str:
    if comparability.get("status") == "not_comparable":
        return "not_comparable"
    if confidence == "low":
        return "low-confidence change"
    if metric in LOWER_IS_BETTER:
        return "regression" if direction == "increase" else "improvement"
    if metric in HIGHER_IS_BETTER:
        return "improvement" if direction == "increase" else "regression"
    return "changed"


def _confidence(
    *,
    metric: str,
    baseline_entity: dict[str, Any],
    candidate_entity: dict[str, Any],
    baseline_sample: int,
    candidate_sample: int,
    comparability: dict[str, Any],
    thresholds: DiffThresholds,
) -> str:
    if comparability.get("status") == "not_comparable":
        return "low"
    if baseline_sample < max(1, thresholds.min_sample_size) or candidate_sample < max(1, thresholds.min_sample_size):
        return "low"

    unknown_baseline = _safe_float(baseline_entity.get("unknown_status_percentage"))
    unknown_candidate = _safe_float(candidate_entity.get("unknown_status_percentage"))
    if metric in {"failure_rate", "success_rate", "retry_to_success_rate"} and (
        unknown_baseline >= thresholds.unknown_status_warning_threshold
        or unknown_candidate >= thresholds.unknown_status_warning_threshold
    ):
        return "low"

    source_overlap = set(comparability.get("source_overlap") or [])
    if not source_overlap:
        return "low"
    base_sources = set(baseline_entity.get("sources") or source_overlap)
    cand_sources = set(candidate_entity.get("sources") or source_overlap)
    if base_sources and cand_sources and base_sources != cand_sources:
        return "medium"

    if metric in DURATION_METRICS:
        return "medium"
    if comparability.get("warnings") and metric in AGGREGATE_METRICS:
        return "medium"
    return "high"


def _is_meaningful(metric: str, baseline_value: float, candidate_value: float, thresholds: DiffThresholds) -> bool:
    delta = abs(candidate_value - baseline_value)
    if metric in RATE_METRICS:
        return delta >= thresholds.failure_rate_delta
    if metric in DURATION_METRICS:
        if baseline_value == 0:
            return delta > 0
        return abs(delta / baseline_value) >= thresholds.duration_delta
    if metric in COUNT_METRICS:
        if baseline_value == 0:
            return candidate_value > 0
        return abs((candidate_value - baseline_value) / baseline_value) >= thresholds.relative_count_delta
    return delta > 0


def _sample_size(entity: dict[str, Any]) -> int:
    for key in ("execution_count", "result_count", "total_result_count", "task_count", "total_task_count"):
        value = _safe_int(entity.get(key))
        if value:
            return value
    return 0


def _command_mix_delta(baseline: dict[str, Any], candidate: dict[str, Any]) -> float:
    baseline_counts = {
        command: _safe_int(data.get("task_count"))
        for command, data in baseline.get("commands", {}).items()
    }
    candidate_counts = {
        command: _safe_int(data.get("task_count"))
        for command, data in candidate.get("commands", {}).items()
    }
    total_baseline = sum(baseline_counts.values())
    total_candidate = sum(candidate_counts.values())
    if not total_baseline or not total_candidate:
        return 0.0
    delta = 0.0
    for command in set(baseline_counts) | set(candidate_counts):
        delta += abs(
            (baseline_counts.get(command, 0) / total_baseline)
            - (candidate_counts.get(command, 0) / total_candidate)
        )
    return delta / 2.0


def _metric(metrics: dict[str, Any], group: str, metric: str) -> float:
    return _safe_float(metrics.get(group, {}).get(metric))


def _has_metric(entity: dict[str, Any], metric: str) -> bool:
    return metric in entity and entity.get(metric) is not None


def _relative_delta(baseline_value: float, candidate_value: float) -> float | None:
    if baseline_value == 0:
        return None
    return (candidate_value - baseline_value) / baseline_value


def _reason(
    metric: str,
    direction: str,
    classification: str,
    confidence: str,
    absolute_delta: float,
    thresholds: DiffThresholds,
) -> str:
    if classification == "low-confidence change":
        return (
            f"{_label(metric)} {_past_direction(direction)} by {_format_abs_delta(metric, absolute_delta)}, "
            "but sample size, source overlap, or status fidelity limits the claim."
        )
    if classification == "not_comparable":
        return "Source sets do not overlap, so Janus cannot classify the change."
    threshold = thresholds.duration_delta if metric in DURATION_METRICS else thresholds.failure_rate_delta
    return (
        f"{_label(metric)} {_past_direction(direction)} by {_format_abs_delta(metric, absolute_delta)} "
        f"with {confidence} confidence; threshold was {threshold:g}."
    )


def _display(metric: str, entity: str, baseline: Any, candidate: Any, direction: str) -> str:
    return (
        f"{entity} {_label(metric)} {_past_direction(direction)} from "
        f"{_format_value(metric, baseline)} to {_format_value(metric, candidate)}"
    )


def _past_direction(direction: str) -> str:
    if direction == "increase":
        return "increased"
    if direction == "decrease":
        return "decreased"
    return "changed"


def _label(metric: str) -> str:
    return metric.replace("_", " ")


def _format_abs_delta(metric: str, value: float) -> str:
    if metric in RATE_METRICS:
        return f"{abs(value) * 100:.1f} percentage points"
    if metric in DURATION_METRICS:
        return f"{abs(value):.1f}s"
    return f"{abs(value):.1f}"


def _format_value(metric: str, value: Any) -> str:
    if value is None:
        return "missing"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if metric in RATE_METRICS:
        return f"{number:.0%}"
    if metric in DURATION_METRICS:
        return f"{number:g}s"
    return f"{number:g}"


def _round_value(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 4)


def _safe_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed >= 0 else 0


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str, str]:
    order = {
        "regression": 0,
        "improvement": 1,
        "low-confidence change": 2,
        "not_comparable": 3,
        "changed": 4,
    }
    return (
        order.get(str(finding.get("classification")), 9),
        str(finding.get("entity_type")),
        str(finding.get("entity")),
        str(finding.get("metric")),
    )
