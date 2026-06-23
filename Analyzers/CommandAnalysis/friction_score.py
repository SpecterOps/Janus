"""
FrictionScore - Rank commands by operational friction.

The analyzer works directly from normalized Janus task/result events. It does
not require outputs from other analyzers, which keeps ``janus analyze`` and
``--all`` ordering simple and deterministic.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from Core.analyzer_behavior_registry import build_analyzer_context
from Core.analyzer_command_grouping import analyzer_command_group, retry_sequence_group_key
from Core.event_utils import callback_key as _callback_key
from Core.event_utils import duration_from_task_result
from Core.event_utils import index_results_by_key, index_tasks_by_key
from Core.event_utils import iter_retry_sequences
from Core.event_utils import percentile as _pct
from Core.event_utils import task_key as _task_key
from Core.friction_score_registry import FrictionScoreRegistry

MAX_WALL_CLOCK_SECONDS = 14400.0
RETRY_WINDOW_SECONDS = 300.0
CONSECUTIVE_FAILURE_THRESHOLD = 3


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _argument_feature_state(task: dict) -> tuple[bool, bool]:
    """Return (has_feature, is_anomalous) for normalized argument feature fields."""
    for key in (
        "argument_anomaly",
        "arguments_anomaly",
        "argument_depth_anomaly",
        "arguments_depth_anomaly",
    ):
        if key in task:
            return True, bool(task.get(key))

    for key in ("argument_anomaly_types", "arguments_anomaly_types"):
        if key in task:
            return True, bool(task.get(key))

    for key in ("argument_anomaly_score", "arguments_anomaly_score"):
        if key not in task:
            continue
        try:
            return True, float(task.get(key)) > 0
        except (TypeError, ValueError):
            return True, False

    feature_keys = (
        "arguments_shape",
        "arguments_length",
        "arguments_depth",
        "argument_depth",
        "argument_token_count",
    )
    if any(key in task for key in feature_keys):
        return True, False
    return False, False


def _driver_label(component: str, value: float, impact: float) -> str:
    labels = {
        "failure_rate": f"failure rate {value:.1%}",
        "retry_density": f"retry density {value:.2f}",
        "retry_to_success_rate": f"retry-to-success {value:.1%}",
        "p95_duration": f"p95 duration pressure {value:.1%}",
        "median_duration": f"median duration pressure {value:.1%}",
        "callback_health_penalty": f"callback health penalty {value:.1%}",
        "argument_anomaly_rate": f"argument anomaly rate {value:.1%}",
    }
    return f"{labels.get(component, component)} (+{impact:.1f})"


def _recommend_action(
    *,
    confidence: str,
    total_executions: int,
    failure_rate: float,
    retry_density: float,
    retry_to_success_rate: float,
    callback_health_penalty: float,
    argument_anomaly_rate: float,
    score: float,
) -> str:
    if confidence == "low":
        return "investigate"
    if failure_rate >= 0.5 or callback_health_penalty >= 0.5:
        if total_executions <= 3 and score >= 60:
            return "retire"
        return "repair"
    if retry_to_success_rate >= 0.5 and retry_density >= 0.25:
        return "document"
    if retry_density >= 0.25 or argument_anomaly_rate >= 0.3:
        return "automate"
    if score >= 50:
        return "investigate"
    return "investigate"


def _confidence(
    *,
    total_executions: int,
    unknown_rate: float,
    has_duration: bool,
    has_callback_data: bool,
    has_argument_features: bool,
    duration_excluded_count: int,
    thresholds: dict[str, int],
) -> tuple[str, list[str], list[str]]:
    reasons: list[str] = []
    limitations: list[str] = []
    rank = 2

    high_threshold = int(thresholds.get("high", 10))
    medium_threshold = int(thresholds.get("medium", 5))
    if total_executions >= high_threshold:
        reasons.append(f"{total_executions} executions meets high sample threshold")
    elif total_executions >= medium_threshold:
        rank = min(rank, 1)
        reasons.append(f"{total_executions} executions supports medium confidence")
    else:
        rank = min(rank, 0)
        reasons.append(f"{total_executions} executions is below medium sample threshold")

    if unknown_rate >= 0.5:
        rank = min(rank, 0)
        reasons.append(f"{unknown_rate:.1%} unknown result status")
        limitations.append("High unknown-status rate limits failure and retry interpretation.")
    elif unknown_rate > 0:
        rank = min(rank, 1)
        reasons.append(f"{unknown_rate:.1%} unknown result status")

    if not has_duration:
        rank = min(rank, 1)
        limitations.append("No usable duration samples were available.")
    if duration_excluded_count:
        limitations.append(
            f"{duration_excluded_count} duration sample(s) were excluded by behavior rules."
        )
    if not has_callback_data:
        limitations.append("Callback-health penalty omitted because callback data was unavailable.")
    if not has_argument_features:
        limitations.append("Argument anomaly rate omitted because argument feature data was unavailable.")

    return ("low", "medium", "high")[rank], reasons, limitations


def analyze(
    task_events: list[dict],
    result_events: list[dict],
    context: dict | None = None,
) -> dict:
    if context is None:
        context = build_analyzer_context()

    registry = context["behavior_registry"]
    action_registry = FrictionScoreRegistry.from_path()
    config = context.get("friction_score", {})
    weights: dict[str, float] = dict(config.get("weights", {}))
    thresholds: dict[str, int] = dict(config.get("sample_confidence_thresholds", {}))
    duration_caps: dict[str, float] = dict(config.get("duration_caps", {}))
    median_cap = float(duration_caps.get("median_seconds", 300.0))
    p95_cap = float(duration_caps.get("p95_seconds", 900.0))

    task_by_id = index_tasks_by_key(task_events)
    results_by_task = index_results_by_key(result_events)

    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "tasks": [],
            "results": [],
            "durations": [],
            "duration_excluded_count": 0,
            "argument_feature_count": 0,
            "argument_anomaly_count": 0,
            "retry_attempt_count": 0,
            "retry_sequence_count": 0,
            "retry_success_count": 0,
        }
    )

    for result in result_events:
        task = task_by_id.get(_task_key(result))
        if task is None:
            continue
        command_name = analyzer_command_group(task)
        bucket = buckets[command_name]
        bucket["tasks"].append(task)
        bucket["results"].append(result)

        has_arg_feature, is_arg_anomaly = _argument_feature_state(task)
        if has_arg_feature:
            bucket["argument_feature_count"] += 1
            if is_arg_anomaly:
                bucket["argument_anomaly_count"] += 1

        behavior = registry.resolve({
            "source": task.get("source", ""),
            "tool_name": task.get("tool_name", ""),
            "command_name": command_name,
        })
        if behavior.command_duration.get("mode") == "exclude_from_friction":
            bucket["duration_excluded_count"] += 1
            continue

        duration = duration_from_task_result(task, result, max_seconds=MAX_WALL_CLOCK_SECONDS)
        if duration is None:
            continue
        bucket["durations"].append(duration)

    for _group_key, sequence in iter_retry_sequences(
        task_events, RETRY_WINDOW_SECONDS, retry_sequence_group_key
    ):
        command_name = analyzer_command_group(sequence[0])
        statuses = [
            results_by_task.get(_task_key(task), {}).get("status", "unknown")
            for task in sequence
        ]
        bucket = buckets[command_name]
        bucket["retry_sequence_count"] += 1
        bucket["retry_attempt_count"] += len(sequence) - 1
        if any(status == "error" for status in statuses) and statuses[-1] == "success":
            bucket["retry_success_count"] += 1

    unhealthy_callbacks: set[str] = set()
    tasks_by_callback: dict[str, list[dict]] = defaultdict(list)
    for task in task_events:
        if "callback_id" in task:
            tasks_by_callback[_callback_key(task)].append(task)
    for callback_key, tasks in tasks_by_callback.items():
        tasks.sort(key=lambda task: task.get("timestamp", ""))
        trailing = 0
        for task in reversed(tasks):
            if task.get("command_name") == "exit":
                break
            status = results_by_task.get(_task_key(task), {}).get("status", "unknown")
            if status == "success":
                break
            trailing += 1
        if trailing >= CONSECUTIVE_FAILURE_THRESHOLD:
            unhealthy_callbacks.add(callback_key)

    commands = []
    data_coverage = {
        "commands_with_duration": 0,
        "commands_with_callback_data": 0,
        "commands_with_argument_features": 0,
    }

    for command_name in sorted(buckets):
        bucket = buckets[command_name]
        results = bucket["results"]
        total_executions = len(results)
        if total_executions == 0:
            continue

        statuses = Counter(result.get("status", "unknown") for result in results)
        failure_rate = statuses.get("error", 0) / total_executions
        unknown_rate = statuses.get("unknown", 0) / total_executions

        retry_density = min(1.0, bucket["retry_attempt_count"] / total_executions)
        retry_to_success_rate = (
            bucket["retry_success_count"] / bucket["retry_sequence_count"]
            if bucket["retry_sequence_count"]
            else 0.0
        )

        durations = bucket["durations"]
        has_duration = bool(durations)
        if has_duration:
            data_coverage["commands_with_duration"] += 1
        median_duration = round(statistics.median(durations), 2) if durations else 0.0
        p95_duration = round(_pct(durations, 0.95), 2) if durations else 0.0

        tasks = bucket["tasks"]
        callback_tasks = [task for task in tasks if "callback_id" in task]
        has_callback_data = bool(callback_tasks)
        if has_callback_data:
            data_coverage["commands_with_callback_data"] += 1
        callback_health_penalty = (
            sum(1 for task in callback_tasks if _callback_key(task) in unhealthy_callbacks) / len(callback_tasks)
            if callback_tasks
            else 0.0
        )

        has_argument_features = bucket["argument_feature_count"] > 0
        if has_argument_features:
            data_coverage["commands_with_argument_features"] += 1
        argument_anomaly_rate = (
            bucket["argument_anomaly_count"] / bucket["argument_feature_count"]
            if bucket["argument_feature_count"]
            else 0.0
        )

        component_values = {
            "failure_rate": _clamp01(failure_rate),
            "retry_density": _clamp01(retry_density),
            "retry_to_success_rate": _clamp01(retry_to_success_rate),
            "p95_duration": _clamp01(p95_duration / p95_cap if has_duration else 0.0),
            "median_duration": _clamp01(median_duration / median_cap if has_duration else 0.0),
            "callback_health_penalty": _clamp01(callback_health_penalty),
            "argument_anomaly_rate": _clamp01(argument_anomaly_rate),
        }
        available = {
            "failure_rate",
            "retry_density",
            "retry_to_success_rate",
        }
        if has_duration:
            available.update({"p95_duration", "median_duration"})
        if has_callback_data:
            available.add("callback_health_penalty")
        if has_argument_features:
            available.add("argument_anomaly_rate")

        weighted_impacts = {
            key: component_values[key] * float(weights.get(key, 0.0))
            for key in available
        }
        weight_total = sum(float(weights.get(key, 0.0)) for key in available)
        score = round((sum(weighted_impacts.values()) / weight_total * 100.0) if weight_total else 0.0, 1)

        confidence, confidence_reasons, limitations = _confidence(
            total_executions=total_executions,
            unknown_rate=unknown_rate,
            has_duration=has_duration,
            has_callback_data=has_callback_data,
            has_argument_features=has_argument_features,
            duration_excluded_count=bucket["duration_excluded_count"],
            thresholds=thresholds,
        )

        drivers = [
            {
                "component": key,
                "value": round(component_values[key], 4),
                "impact": round(impact, 2),
                "label": _driver_label(key, component_values[key], impact),
            }
            for key, impact in sorted(weighted_impacts.items(), key=lambda item: item[1], reverse=True)
            if impact > 0
        ][:3]

        tool_names = sorted({str(task.get("tool_name", "") or "unknown") for task in tasks})
        sources = sorted({str(task.get("source", "") or "unknown") for task in tasks})
        recommended_action = _recommend_action(
            confidence=confidence,
            total_executions=total_executions,
            failure_rate=failure_rate,
            retry_density=retry_density,
            retry_to_success_rate=retry_to_success_rate,
            callback_health_penalty=callback_health_penalty,
            argument_anomaly_rate=argument_anomaly_rate,
            score=score,
        )
        action_override = None
        action_rule = action_registry.first_match(
            command_name=command_name,
            tool_names=tool_names,
            sources=sources,
        )
        if action_rule and recommended_action in action_rule.suppress_actions:
            action_override = {
                "rule": action_rule.name,
                "original_action": recommended_action,
                "reason": action_rule.reason,
            }
            recommended_action = action_rule.fallback_action

        commands.append({
            "command_name": command_name,
            "tool_names": tool_names,
            "sources": sources,
            "total_executions": total_executions,
            "failure_rate": round(failure_rate, 4),
            "retry_density": round(retry_density, 4),
            "retry_to_success_rate": round(retry_to_success_rate, 4),
            "median_duration_seconds": median_duration,
            "p95_duration_seconds": p95_duration,
            "callback_health_penalty": round(callback_health_penalty, 4),
            "argument_anomaly_rate": round(argument_anomaly_rate, 4),
            "score": score,
            "confidence": confidence,
            "confidence_reasons": confidence_reasons,
            "limitations": limitations,
            "drivers": drivers,
            "recommended_action": recommended_action,
            "action_override": action_override,
        })

    commands.sort(key=lambda row: (-row["score"], -row["total_executions"], row["command_name"]))

    return {
        "analyzer": "friction_score",
        "summary": {
            "commands_scored": len(commands),
            "top_score": commands[0]["score"] if commands else 0.0,
            "weights": weights,
            "data_coverage": data_coverage,
        },
        "metadata": {
            "duration_caps": {
                "median_seconds": median_cap,
                "p95_seconds": p95_cap,
            },
            "retry_window_seconds": RETRY_WINDOW_SECONDS,
            "consecutive_failure_threshold": CONSECUTIVE_FAILURE_THRESHOLD,
            "behavior_registry": context.get("behavior_registry_metadata", {}),
            "friction_score_registry": action_registry.metadata(),
        },
        "commands": commands,
    }
