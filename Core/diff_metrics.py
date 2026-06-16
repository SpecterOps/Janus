"""Derive comparable run metrics from Janus artifacts."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from Core.analyzer_command_grouping import analyzer_command_group, retry_sequence_group_key
from Core.diff_load import RunArtifacts

MAX_WALL_CLOCK_SECONDS = 14400.0
RETRY_WINDOW_SECONDS = 300.0
CONSECUTIVE_FAILURE_THRESHOLD = 3


def derive_run_metrics(artifacts: RunArtifacts) -> dict[str, Any]:
    task_events = artifacts.task_events
    result_events = artifacts.result_events
    task_by_key = {_task_key(task): task for task in task_events}
    result_by_key = {_task_key(result): result for result in result_events}

    commands = _derive_command_status_metrics(task_events, result_events, task_by_key)
    _merge_failure_analyzer(commands, artifacts)
    _merge_duration_metrics(commands, artifacts, task_by_key, result_events)
    _merge_retry_metrics(commands, artifacts, task_events, result_by_key)
    _merge_friction_metrics(commands, artifacts)
    _merge_dwell_metrics(commands, artifacts, task_events)
    _merge_argument_metrics(commands, artifacts)
    for entry in commands.values():
        _finish_status_rates(entry)

    source_metrics = _derive_source_metrics(task_events, result_events, task_by_key, artifacts)
    aggregate = _derive_aggregate_metrics(artifacts, task_events, result_events, commands)

    return {
        "aggregate": aggregate,
        "commands": {key: commands[key] for key in sorted(commands)},
        "sources": {key: source_metrics[key] for key in sorted(source_metrics)},
        "data_quality": artifacts.data_quality,
    }


def _derive_command_status_metrics(
    task_events: list[dict[str, Any]],
    result_events: list[dict[str, Any]],
    task_by_key: dict[tuple[Any, Any], dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = defaultdict(_empty_command)

    for task in task_events:
        command = analyzer_command_group(task)
        entry = buckets[command]
        entry["task_count"] += 1
        entry["sources"].add(str(task.get("source") or "unknown"))
        entry["tool_names"].add(str(task.get("tool_name") or "unknown"))

    for result in result_events:
        task = task_by_key.get(_task_key(result))
        if task is None:
            continue
        command = analyzer_command_group(task)
        entry = buckets[command]
        status = str(result.get("status") or "unknown")
        if status not in {"success", "error", "unknown"}:
            status = "unknown"
        entry["execution_count"] += 1
        entry[f"{status}_count"] += 1
        entry["sources"].add(str(result.get("source") or task.get("source") or "unknown"))

    for entry in buckets.values():
        _finish_status_rates(entry)
    return buckets


def _merge_failure_analyzer(commands: dict[str, dict[str, Any]], artifacts: RunArtifacts) -> None:
    payload = artifacts.analyzers.get("command-failure-summary", {})
    for command, stats in (payload.get("commands") or {}).items():
        if not isinstance(stats, dict):
            continue
        entry = commands.setdefault(str(command), _empty_command())
        for key in ("execution_count", "success_count", "error_count", "unknown_count"):
            if key in stats:
                entry[key] = _safe_int(stats.get(key))
        entry["failure_rate"] = _safe_float(stats.get("failure_rate"))
        _finish_status_rates(entry)


def _merge_duration_metrics(
    commands: dict[str, dict[str, Any]],
    artifacts: RunArtifacts,
    task_by_key: dict[tuple[Any, Any], dict[str, Any]],
    result_events: list[dict[str, Any]],
) -> None:
    payload = artifacts.analyzers.get("command-duration", {})
    durations = payload.get("durations")
    if isinstance(durations, dict) and durations:
        for command, stats in durations.items():
            if not isinstance(stats, dict):
                continue
            samples = _safe_int(stats.get("execution_count"))
            entry = commands.setdefault(str(command), _empty_command())
            if samples > 0:
                entry["duration_sample_count"] = samples
                entry["median_duration_seconds"] = _safe_float(stats.get("median_seconds"))
                entry["p95_duration_seconds"] = _safe_float(stats.get("p95_seconds"))
        return

    by_command: dict[str, list[float]] = defaultdict(list)
    for result in result_events:
        task = task_by_key.get(_task_key(result))
        if task is None:
            continue
        start = task.get("processing_timestamp") or task.get("timestamp")
        duration = _time_diff_seconds(start, result.get("timestamp"))
        if duration is None or duration < 0 or duration > MAX_WALL_CLOCK_SECONDS:
            continue
        by_command[analyzer_command_group(task)].append(duration)
    for command, values in by_command.items():
        entry = commands.setdefault(command, _empty_command())
        entry["duration_sample_count"] = len(values)
        entry["median_duration_seconds"] = round(statistics.median(values), 2)
        entry["p95_duration_seconds"] = round(_percentile(values, 0.95), 2)


def _merge_retry_metrics(
    commands: dict[str, dict[str, Any]],
    artifacts: RunArtifacts,
    task_events: list[dict[str, Any]],
    result_by_key: dict[tuple[Any, Any], dict[str, Any]],
) -> None:
    if task_events:
        by_group: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
        for task in task_events:
            by_group[retry_sequence_group_key(task)].append(task)

        for tasks in by_group.values():
            tasks.sort(key=lambda task: task.get("timestamp", ""))
            sequence: list[dict[str, Any]] = []

            def flush() -> None:
                if len(sequence) < 2:
                    return
                command = analyzer_command_group(sequence[0])
                entry = commands.setdefault(command, _empty_command())
                entry["retry_sequence_count"] += 1
                entry["retry_attempt_count"] += len(sequence) - 1
                statuses = [
                    str(result_by_key.get(_task_key(task), {}).get("status") or "unknown")
                    for task in sequence
                ]
                if any(status == "error" for status in statuses) and statuses[-1] == "success":
                    entry["retry_success_count"] += 1

            for task in tasks:
                if not sequence:
                    sequence = [task]
                    continue
                gap = _time_diff_seconds(sequence[-1].get("timestamp"), task.get("timestamp"))
                if gap is not None and gap <= RETRY_WINDOW_SECONDS:
                    sequence.append(task)
                    continue
                flush()
                sequence = [task]
            flush()
    else:
        payload = artifacts.analyzers.get("command-retry-success", {})
        for pattern in payload.get("retry_patterns") or []:
            if not isinstance(pattern, dict):
                continue
            command = str(pattern.get("command_name") or "unknown")
            attempts = max(0, _safe_int(pattern.get("attempt_count")) - 1)
            entry = commands.setdefault(command, _empty_command())
            entry["retry_sequence_count"] += 1
            entry["retry_attempt_count"] += attempts
            if pattern.get("final_status") == "success":
                entry["retry_success_count"] += 1

    for entry in commands.values():
        executions = _safe_int(entry.get("execution_count"))
        sequences = _safe_int(entry.get("retry_sequence_count"))
        attempts = _safe_int(entry.get("retry_attempt_count"))
        successes = _safe_int(entry.get("retry_success_count"))
        entry["retry_density"] = round(attempts / executions, 4) if executions else None
        entry["retry_to_success_rate"] = round(successes / sequences, 4) if sequences else None


def _merge_friction_metrics(commands: dict[str, dict[str, Any]], artifacts: RunArtifacts) -> None:
    payload = artifacts.analyzers.get("friction-score", {})
    for row in payload.get("commands") or []:
        if not isinstance(row, dict):
            continue
        command = str(row.get("command_name") or "unknown")
        entry = commands.setdefault(command, _empty_command())
        for key in (
            "retry_density",
            "retry_to_success_rate",
            "callback_health_penalty",
            "argument_anomaly_rate",
        ):
            if key in row:
                entry[key] = _safe_float(row.get(key))
        entry["friction_score"] = _safe_float(row.get("score"))
        if row.get("confidence"):
            entry["friction_confidence"] = str(row.get("confidence"))


def _merge_dwell_metrics(
    commands: dict[str, dict[str, Any]],
    artifacts: RunArtifacts,
    task_events: list[dict[str, Any]],
) -> None:
    if not task_events:
        stats = (artifacts.analyzers.get("dwell-time", {}).get("global_statistics") or {})
        if stats:
            return

    grouped: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for task in task_events:
        grouped[task.get("operation_id", 0)].append(task)

    by_command: dict[str, list[float]] = defaultdict(list)
    for tasks in grouped.values():
        tasks.sort(key=lambda task: task.get("timestamp", ""))
        for idx in range(len(tasks) - 1):
            dwell = _time_diff_seconds(tasks[idx].get("timestamp"), tasks[idx + 1].get("timestamp"))
            if dwell is None or dwell < 1.0 or dwell >= MAX_WALL_CLOCK_SECONDS:
                continue
            by_command[analyzer_command_group(tasks[idx])].append(dwell)

    for command, values in by_command.items():
        entry = commands.setdefault(command, _empty_command())
        entry["dwell_sample_count"] = len(values)
        entry["dwell_median_seconds"] = round(statistics.median(values), 2)
        entry["dwell_p95_seconds"] = round(_percentile(values, 0.95), 2)


def _merge_argument_metrics(commands: dict[str, dict[str, Any]], artifacts: RunArtifacts) -> None:
    by_command: Counter[str] = Counter()
    entropy = artifacts.analyzers.get("parameter-entropy", {})
    for finding in entropy.get("findings") or []:
        if isinstance(finding, dict):
            by_command[str(finding.get("command_name") or "unknown")] += 1

    profile = artifacts.analyzers.get("argument-position-profile", {})
    for finding in profile.get("findings") or []:
        if isinstance(finding, dict):
            by_command[str(finding.get("command_name") or "unknown")] += 1

    for command, count in by_command.items():
        entry = commands.setdefault(command, _empty_command())
        entry["argument_anomaly_count"] = count
        denominator = max(_safe_int(entry.get("task_count")), _safe_int(entry.get("execution_count")))
        entry["argument_anomaly_rate"] = round(count / denominator, 4) if denominator else None


def _derive_source_metrics(
    task_events: list[dict[str, Any]],
    result_events: list[dict[str, Any]],
    task_by_key: dict[tuple[Any, Any], dict[str, Any]],
    artifacts: RunArtifacts,
) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"task_count": 0, "result_count": 0, "success_count": 0, "error_count": 0, "unknown_count": 0}
    )
    for task in task_events:
        buckets[str(task.get("source") or "unknown")]["task_count"] += 1
    for result in result_events:
        task = task_by_key.get(_task_key(result), {})
        source = str(result.get("source") or task.get("source") or "unknown")
        entry = buckets[source]
        status = str(result.get("status") or "unknown")
        if status not in {"success", "error", "unknown"}:
            status = "unknown"
        entry["result_count"] += 1
        entry[f"{status}_count"] += 1

    for entry in artifacts.data_quality:
        source = str(entry.get("source") or "unknown")
        bucket = buckets[source]
        if not bucket["result_count"]:
            status_distribution = entry.get("status_distribution") or {}
            for key in ("success", "error", "unknown"):
                bucket[f"{key}_count"] = _safe_int(status_distribution.get(key))
            bucket["result_count"] = sum(bucket[f"{key}_count"] for key in ("success", "error", "unknown"))
        bucket["data_quality_unknown_status_percent"] = _safe_float(entry.get("unknown_status_percent"))
        bucket["data_quality_warning_count"] = len(entry.get("warnings") or [])

    for entry in buckets.values():
        result_count = entry["result_count"]
        entry["unknown_status_percentage"] = (
            round(entry["unknown_count"] / result_count, 4) if result_count else 0.0
        )
    return buckets


def _derive_aggregate_metrics(
    artifacts: RunArtifacts,
    task_events: list[dict[str, Any]],
    result_events: list[dict[str, Any]],
    commands: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    statuses = Counter(str(result.get("status") or "unknown") for result in result_events)
    result_count = len(result_events)
    callback_payload = artifacts.analyzers.get("callback-health", {})
    callback_summary = callback_payload.get("summary") or {}
    av_summary = artifacts.analyzers.get("av-tracker", {}).get("summary") or {}
    dwell_stats = artifacts.analyzers.get("dwell-time", {}).get("global_statistics") or {}

    callback_loss = _safe_int(callback_summary.get("callbacks_with_consecutive_failures"))
    if callback_loss == 0 and task_events:
        callback_loss = _fallback_callback_loss(task_events, result_events)

    return {
        "total_task_count": len(task_events) or _safe_int(artifacts.bundle.get("task_count")),
        "total_result_count": result_count or _safe_int(artifacts.bundle.get("result_count")),
        "command_entity_count": len(commands),
        "success_count": statuses.get("success", 0),
        "error_count": statuses.get("error", 0),
        "unknown_count": statuses.get("unknown", 0),
        "unknown_status_percentage": round(statuses.get("unknown", 0) / result_count, 4) if result_count else 0.0,
        "callback_loss_adjacent_events": callback_loss,
        "detection_adjacent_events": _safe_int(av_summary.get("detection_count")),
        "callbacks_with_detections": _safe_int(av_summary.get("callbacks_with_detections")),
        "dwell_median_seconds": _nullable_float(dwell_stats.get("median_seconds")),
        "dwell_p95_seconds": _nullable_float(dwell_stats.get("p95_seconds")),
        "parser_quality_warning_count": sum(len(entry.get("warnings") or []) for entry in artifacts.data_quality),
    }


def _fallback_callback_loss(
    task_events: list[dict[str, Any]],
    result_events: list[dict[str, Any]],
) -> int:
    result_by_key = {_task_key(result): result for result in result_events}
    by_callback: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for task in task_events:
        if "callback_id" in task:
            by_callback[f"{task.get('operation_id', 0)}:{task.get('callback_id', 0)}"].append(task)

    loss_count = 0
    for tasks in by_callback.values():
        tasks.sort(key=lambda task: task.get("timestamp", ""))
        trailing = 0
        for task in reversed(tasks):
            if task.get("command_name") == "exit":
                break
            status = str(result_by_key.get(_task_key(task), {}).get("status") or "unknown")
            if status == "success":
                break
            trailing += 1
        if trailing >= CONSECUTIVE_FAILURE_THRESHOLD:
            loss_count += 1
    return loss_count


def _empty_command() -> dict[str, Any]:
    return {
        "task_count": 0,
        "execution_count": 0,
        "success_count": 0,
        "error_count": 0,
        "unknown_count": 0,
        "failure_rate": None,
        "success_rate": None,
        "unknown_status_percentage": None,
        "sources": set(),
        "tool_names": set(),
        "retry_sequence_count": 0,
        "retry_attempt_count": 0,
        "retry_success_count": 0,
    }


def _finish_status_rates(entry: dict[str, Any]) -> None:
    executions = _safe_int(entry.get("execution_count"))
    if executions <= 0:
        entry["failure_rate"] = None
        entry["success_rate"] = None
        entry["unknown_status_percentage"] = None
    else:
        entry["failure_rate"] = round(_safe_int(entry.get("error_count")) / executions, 4)
        entry["success_rate"] = round(_safe_int(entry.get("success_count")) / executions, 4)
        entry["unknown_status_percentage"] = round(_safe_int(entry.get("unknown_count")) / executions, 4)
    if isinstance(entry.get("sources"), set):
        entry["sources"] = sorted(entry["sources"])
    if isinstance(entry.get("tool_names"), set):
        entry["tool_names"] = sorted(entry["tool_names"])


def _task_key(event: dict[str, Any]) -> tuple[Any, Any]:
    return (event.get("operation_id", 0), event.get("task_id"))


def _time_diff_seconds(ts1: Any, ts2: Any) -> float | None:
    try:
        dt1 = datetime.fromisoformat(str(ts1).replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(str(ts2).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (dt2 - dt1).total_seconds()


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = int(percentile * len(sorted_values))
    if index >= len(sorted_values):
        index = len(sorted_values) - 1
    return sorted_values[index]


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


def _nullable_float(value: Any) -> float | None:
    if value is None:
        return None
    return _safe_float(value)
