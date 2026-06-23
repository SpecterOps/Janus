"""Shared helpers for normalized Janus event dictionaries."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any


def task_key(event: dict[str, Any]) -> tuple[Any, Any]:
    return (event.get("operation_id", 0), event["task_id"])


def optional_task_key(event: dict[str, Any]) -> tuple[Any, Any]:
    return (event.get("operation_id", 0), event.get("task_id"))


def callback_key(task: dict[str, Any]) -> str:
    return f"{task.get('operation_id', 0)}:{task.get('callback_id', 0)}"


def index_tasks_by_key(task_events: list[dict[str, Any]]) -> dict[tuple[Any, Any], dict[str, Any]]:
    return {task_key(task): task for task in task_events}


def index_results_by_key(result_events: list[dict[str, Any]]) -> dict[tuple[Any, Any], dict[str, Any]]:
    return {task_key(result): result for result in result_events}


def iter_joined_results(
    task_events: list[dict[str, Any]],
    result_events: list[dict[str, Any]],
):
    task_by_id = index_tasks_by_key(task_events)
    for result in result_events:
        task = task_by_id.get(task_key(result))
        if task is not None:
            yield task, result


def group_tasks_by_operation_sorted(
    task_events: list[dict[str, Any]],
    require_timestamp: bool = True,
) -> dict[Any, list[dict[str, Any]]]:
    if require_timestamp:
        for task in task_events:
            ts = task.get("timestamp")
            if ts is None or ts == "":
                raise ValueError(f"Task {task.get('task_id')} has null or empty timestamp")

    grouped: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for task in task_events:
        grouped[task.get("operation_id", 0)].append(task)
    return {
        operation_id: sorted(tasks, key=lambda task: task["timestamp"])
        for operation_id, tasks in grouped.items()
    }


def seconds_between(ts1: Any, ts2: Any) -> float | None:
    try:
        dt1 = datetime.fromisoformat(str(ts1).replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(str(ts2).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (dt2 - dt1).total_seconds()


def duration_from_task_result(
    task: dict[str, Any],
    result: dict[str, Any],
    prefer_processing_timestamp: bool = True,
    max_seconds: float | None = None,
) -> float | None:
    start_ts = task.get("processing_timestamp") if prefer_processing_timestamp else None
    duration = seconds_between(start_ts or task.get("timestamp", ""), result.get("timestamp", ""))
    if duration is None or duration < 0:
        return None
    if max_seconds is not None and duration > max_seconds:
        return None
    return duration


def iter_retry_sequences(
    task_events: list[dict[str, Any]],
    window_seconds: float,
    key_fn,
):
    groups: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for task in task_events:
        groups[key_fn(task)].append(task)

    for group_key, tasks in groups.items():
        tasks.sort(key=lambda task: task.get("timestamp", ""))
        sequence: list[dict[str, Any]] = []
        for task in tasks:
            if not sequence:
                sequence = [task]
                continue
            gap = seconds_between(sequence[-1].get("timestamp", ""), task.get("timestamp", ""))
            if gap is not None and gap <= window_seconds:
                sequence.append(task)
                continue
            if len(sequence) >= 2:
                yield group_key, sequence
            sequence = [task]
        if len(sequence) >= 2:
            yield group_key, sequence


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    return sorted_values[min(int(pct * len(sorted_values)), len(sorted_values) - 1)]
