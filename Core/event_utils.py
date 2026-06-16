"""Shared helpers for normalized Janus event dictionaries."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def task_key(event: dict[str, Any]) -> tuple[Any, Any]:
    return (event.get("operation_id", 0), event["task_id"])


def optional_task_key(event: dict[str, Any]) -> tuple[Any, Any]:
    return (event.get("operation_id", 0), event.get("task_id"))


def callback_key(task: dict[str, Any]) -> str:
    return f"{task.get('operation_id', 0)}:{task.get('callback_id', 0)}"


def seconds_between(ts1: Any, ts2: Any) -> float | None:
    try:
        dt1 = datetime.fromisoformat(str(ts1).replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(str(ts2).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (dt2 - dt1).total_seconds()


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    return sorted_values[min(int(pct * len(sorted_values)), len(sorted_values) - 1)]
