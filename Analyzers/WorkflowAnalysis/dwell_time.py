"""
DwellTime — Measures time gaps between consecutive operator commands.

Calculates "think time" between task submissions to identify friction points
where operators pause (context switching, confusion, tool failures). Filters
automated sequences (<1s) to focus on human decision-making delays.

Reports global statistics (mean, median, p95, p99, outliers) to answer:
How much operator friction exists in this engagement?
"""

import statistics
from collections import defaultdict
from datetime import datetime


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    """Calculate dwell time statistics between consecutive operator commands.

    Args:
        task_events: List of normalized task event dicts (must have task_id, command_name, timestamp).
        result_events: List of normalized result event dicts (unused but required for interface consistency).

    Returns:
        Dict with analyzer name, metadata, and global dwell time statistics.
    """
    # Sort tasks chronologically within each operation.
    ordered_by_operation = _group_and_sort_tasks(task_events)
    events_analyzed = sum(len(tasks) for tasks in ordered_by_operation.values())

    if events_analyzed < 2:
        # Need at least 2 tasks to calculate dwell times
        return {
            "analyzer": "dwell_time",
            "metadata": {
                "events_analyzed": events_analyzed,
                "dwell_count": 0,
                "min_threshold_seconds": 1.0,
                "max_threshold_seconds": 14400.0,
            },
            "global_statistics": _empty_statistics(),
        }

    dwells = []
    for operation_id, ordered_tasks in ordered_by_operation.items():
        for i in range(len(ordered_tasks) - 1):
            from_task = ordered_tasks[i]
            to_task = ordered_tasks[i + 1]

            dwell_seconds = _time_diff_seconds(from_task["timestamp"], to_task["timestamp"])

            # Filter negative dwells (clock skew), dwells < 1.0s (automated sequences),
            # and dwells >= 14400.0s (overnight/weekend session breaks — not operator friction)
            if dwell_seconds < 1.0 or dwell_seconds >= 14400.0:
                continue

            dwells.append({
                "operation_id": operation_id,
                "from_task_id": from_task["task_id"],
                "from_display_id": from_task.get("display_id", 0),
                "from_command": from_task["command_name"],
                "from_timestamp": from_task["timestamp"],
                "from_arguments_raw": from_task.get("arguments_raw", ""),
                "to_task_id": to_task["task_id"],
                "to_display_id": to_task.get("display_id", 0),
                "to_command": to_task["command_name"],
                "to_timestamp": to_task["timestamp"],
                "to_arguments_raw": to_task.get("arguments_raw", ""),
                "dwell_seconds": dwell_seconds,
            })

    # Compute statistics
    statistics_result = _compute_statistics(dwells) if dwells else _empty_statistics()

    return {
        "analyzer": "dwell_time",
        "metadata": {
            "events_analyzed": events_analyzed,
            "dwell_count": len(dwells),
            "min_threshold_seconds": 1.0,
            "max_threshold_seconds": 14400.0,
        },
        "global_statistics": statistics_result,
    }


def _group_and_sort_tasks(task_events: list[dict]) -> dict[int, list[dict]]:
    """Group tasks by operation and sort each group by timestamp.

    Args:
        task_events: List of task event dicts.

    Returns:
        Mapping of operation_id -> tasks sorted chronologically by timestamp.

    Raises:
        ValueError: If any task has null or empty timestamp.
    """
    for t in task_events:
        ts = t.get("timestamp")
        if ts is None or ts == "":
            raise ValueError(f"Task {t.get('task_id')} has null or empty timestamp")

    grouped: dict[int, list[dict]] = defaultdict(list)
    for t in task_events:
        grouped[t.get("operation_id", 0)].append(t)

    return {
        operation_id: sorted(tasks, key=lambda e: e["timestamp"])
        for operation_id, tasks in grouped.items()
    }


def _time_diff_seconds(ts1: str, ts2: str) -> float:
    """Calculate time difference in seconds between two ISO 8601 timestamps.

    Args:
        ts1: Earlier timestamp in ISO 8601 format.
        ts2: Later timestamp in ISO 8601 format.

    Returns:
        Time difference in seconds (ts2 - ts1).
    """
    dt1 = datetime.fromisoformat(ts1.replace("Z", "+00:00"))
    dt2 = datetime.fromisoformat(ts2.replace("Z", "+00:00"))
    return (dt2 - dt1).total_seconds()


def _compute_statistics(dwells: list[dict]) -> dict:
    """Compute statistical summary for dwell times.

    Args:
        dwells: List of dwell event dicts with dwell_seconds field.

    Returns:
        Dict containing dwell count, mean, median, percentiles, min, max, stdev, and outliers.
    """
    if not dwells:
        return _empty_statistics()

    dwell_values = [d["dwell_seconds"] for d in dwells]
    dwell_count = len(dwell_values)

    mean_val = statistics.mean(dwell_values)
    median_val = statistics.median(dwell_values)
    min_val = min(dwell_values)
    max_val = max(dwell_values)

    # Calculate percentiles
    sorted_dwells = sorted(dwell_values)
    p95_val = _percentile(sorted_dwells, 0.95)
    p99_val = _percentile(sorted_dwells, 0.99)

    # Calculate standard deviation (need at least 2 values)
    stdev_val = statistics.stdev(dwell_values) if dwell_count >= 2 else 0.0

    # Detect outliers (mean + 3*stdev threshold)
    outlier_events = []
    if dwell_count >= 2:
        threshold = mean_val + (3 * stdev_val)
        outlier_dwells = [d for d in dwells if d["dwell_seconds"] > threshold]
        # Sort outliers descending by dwell time
        outlier_dwells.sort(key=lambda d: d["dwell_seconds"], reverse=True)

        # Build outlier event list with full context
        outlier_events = [
            {
                "operation_id": d.get("operation_id", 0),
                "from_task_id": d["from_task_id"],
                "from_display_id": d["from_display_id"],
                "from_command": d["from_command"],
                "from_timestamp": d["from_timestamp"],
                "from_arguments_raw": d["from_arguments_raw"],
                "to_task_id": d["to_task_id"],
                "to_display_id": d["to_display_id"],
                "to_command": d["to_command"],
                "to_timestamp": d["to_timestamp"],
                "to_arguments_raw": d["to_arguments_raw"],
                "dwell_seconds": round(d["dwell_seconds"], 2),
            }
            for d in outlier_dwells
        ]

    return {
        "dwell_count": dwell_count,
        "mean_seconds": round(mean_val, 2),
        "median_seconds": round(median_val, 2),
        "p95_seconds": round(p95_val, 2),
        "p99_seconds": round(p99_val, 2),
        "max_seconds": round(max_val, 2),
        "min_seconds": round(min_val, 2),
        "stdev_seconds": round(stdev_val, 2),
        "outlier_count": len(outlier_events),
        "outlier_events": outlier_events,
    }


def _percentile(sorted_values: list[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0

    index = int(percentile * len(sorted_values))
    if index >= len(sorted_values):
        index = len(sorted_values) - 1

    return sorted_values[index]


def _empty_statistics() -> dict:
    return {
        "dwell_count": 0,
        "mean_seconds": 0.0,
        "median_seconds": 0.0,
        "p95_seconds": 0.0,
        "p99_seconds": 0.0,
        "max_seconds": 0.0,
        "min_seconds": 0.0,
        "stdev_seconds": 0.0,
        "outlier_count": 0,
        "outlier_events": [],
    }
