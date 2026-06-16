"""
OutlierContext — Enriches duration outliers with chronological context.

Uses outlier detection from command_duration analyzer. For each outlier, extracts
±5 task context window, builds sequence signature, and aggregates cross-outlier
patterns to answer: What typically happens before/after long-running commands?
"""

from collections import Counter

from Core.analyzer_command_grouping import analyzer_command_group
from Core.event_utils import seconds_between as _time_diff_seconds
from Core.event_utils import task_key as _task_key

from Analyzers.CommandAnalysis.command_duration import (
    analyze as command_duration_analyze,
)


def analyze(task_events: list[dict], result_events: list[dict], context: dict | None = None) -> dict:
    """Enrich duration outliers with context windows and pattern aggregations.

    Args:
        task_events: List of normalized task event dicts.
        result_events: List of normalized result event dicts.

    Returns:
        Dict with analyzer name, enriched outliers, and aggregations.
    """
    # 1. Sort and validate tasks
    ordered_tasks_by_operation, task_index = _build_ordered_task_index(task_events)

    # 2. Build duration lookup ((operation_id, task_id) -> duration_seconds)
    duration_by_task = _build_duration_lookup(task_events, result_events)

    # 3. Collect outliers from command_duration analyzer
    duration_result = command_duration_analyze(task_events, result_events, context)
    all_outliers: list[dict] = []
    for command_name, stats in duration_result["durations"].items():
        for evt in stats.get("outlier_events", []):
            row = {
                "operation_id": evt.get("operation_id", 0),
                "task_id": evt["task_id"],
                "display_id": evt.get("display_id", 0),
                "command_name": command_name,
                "duration_seconds": evt["duration_seconds"],
            }
            if evt.get("pty_shell_command"):
                row["pty_shell_command"] = evt["pty_shell_command"]
            all_outliers.append(row)

    # 4–6. Extract context, build signature for each outlier
    enriched: list[dict] = []
    preceding_counts: Counter = Counter()
    following_counts: Counter = Counter()
    chain_counts: Counter = Counter()

    for outlier in all_outliers:
        scoped_task_id = (outlier.get("operation_id", 0), outlier["task_id"])
        if scoped_task_id not in task_index:
            continue  # Orphan or ordering anomaly
        ordered_tasks = ordered_tasks_by_operation[outlier.get("operation_id", 0)]
        i = task_index[scoped_task_id]

        preceding_context = _extract_context(
            ordered_tasks, duration_by_task, max(0, i - 5), i
        )
        following_context = _extract_context(
            ordered_tasks, duration_by_task, i + 1, min(len(ordered_tasks), i + 6)
        )

        sequence_signature = _build_sequence_signature(
            preceding_context, outlier["command_name"], following_context
        )

        enr = {
            "operation_id": outlier.get("operation_id", 0),
            "task_id": outlier["task_id"],
            "display_id": outlier.get("display_id", 0),
            "command_name": outlier["command_name"],
            "duration_seconds": outlier["duration_seconds"],
            "preceding_context": preceding_context,
            "following_context": following_context,
            "sequence_signature": sequence_signature,
        }
        if outlier.get("pty_shell_command"):
            enr["pty_shell_command"] = outlier["pty_shell_command"]
        enriched.append(enr)

        if preceding_context:
            preceding_counts[preceding_context[-1]["command_name"]] += 1
        if following_context:
            following_counts[following_context[0]["command_name"]] += 1
        if preceding_context and following_context:
            chain = (
                f"{preceding_context[-1]['command_name']} -> "
                f"{outlier['command_name']} -> "
                f"{following_context[0]['command_name']}"
            )
            chain_counts[chain] += 1

    # 7. Build aggregations
    aggregations = {
        "most_common_preceding_command": dict(preceding_counts),
        "most_common_following_command": dict(following_counts),
        "most_common_3step_chains": dict(chain_counts),
    }

    return {
        "analyzer": "outlier_context",
        "outliers": enriched,
        "aggregations": aggregations,
    }


def _build_ordered_task_index(task_events: list[dict]) -> tuple[dict[int, list[dict]], dict[tuple[int, int], int]]:
    """Sort tasks by timestamp per operation and build scoped task index lookup.

    Raises:
        ValueError: If any task has null/empty timestamp.
    """
    for t in task_events:
        ts = t.get("timestamp")
        if ts is None or ts == "":
            raise ValueError(f"Task {t.get('task_id')} has null or empty timestamp")

    ordered_by_operation: dict[int, list[dict]] = {}
    index_map: dict[tuple[int, int], int] = {}
    grouped: dict[int, list[dict]] = {}
    for t in task_events:
        grouped.setdefault(t.get("operation_id", 0), []).append(t)

    for operation_id, tasks in grouped.items():
        ordered = sorted(tasks, key=lambda e: e["timestamp"])
        ordered_by_operation[operation_id] = ordered
        for i, task in enumerate(ordered):
            index_map[_task_key(task)] = i

    return ordered_by_operation, index_map


def _build_duration_lookup(
    task_events: list[dict], result_events: list[dict]
) -> dict[tuple[int, int], float]:
    """Compute scoped task key -> duration_seconds from task and result timestamps.

    Uses processing_timestamp (agent pickup time) when available to exclude
    callback check-in overhead, falling back to the task submitted timestamp.
    """
    task_by_id: dict[tuple[int, int], str] = {}
    for t in task_events:
        start_ts = t.get("processing_timestamp") or t["timestamp"]
        task_by_id[_task_key(t)] = start_ts

    lookup: dict[tuple[int, int], float] = {}
    for r in result_events:
        task_id = _task_key(r)
        if task_id not in task_by_id:
            continue
        task_ts = task_by_id[task_id]
        result_ts = r["timestamp"]
        duration = _time_diff_seconds(task_ts, result_ts)
        if duration is not None and duration >= 0:
            lookup[task_id] = round(duration, 2)
    return lookup


def _extract_context(
    ordered_tasks: list[dict],
    duration_by_task: dict[tuple[int, int], float],
    start: int,
    end: int,
) -> list[dict]:
    """Extract lightweight context items for tasks[start:end]."""
    context = []
    for t in ordered_tasks[start:end]:
        duration = duration_by_task.get(_task_key(t))
        ctx = {
            "operation_id": t.get("operation_id", 0),
            "task_id": t["task_id"],
            "display_id": t.get("display_id", 0),
            "command_name": analyzer_command_group(t),
            "duration_seconds": duration,
        }
        if t.get("pty_synthetic"):
            ctx["pty_shell_command"] = t.get("command_name", "")
        context.append(ctx)
    return context


def _build_sequence_signature(
    preceding: list[dict], outlier_cmd: str, following: list[dict]
) -> str:
    """Build string signature: cmd1 -> cmd2 -> ... -> outlier -> ..."""
    parts = []
    for c in preceding:
        parts.append(c["command_name"])
    parts.append(outlier_cmd)
    for c in following:
        parts.append(c["command_name"])
    return " -> ".join(parts)
