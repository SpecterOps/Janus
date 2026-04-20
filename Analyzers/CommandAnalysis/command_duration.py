"""
CommandDuration — Analyzer 03.

Calculates execution time statistics for commands by joining task and result
events. Identifies slow commands that may indicate operator friction or
inefficient tooling.

Reports three duration tiers when data is available:

- wall_clock: result.timestamp - task.timestamp (includes callback overhead)
- agent: result.timestamp - task.processing_timestamp (pickup delay removed)
- estimated: agent - (sleep_interval / 2) (return delay estimated and removed)

Primary stats use the best available tier; wall_clock is always included for
reference.
"""

import re
import statistics
from collections import defaultdict
from datetime import datetime

from Core.analyzer_behavior_registry import build_analyzer_context
from Core.analyzer_command_grouping import analyzer_command_group
from Core.output_rule import copy_task_retention_fields

# Gaps longer than 4 hours between task submission and result are almost certainly
# overnight/session-break artefacts, not real execution time. Drop them so they
# don't inflate mean/p95/outlier statistics.
MAX_WALL_CLOCK_SECONDS = 14400.0


def _task_key(event: dict) -> tuple[int, int]:
    return (event.get("operation_id", 0), event["task_id"])


def analyze(task_events: list[dict], result_events: list[dict], context: dict | None = None) -> dict:
    if context is None:
        context = build_analyzer_context()

    registry = context["behavior_registry"]
    task_by_id: dict[tuple[int, int], dict] = {}
    for t in task_events:
        task_by_id[_task_key(t)] = {
            "operation_id": t.get("operation_id", 0),
            "source": t.get("source", ""),
            "tool_name": t.get("tool_name", ""),
            "command_name": t["command_name"],
            "analyzer_group": analyzer_command_group(t),
            "shell_command_name": t.get("command_name", ""),
            "pty_synthetic": bool(t.get("pty_synthetic")),
            "timestamp": t["timestamp"],
            "arguments_raw": t.get("arguments_raw", ""),
            "display_id": t.get("display_id", 0),
            "processing_timestamp": t.get("processing_timestamp", ""),
            "callback_sleep_info": t.get("callback_sleep_info", ""),
            **copy_task_retention_fields(t),
        }

    durations_by_command: dict[str, list[dict]] = defaultdict(list)
    excluded_by_command: dict[str, int] = defaultdict(int)
    registry_excluded_by_command: dict[str, int] = defaultdict(int)
    any_agent_duration = False

    for r in result_events:
        task_id = _task_key(r)
        if task_id not in task_by_id:
            continue

        task_info = task_by_id[task_id]
        result_timestamp = r["timestamp"]
        bucket = task_info["analyzer_group"]
        behavior = registry.resolve({
            "source": task_info["source"],
            "tool_name": task_info["tool_name"],
            "command_name": bucket,
        })

        if behavior.command_duration.get("mode") == "exclude_from_friction":
            # Keep the command visible in the output for traceability, but record
            # that its timings are expected (sleep, PTY session lifetime, etc.) rather
            # than operator friction.
            registry_excluded_by_command[bucket] += 1

        wall_clock = _time_diff_seconds(task_info["timestamp"], result_timestamp)
        if wall_clock < 0:
            continue
        if wall_clock > MAX_WALL_CLOCK_SECONDS:
            # Overnight / session-break gap — not real execution time; skip silently
            # but count it so callers can see data was excluded.
            excluded_by_command[bucket] += 1
            continue

        processing_ts = task_info["processing_timestamp"]
        agent_duration = None
        if processing_ts:
            agent_duration = _time_diff_seconds(processing_ts, result_timestamp)
            if agent_duration < 0:
                agent_duration = None
            else:
                any_agent_duration = True

        estimated_duration = None
        sleep_seconds = parse_sleep_info(task_info["callback_sleep_info"])
        if agent_duration is not None and sleep_seconds is not None:
            estimated_duration = max(0.0, agent_duration - (sleep_seconds / 2))

        primary = agent_duration if agent_duration is not None else wall_clock

        row = {
            "duration": primary,
            "wall_clock": wall_clock,
            "agent": agent_duration,
            "estimated": estimated_duration,
            "operation_id": task_info["operation_id"],
            "task_id": r["task_id"],
            "display_id": task_info["display_id"],
            "command_name": bucket,
            "arguments_raw": task_info["arguments_raw"],
            **copy_task_retention_fields(task_info),
        }
        if task_info.get("pty_synthetic"):
            row["pty_shell_command"] = task_info.get("shell_command_name", "")
        durations_by_command[bucket].append(row)

    command_stats = {}
    for command_name in sorted(durations_by_command):
        entries = durations_by_command[command_name]
        stats = _compute_stats(entries)
        stats["excluded_count"] = excluded_by_command.get(command_name, 0)
        stats["registry_excluded_count"] = registry_excluded_by_command.get(command_name, 0)
        command_stats[command_name] = stats

    # Commands that were entirely excluded (no valid entries) still get a record
    for command_name in sorted(set(excluded_by_command) | set(registry_excluded_by_command)):
        if command_name not in command_stats:
            empty = _compute_stats([])
            empty["excluded_count"] = excluded_by_command.get(command_name, 0)
            empty["registry_excluded_count"] = registry_excluded_by_command.get(command_name, 0)
            command_stats[command_name] = empty

    unreliable_sources = sorted({
        info["source"]
        for info in task_by_id.values()
        if registry.resolve({
            "source": info["source"],
            "tool_name": info["tool_name"],
            "command_name": info["analyzer_group"],
        }).has_class("result_status_unreliable")
    })

    return {
        "analyzer": "command_duration",
        "sleep_adjusted": any_agent_duration,
        "metadata": {
            "behavior_registry": context["behavior_registry_metadata"],
            "registry_excluded_commands": dict(sorted(registry_excluded_by_command.items())),
            "sources_with_unreliable_status": unreliable_sources,
        },
        "durations": command_stats,
    }


def parse_sleep_info(sleep_info: str) -> float | None:
    if not sleep_info or not sleep_info.strip():
        return None
    text = sleep_info.strip().lower()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*s?", text)
    if m:
        return float(m.group(1))
    return None


def _time_diff_seconds(ts1: str, ts2: str) -> float:
    """Calculate time difference in seconds between two ISO 8601 timestamps."""
    dt1 = datetime.fromisoformat(ts1.replace("Z", "+00:00"))
    dt2 = datetime.fromisoformat(ts2.replace("Z", "+00:00"))
    return (dt2 - dt1).total_seconds()


def _compute_stats(entries: list[dict]) -> dict:
    """Compute statistical summary for a list of duration entries."""
    if not entries:
        return {
            "execution_count": 0,
            "excluded_count": 0,
            "registry_excluded_count": 0,
            "mean_seconds": 0.0,
            "median_seconds": 0.0,
            "p95_seconds": 0.0,
            "max_seconds": 0.0,
            "max_event": None,
            "min_seconds": 0.0,
            "outlier_count": 0,
            "outlier_events": [],
            "wall_clock_mean_seconds": 0.0,
            "wall_clock_median_seconds": 0.0,
        }

    durations = [e["duration"] for e in entries]
    wall_clocks = [e["wall_clock"] for e in entries]
    execution_count = len(durations)
    mean_val = statistics.mean(durations)
    median_val = statistics.median(durations)
    min_val = min(durations)
    max_val = max(durations)

    max_entry = max(entries, key=lambda e: e["duration"])
    max_event = {
        "operation_id": max_entry.get("operation_id", 0),
        "task_id": max_entry["task_id"],
        "display_id": max_entry.get("display_id", 0),
        "command_name": max_entry.get("command_name", ""),
        "arguments_raw": max_entry["arguments_raw"],
        "duration_seconds": round(max_entry["duration"], 2),
        **copy_task_retention_fields(max_entry),
    }
    # Not in copy_task_retention_fields; required for HTML / consumers (pty_in_session → cd …)
    if max_entry.get("pty_shell_command"):
        max_event["pty_shell_command"] = max_entry["pty_shell_command"]

    sorted_durations = sorted(durations)
    p95_index = int(0.95 * len(sorted_durations))
    if p95_index >= len(sorted_durations):
        p95_index = len(sorted_durations) - 1
    p95_val = sorted_durations[p95_index]

    outlier_count = 0
    outlier_events: list[dict] = []
    if execution_count >= 2:
        stdev = statistics.stdev(durations)
        threshold = mean_val + (3 * stdev)
        outlier_entries = [e for e in entries if e["duration"] > threshold]
        outlier_count = len(outlier_entries)
        outlier_events = []
        for e in sorted(outlier_entries, key=lambda x: x["duration"], reverse=True):
            od = {
                "operation_id": e.get("operation_id", 0),
                "task_id": e["task_id"],
                "display_id": e.get("display_id", 0),
                "command_name": e.get("command_name", ""),
                "arguments_raw": e["arguments_raw"],
                "duration_seconds": round(e["duration"], 2),
                **copy_task_retention_fields(e),
            }
            if e.get("pty_shell_command"):
                od["pty_shell_command"] = e["pty_shell_command"]
            outlier_events.append(od)

    return {
        "execution_count": execution_count,
        "excluded_count": 0,  # populated by caller if any were filtered
        "registry_excluded_count": 0,
        "mean_seconds": round(mean_val, 2),
        "median_seconds": round(median_val, 2),
        "p95_seconds": round(p95_val, 2),
        "max_seconds": round(max_val, 2),
        "max_event": max_event,
        "min_seconds": round(min_val, 2),
        "outlier_count": outlier_count,
        "outlier_events": outlier_events,
        "wall_clock_mean_seconds": round(statistics.mean(wall_clocks), 2),
        "wall_clock_median_seconds": round(statistics.median(wall_clocks), 2),
    }
