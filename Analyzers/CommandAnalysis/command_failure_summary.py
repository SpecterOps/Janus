"""
CommandFailureSummary — Analyzer 01.

Joins task events to result events by task_id, counts executions and
status outcomes per command_name, computes failure_rate.

No heuristics. No workflows. No chaining.
"""

from collections import defaultdict

from Core.analyzer_command_grouping import analyzer_command_group
from Core.event_utils import task_key as _task_key
from Core.output_rule import copy_result_retention_fields, copy_task_retention_fields


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    """Produce per-command execution and failure counts.

    Args:
        task_events: List of normalized task event dicts (must have task_id, command_name).
        result_events: List of normalized result event dicts (must have task_id, status).

    Returns:
        Dict with analyzer name and per-command summary keyed by command_name.
    """
    # Index: (operation_id, task_id) -> full task (for callback_id lookup)
    task_by_id: dict[tuple[int, int], dict] = {}
    for t in task_events:
        task_by_id[_task_key(t)] = t

    # Accumulate per-command counts
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"execution_count": 0, "success_count": 0, "error_count": 0, "dispatch_error_count": 0, "unknown_count": 0}
    )

    # Per-command, per-callback counts: command_name -> callback_id -> counts
    cb_counts: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(lambda: {"callback_display_id": 0, "task_count": 0, "success_count": 0, "error_count": 0, "dispatch_error_count": 0, "unknown_count": 0})
    )

    for r in result_events:
        task = task_by_id.get(_task_key(r))
        if task is None:
            # Orphaned result — no matching task. Skip silently.
            continue

        command_name = analyzer_command_group(task)
        cb_id = str(task.get("callback_id", 0))

        entry = counts[command_name]
        entry["execution_count"] += 1

        cb_entry = cb_counts[command_name][cb_id]
        cb_entry["task_count"] += 1
        cb_entry["callback_display_id"] = task.get("callback_display_id", 0)

        status = r["status"]
        if status == "success":
            entry["success_count"] += 1
            cb_entry["success_count"] += 1
        elif status == "error":
            entry["error_count"] += 1
            cb_entry["error_count"] += 1
            if r.get("dispatch_failed"):
                entry["dispatch_error_count"] += 1
                cb_entry["dispatch_error_count"] += 1
        else:
            entry["unknown_count"] += 1
            cb_entry["unknown_count"] += 1

    # Build result event lookup by scoped task key for failure details
    result_by_task: dict[tuple[int, int], dict] = {}
    for r in result_events:
        result_by_task[_task_key(r)] = r

    # Compute failure_rate, attach callback_breakdown, and collect failure details
    commands = {}
    for command_name in sorted(counts):
        entry = dict(counts[command_name])
        ec = entry["execution_count"]
        entry["failure_rate"] = entry["error_count"] / ec if ec > 0 else 0.0
        entry["callback_breakdown"] = {
            cb_id: dict(cb_entry)
            for cb_id, cb_entry in sorted(cb_counts[command_name].items(), key=lambda x: int(x[0]))
        }

        # Collect detailed failure information (limit to first 20 per command)
        failures = []
        if entry["error_count"] > 0:
            for r in result_events:
                if r["status"] == "error":
                    task = task_by_id.get(_task_key(r))
                    if task and analyzer_command_group(task) == command_name:
                        # Truncate error message to ~500 chars
                        error_msg = r.get("output_text", "")
                        if len(error_msg) > 500:
                            error_msg = error_msg[:500] + "..."

                        fail_row = {
                            "operation_id": r.get("operation_id", 0),
                            "task_id": r["task_id"],
                            "display_id": task.get("display_id", 0),
                            "command_name": command_name,
                            "timestamp": task.get("timestamp", ""),
                            "callback_id": task.get("callback_id", 0),
                            "callback_display_id": task.get("callback_display_id", 0),
                            "arguments_raw": task.get("arguments_raw", ""),
                            "error_message": error_msg,
                            "dispatch_failed": r.get("dispatch_failed", False),
                            **copy_task_retention_fields(task),
                            **copy_result_retention_fields(r),
                        }
                        if task.get("pty_synthetic"):
                            fail_row["pty_shell_command"] = task.get("command_name", "")
                        failures.append(fail_row)

                        # Limit to 20 failures per command to avoid JSON bloat
                        if len(failures) >= 20:
                            break

        entry["failures"] = failures
        commands[command_name] = entry

    return {
        "analyzer": "command_failure_summary",
        "commands": commands,
    }
