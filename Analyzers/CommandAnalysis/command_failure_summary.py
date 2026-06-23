"""
CommandFailureSummary - Analyzer 01.

Joins task events to result events by task_id, counts executions and
status outcomes per command_name, computes failure_rate.

No heuristics. No workflows. No chaining.
"""

from collections import defaultdict

from Core.analyzer_command_grouping import analyzer_command_group
from Core.event_utils import index_tasks_by_key, iter_joined_results
from Core.output_rule import copy_result_retention_fields, copy_task_retention_fields


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    """Produce per-command execution and failure counts."""
    task_by_id = index_tasks_by_key(task_events)
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"execution_count": 0, "success_count": 0, "error_count": 0, "dispatch_error_count": 0, "unknown_count": 0}
    )
    cb_counts: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(lambda: {"callback_display_id": 0, "task_count": 0, "success_count": 0, "error_count": 0, "dispatch_error_count": 0, "unknown_count": 0})
    )

    for task, result in iter_joined_results(task_events, result_events):
        command_name = analyzer_command_group(task)
        cb_id = str(task.get("callback_id", 0))
        entry = counts[command_name]
        cb_entry = cb_counts[command_name][cb_id]
        entry["execution_count"] += 1
        cb_entry["task_count"] += 1
        cb_entry["callback_display_id"] = task.get("callback_display_id", 0)

        status = result["status"]
        if status == "success":
            entry["success_count"] += 1
            cb_entry["success_count"] += 1
        elif status == "error":
            entry["error_count"] += 1
            cb_entry["error_count"] += 1
            if result.get("dispatch_failed"):
                entry["dispatch_error_count"] += 1
                cb_entry["dispatch_error_count"] += 1
        else:
            entry["unknown_count"] += 1
            cb_entry["unknown_count"] += 1

    commands = {}
    for command_name in sorted(counts):
        entry = dict(counts[command_name])
        ec = entry["execution_count"]
        entry["failure_rate"] = entry["error_count"] / ec if ec > 0 else 0.0
        entry["callback_breakdown"] = {
            cb_id: dict(cb_entry)
            for cb_id, cb_entry in sorted(cb_counts[command_name].items(), key=lambda x: int(x[0]))
        }

        failures = []
        if entry["error_count"] > 0:
            for result in result_events:
                if result["status"] == "error":
                    task = task_by_id.get((result.get("operation_id", 0), result["task_id"]))
                    if task and analyzer_command_group(task) == command_name:
                        error_msg = result.get("output_text", "")
                        if len(error_msg) > 500:
                            error_msg = error_msg[:500] + "..."

                        fail_row = {
                            "operation_id": result.get("operation_id", 0),
                            "task_id": result["task_id"],
                            "display_id": task.get("display_id", 0),
                            "command_name": command_name,
                            "timestamp": task.get("timestamp", ""),
                            "callback_id": task.get("callback_id", 0),
                            "callback_display_id": task.get("callback_display_id", 0),
                            "arguments_raw": task.get("arguments_raw", ""),
                            "error_message": error_msg,
                            "dispatch_failed": result.get("dispatch_failed", False),
                            **copy_task_retention_fields(task),
                            **copy_result_retention_fields(result),
                        }
                        if task.get("pty_synthetic"):
                            fail_row["pty_shell_command"] = task.get("command_name", "")
                        failures.append(fail_row)
                        if len(failures) >= 20:
                            break

        entry["failures"] = failures
        commands[command_name] = entry

    return {
        "analyzer": "command_failure_summary",
        "commands": commands,
    }
