"""
CallbackHealth — Analyzer.

Groups tasks by callback_id, correlates with result statuses, and tracks
task execution patterns.  Surfaces the probable crash/hang point (last
successful task) and consecutive failure sequences.

Requires callback_id on task events (Mythic parser ≥ v0.4).
"""

from collections import defaultdict

from Core.event_utils import callback_key as _callback_key
from Core.event_utils import index_results_by_key
from Core.event_utils import task_key as _task_key
from Core.output_rule import copy_task_retention_fields

CONSECUTIVE_FAILURE_THRESHOLD = 3


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    result_by_task = {
        task_id: result.get("status", "unknown")
        for task_id, result in index_results_by_key(result_events).items()
    }

    # Group tasks by (operation_id, callback_id), preserving timestamp order.
    by_callback: dict[str, list[dict]] = defaultdict(list)
    for t in task_events:
        by_callback[_callback_key(t)].append(t)

    for callback_scope in by_callback:
        by_callback[callback_scope].sort(key=lambda t: t.get("timestamp", ""))

    callbacks = {}
    callbacks_with_consecutive_failures = 0

    for callback_scope, tasks in by_callback.items():
        success_count = 0
        error_count = 0
        unknown_count = 0
        last_successful_task = None

        statuses_in_order: list[str] = []

        for t in tasks:
            status = result_by_task.get(_task_key(t), "unknown")
            statuses_in_order.append(status)

            if status == "success":
                success_count += 1
                last_successful_task = {
                    "operation_id": t.get("operation_id", 0),
                    "task_id": t["task_id"],
                    "display_id": t.get("display_id", 0),
                    "command_name": t.get("command_name", ""),
                    "timestamp": t.get("timestamp", ""),
                    "arguments_raw": t.get("arguments_raw", ""),
                    **copy_task_retention_fields(t),
                }
            elif status == "error":
                error_count += 1
            else:
                unknown_count += 1

        task_count = len(tasks)
        completion_rate = round(success_count / task_count, 4) if task_count else 0.0

        # resolved_rate = success / (success + error) — excludes tasks with no result
        # at all (unknown) so the metric reflects actual pass/fail, not missing data.
        resolved_count = success_count + error_count
        resolved_rate = round(success_count / resolved_count, 4) if resolved_count > 0 else 0.0
        unresolved_count = unknown_count  # tasks whose result never arrived

        # Trailing failures: consecutive non-success tasks at the end.
        # Exclude "exit" — it is expected end-of-lifecycle, not a failure.
        trailing_failures = []
        for t in reversed(tasks):
            status = result_by_task.get(_task_key(t), "unknown")
            if status == "success":
                break
            if t.get("command_name") == "exit":
                break  # exit at end is expected; do not count as trailing failure
            trailing_failures.append({
                "operation_id": t.get("operation_id", 0),
                "task_id": t["task_id"],
                "display_id": t.get("display_id", 0),
                "command_name": t.get("command_name", ""),
                "status": status,
                "timestamp": t.get("timestamp", ""),
                "arguments_raw": t.get("arguments_raw", ""),
                **copy_task_retention_fields(t),
            })
        trailing_failures.reverse()

        # Consecutive failure detection: 3+ consecutive non-success tasks at the tail
        consecutive_failure_count = len(trailing_failures)
        has_consecutive_failures = consecutive_failure_count >= CONSECUTIVE_FAILURE_THRESHOLD
        if has_consecutive_failures:
            callbacks_with_consecutive_failures += 1

        callbacks[callback_scope] = {
            "operation_id": tasks[0].get("operation_id", 0) if tasks else 0,
            "callback_id": tasks[0].get("callback_id", 0) if tasks else 0,
            "callback_display_id": tasks[0].get("callback_display_id", 0) if tasks else 0,
            "task_count": task_count,
            "success_count": success_count,
            "error_count": error_count,
            "unknown_count": unknown_count,
            "unresolved_count": unresolved_count,
            "completion_rate": completion_rate,
            "resolved_rate": resolved_rate,
            "first_task_timestamp": tasks[0].get("timestamp", "") if tasks else "",
            "last_task_timestamp": tasks[-1].get("timestamp", "") if tasks else "",
            "last_successful_task": last_successful_task,
            "has_consecutive_failures": has_consecutive_failures,
            "consecutive_failure_count": consecutive_failure_count,
            "trailing_failures": trailing_failures,
        }

    return {
        "analyzer": "callback_health",
        "callbacks": callbacks,
        "summary": {
            "total_callbacks": len(callbacks),
            "callbacks_with_consecutive_failures": callbacks_with_consecutive_failures,
        },
    }
