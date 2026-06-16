"""
CommandRetrySuccess — Analyzer 02.

Detects retry patterns where operators re-issue the same command with
modified arguments until success. Identifies friction points and parameter
tuning sequences.

Time window: 300 seconds (5 minutes)
Argument comparison: JSON diff with string fallback
"""

import json
from collections import defaultdict

from Core.analyzer_command_grouping import retry_sequence_group_key
from Core.event_utils import seconds_between as _time_diff_seconds
from Core.event_utils import task_key as _task_key
from Core.output_rule import copy_task_retention_fields


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    """Detect command retry patterns with eventual success.

    Args:
        task_events: List of normalized task event dicts (must have task_id, command_name, timestamp, arguments_raw, operation_id).
        result_events: List of normalized result event dicts (must have task_id, status, timestamp).

    Returns:
        Dict with analyzer name, retry patterns list, and summary statistics.
    """
    # Build result lookup: (operation_id, task_id) -> status
    result_by_task: dict[tuple[int, int], str] = {}
    for r in result_events:
        result_by_task[_task_key(r)] = r["status"]

    # Group tasks by (operation_id, command_name) and sort by timestamp.
    # PTY in-session synthetics share bucket pty_in_session but are split by shell command.
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for t in task_events:
        key = retry_sequence_group_key(t)
        groups[key].append(t)

    # Sort each group by timestamp
    for key in groups:
        groups[key].sort(key=lambda x: x["timestamp"])

    retry_patterns = []

    # Process each group to find retry sequences
    for group_key, tasks in groups.items():
        if len(group_key) == 3:
            operation_id, _pty_bucket, command_name = group_key
        else:
            operation_id, command_name = group_key
        # Scan for retry windows, avoiding overlaps
        i = 0
        while i < len(tasks):
            # Start a potential retry sequence
            sequence = [tasks[i]]
            j = i + 1

            # Expand sequence while each consecutive pair is within the time window.
            # Anchor each gap to the *previous* task (not sequence[0]) so a single
            # overnight gap doesn't silently absorb tasks from the next session.
            while j < len(tasks):
                gap = _time_diff_seconds(tasks[j - 1]["timestamp"], tasks[j]["timestamp"])
                if gap is not None and gap <= 300:  # 5-minute window between consecutive attempts
                    sequence.append(tasks[j])
                    j += 1
                else:
                    break

            # Check if this sequence qualifies as a retry pattern
            if len(sequence) >= 2:
                pattern = _analyze_sequence(sequence, result_by_task, operation_id, command_name, task_events)
                if pattern:
                    retry_patterns.append(pattern)
                    # Skip to end of this sequence to avoid overlapping patterns
                    i = j - 1

            # Move to next task
            i += 1

    # Compute summary statistics
    summary = _compute_summary(retry_patterns)

    return {
        "analyzer": "command_retry_success",
        "retry_patterns": retry_patterns,
        "summary": summary,
    }


def _parse_args(arguments_raw: str) -> dict | str:
    """Parse arguments_raw as JSON, or return as string if parsing fails."""
    try:
        return json.loads(arguments_raw)
    except (json.JSONDecodeError, ValueError):
        return arguments_raw


def _compare_attempt_arguments(
    attempt1: dict,
    attempt2: dict,
) -> tuple[list[str], list[dict], str | None, bool]:
    """Compare attempt arguments while respecting retention limits."""
    retained1 = str(attempt1.get("arguments_retained", "") or "")
    retained2 = str(attempt2.get("arguments_retained", "") or "")

    if not retained1 and not retained2:
        args1 = _parse_args(attempt1.get("arguments_raw", ""))
        args2 = _parse_args(attempt2.get("arguments_raw", ""))
        legacy_changes, structured_changes = _compare_args(args1, args2)
        return legacy_changes, structured_changes, None, False

    if retained1 == "hash" and retained2 == "hash":
        digest1 = str(attempt1.get("arguments_digest", "") or "")
        digest2 = str(attempt2.get("arguments_digest", "") or "")
        if digest1 and digest2:
            if digest1 == digest2:
                return [], [], "arguments compared via digest only; digest unchanged", False
            return (
                ["arguments modified (digest changed)"],
                [{
                    "path": "(arguments_digest)",
                    "type": "modified",
                    "old_value": digest1[:20] + ("..." if len(digest1) > 20 else ""),
                    "new_value": digest2[:20] + ("..." if len(digest2) > 20 else ""),
                }],
                "arguments compared via digest only; detailed diff unavailable",
                False,
            )

    retained_label = retained1 or retained2 or "withheld"
    note = (
        f"parameter comparison unavailable because arguments were withheld "
        f"(policy: {retained_label})"
    )
    if retained1 and retained2 and retained1 != retained2:
        note = (
            "parameter comparison unavailable because attempts used different "
            f"retention policies ({retained1} vs {retained2})"
        )
    return [], [], note, True


def _deep_diff(obj1, obj2, path="", depth=0, max_depth=10) -> list[dict]:
    """Recursively compare two objects and return structured diff.

    Args:
        obj1: First object to compare
        obj2: Second object to compare
        path: Dot-notation path to current field (e.g., "connection_info.callback_uuid")
        depth: Current recursion depth
        max_depth: Maximum recursion depth to prevent infinite loops

    Returns:
        List of change dicts with:
        - path: dot-notation path to changed field
        - type: "added", "removed", "modified", or "type_changed"
        - old_value: previous value (for removed/modified, truncated if too long)
        - new_value: new value (for added/modified, truncated if too long)
    """
    changes = []

    # Stop recursion if too deep
    if depth >= max_depth:
        if obj1 != obj2:
            changes.append({
                "path": path,
                "type": "modified",
                "old_value": "<deeply nested>",
                "new_value": "<deeply nested>",
            })
        return changes

    # Helper to truncate long values; non-strings are repr'd, strings are not
    def truncate_value(val, max_len=100):
        if not isinstance(val, str):
            val = repr(val)
        return val[:max_len] + "..." if len(val) > max_len else val

    # If types differ, report type change
    if type(obj1) != type(obj2):
        changes.append({
            "path": path,
            "type": "type_changed",
            "old_value": f"({type(obj1).__name__}) {truncate_value(obj1)}",
            "new_value": f"({type(obj2).__name__}) {truncate_value(obj2)}",
        })
        return changes

    # Both are dicts: compare recursively
    if isinstance(obj1, dict) and isinstance(obj2, dict):
        all_keys = set(obj1.keys()) | set(obj2.keys())
        for key in sorted(all_keys):
            key_path = f"{path}.{key}" if path else key

            if key not in obj1:
                # Key was added
                changes.append({
                    "path": key_path,
                    "type": "added",
                    "new_value": truncate_value(obj2[key]),
                })
            elif key not in obj2:
                # Key was removed
                changes.append({
                    "path": key_path,
                    "type": "removed",
                    "old_value": truncate_value(obj1[key]),
                })
            elif obj1[key] != obj2[key]:
                # Key exists in both but values differ - recurse if nested, else report change
                if isinstance(obj1[key], dict) and isinstance(obj2[key], dict):
                    changes.extend(_deep_diff(obj1[key], obj2[key], key_path, depth + 1, max_depth))
                elif isinstance(obj1[key], list) and isinstance(obj2[key], list):
                    changes.extend(_deep_diff(obj1[key], obj2[key], key_path, depth + 1, max_depth))
                else:
                    changes.append({
                        "path": key_path,
                        "type": "modified",
                        "old_value": truncate_value(obj1[key]),
                        "new_value": truncate_value(obj2[key]),
                    })

    # Both are lists: compare element-by-element
    elif isinstance(obj1, list) and isinstance(obj2, list):
        max_compare = 20  # Only compare first 20 elements to avoid huge diffs
        min_len = min(len(obj1), len(obj2), max_compare)

        for i in range(min_len):
            elem_path = f"{path}[{i}]"
            if obj1[i] != obj2[i]:
                if isinstance(obj1[i], (dict, list)) and isinstance(obj2[i], (dict, list)):
                    changes.extend(_deep_diff(obj1[i], obj2[i], elem_path, depth + 1, max_depth))
                else:
                    changes.append({
                        "path": elem_path,
                        "type": "modified",
                        "old_value": truncate_value(obj1[i]),
                        "new_value": truncate_value(obj2[i]),
                    })

        # Report length changes
        if len(obj1) != len(obj2):
            diff = len(obj2) - len(obj1)
            if diff > 0:
                changes.append({
                    "path": path,
                    "type": "added",
                    "new_value": f"+{diff} item{'s' if diff != 1 else ''}",
                })
            else:
                diff = abs(diff)
                changes.append({
                    "path": path,
                    "type": "removed",
                    "old_value": f"\u2212{diff} item{'s' if diff != 1 else ''}",
                })

    # Primitive values that differ
    elif obj1 != obj2:
        changes.append({
            "path": path,
            "type": "modified",
            "old_value": truncate_value(repr(obj1)),
            "new_value": truncate_value(repr(obj2)),
        })

    return changes


def _compare_args(args1: dict | str, args2: dict | str) -> tuple[list[str], list[dict]]:
    """Compare two argument sets and return both legacy and structured changes.

    Returns:
        tuple of (legacy_changes, structured_changes)
        - legacy_changes: list of strings (existing format for backward compatibility)
        - structured_changes: list of change dicts (new format for git-like diff)
    """
    legacy_changes = []
    structured_changes = []

    # If both are dicts, compare field-by-field
    if isinstance(args1, dict) and isinstance(args2, dict):
        # Legacy format: top-level comparison only
        all_keys = set(args1.keys()) | set(args2.keys())
        for key in sorted(all_keys):
            val1 = args1.get(key)
            val2 = args2.get(key)
            if val1 != val2:
                if val1 is None:
                    legacy_changes.append(f"{key}: (added) -> {val2}")
                elif val2 is None:
                    legacy_changes.append(f"{key}: {val1} -> (removed)")
                else:
                    legacy_changes.append(f"{key}: {val1} -> {val2}")

        # Structured format: deep recursive comparison
        structured_changes = _deep_diff(args1, args2)

    # Otherwise, check if strings differ
    elif args1 != args2:
        legacy_changes.append("arguments modified")
        structured_changes.append({
            "path": "(arguments)",
            "type": "modified",
            "old_value": repr(args1)[:100] + ("..." if len(repr(args1)) > 100 else ""),
            "new_value": repr(args2)[:100] + ("..." if len(repr(args2)) > 100 else ""),
        })

    return (legacy_changes, structured_changes)


def _analyze_sequence(
    sequence: list[dict],
    result_by_task: dict[tuple[int, int], str],
    operation_id: int,
    command_name: str,
    task_events: list[dict],
) -> dict | None:
    """Analyze a sequence of tasks to determine if it's a valid retry pattern.

    Returns pattern dict if valid (has failures followed by success), None otherwise.
    """
    # Must have at least 2 attempts
    if len(sequence) < 2:
        return None

    # Get statuses for all tasks in sequence
    statuses = []
    for task in sequence:
        status = result_by_task.get(_task_key(task), "unknown")
        statuses.append(status)

    # Must have at least one failure and final attempt must be success
    has_failure = any(s == "error" for s in statuses)
    final_success = statuses[-1] == "success"

    if not (has_failure and final_success):
        return None

    # Extract task_ids and timestamps
    task_ids = [t["task_id"] for t in sequence]
    timestamps = [t["timestamp"] for t in sequence]

    # Build per-attempt details (task_id, display_id, timestamp, status, arguments_raw)
    attempts = []
    for task in sequence:
        status = result_by_task.get(_task_key(task), "unknown")
        attempts.append({
            "operation_id": task.get("operation_id", 0),
            "task_id": task["task_id"],
            "display_id": task.get("display_id", 0),
            "timestamp": task["timestamp"],
            "status": status,
            "arguments_raw": task.get("arguments_raw", ""),
            **copy_task_retention_fields(task),
        })

    # Calculate time span
    time_span = _time_diff_seconds(timestamps[0], timestamps[-1]) or 0.0

    # Analyze argument changes between consecutive attempts
    all_legacy_changes = []
    per_transition_changes = []
    comparison_notes = []
    comparison_unknown = False
    for i in range(len(sequence) - 1):
        legacy_changes, structured_changes, comparison_note, unknown = _compare_attempt_arguments(
            sequence[i],
            sequence[i + 1],
        )
        all_legacy_changes.extend(legacy_changes)
        if structured_changes:
            per_transition_changes.append({
                "from_attempt": i + 1,
                "to_attempt": i + 2,
                "changes": structured_changes,
            })
        if comparison_note:
            comparison_notes.append(f"Attempt {i + 1} -> {i + 2}: {comparison_note}")
        if unknown:
            comparison_unknown = True

    # Remove duplicates from legacy changes while preserving order
    seen = set()
    unique_legacy_changes = []
    for change in all_legacy_changes:
        if change not in seen:
            seen.add(change)
            unique_legacy_changes.append(change)

    # Find intervening commands between first and last attempt
    # Get callback_id from first task in sequence
    callback_id = sequence[0].get("callback_id")
    start_time = timestamps[0]
    end_time = timestamps[-1]

    intervening_commands = []
    if callback_id is not None and task_events:
        # Find all tasks from same callback between start and end time
        for t in task_events:
            if (t.get("callback_id") == callback_id and
                t["command_name"] != command_name and
                t["task_id"] not in task_ids):
                # Check if timestamp is between start and end
                task_time = t["timestamp"]
                if start_time <= task_time <= end_time:
                    status = result_by_task.get(_task_key(t), "unknown")
                    intervening_commands.append({
                        "operation_id": t.get("operation_id", 0),
                        "task_id": t["task_id"],
                        "display_id": t.get("display_id", 0),
                        "command_name": t["command_name"],
                        "timestamp": task_time,
                        "status": status,
                        "arguments_raw": t.get("arguments_raw", ""),
                        **copy_task_retention_fields(t),
                    })

        # Sort by timestamp
        intervening_commands.sort(key=lambda x: x["timestamp"])

        # Limit to first 20 to avoid bloat
        intervening_commands = intervening_commands[:20]

    return {
        "command_name": command_name,
        "operation_id": operation_id,
        "task_ids": task_ids,
        "attempt_count": len(sequence),
        "time_span_seconds": round(time_span, 1),
        "argument_changes": unique_legacy_changes,
        "argument_changes_structured": per_transition_changes,
        "argument_comparison_notes": comparison_notes,
        "argument_comparison_unknown": comparison_unknown,
        "final_status": "success",
        "timestamps": timestamps,
        "attempts": attempts,
        "intervening_commands": intervening_commands,
    }


def _compute_summary(retry_patterns: list[dict]) -> dict:
    """Compute summary statistics from retry patterns."""
    if not retry_patterns:
        return {
            "total_retry_sequences": 0,
            "commands_with_retries": [],
            "avg_retries_to_success": 0.0,
            "most_retried_command": None,
        }

    total_sequences = len(retry_patterns)

    # Collect all commands with retries
    commands_with_retries = sorted(set(p["command_name"] for p in retry_patterns))

    # Calculate average retries
    total_retries = sum(p["attempt_count"] for p in retry_patterns)
    avg_retries = total_retries / total_sequences if total_sequences > 0 else 0.0

    # Find most retried command
    retry_counts: dict[str, int] = defaultdict(int)
    for p in retry_patterns:
        retry_counts[p["command_name"]] += 1

    most_retried = max(retry_counts.items(), key=lambda x: x[1])[0] if retry_counts else None

    return {
        "total_retry_sequences": total_sequences,
        "commands_with_retries": commands_with_retries,
        "avg_retries_to_success": round(avg_retries, 1),
        "most_retried_command": most_retried,
    }
