"""
ArgumentPositionProfile — Profile argument structure and detect positional anomalies.

Primary output is a per-command × per-position breakdown showing:
  - Volume: how many tasks reached each argument position
  - Frequency: what % of that command's tasks reached the position
  - Distribution: top values at each position with counts and percentages

Secondary output is a findings list that flags structural anomalies:
  - Static arguments — a position is always (or nearly always) the same value
  - High-diversity positions — every invocation uses a different value
  - Depth anomalies — argument count varies wildly across invocations
  - Sparse trailing positions — rarely-used optional or error-prone args
"""

from __future__ import annotations

import json
import math
import re
import shlex
import statistics
from collections import Counter, defaultdict


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

MAX_PROFILE_DEPTH: int = 64
"""Maximum argument position to profile (1-based). Positions beyond this are
counted toward depth statistics but not individually profiled."""

STATIC_THRESHOLD: float = 0.90
"""Fraction of tasks at a position that must share the same value for it to
be flagged as a static argument."""

STATIC_MIN_TASKS: int = 3
"""Minimum tasks reaching a position before a static-argument finding fires."""

DIVERSITY_THRESHOLD: float = 0.80
"""When unique_values / tasks_reaching >= this ratio, the position is flagged
as high-diversity (operator improvisation)."""

DIVERSITY_MIN_TASKS: int = 5
"""Minimum tasks at a position before diversity findings fire."""

DEPTH_ANOMALY_CV_THRESHOLD: float = 0.50
"""Coefficient of variation (stdev/mean) of argument depth per command above
which a depth anomaly finding is emitted."""

DEPTH_ANOMALY_MIN_TASKS: int = 5
"""Minimum tasks for a command before depth anomaly detection applies."""

SPARSE_TRAILING_THRESHOLD: float = 0.10
"""A position reached by fewer than this fraction of a command's tasks is
flagged as sparse/trailing."""

SPARSE_TRAILING_MIN_TASKS: int = 5
"""Minimum tasks for a command before sparse trailing detection applies."""

TOP_N: int = 5
"""Number of top values to include in profiles."""


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------

_FALLBACK_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')


def _stringify_scalar(value) -> str:
    """Return a deterministic string form for a scalar JSON value."""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _flatten_json_scalars(value, path_prefix: str = "") -> list[dict]:
    """Flatten scalar JSON leaves into a stable, ordered list."""
    flattened: list[dict] = []

    if isinstance(value, dict):
        for key, child in value.items():
            next_path = f"{path_prefix}.{key}" if path_prefix else str(key)
            flattened.extend(_flatten_json_scalars(child, next_path))
        return flattened

    if isinstance(value, list):
        for index, child in enumerate(value):
            next_path = f"{path_prefix}[{index}]" if path_prefix else f"[{index}]"
            flattened.extend(_flatten_json_scalars(child, next_path))
        return flattened

    flattened.append({
        "value": _stringify_scalar(value),
        "path": path_prefix or "$",
        "source": "json_scalar",
    })
    return flattened


def _tokenize_arguments(raw: str) -> list[dict]:
    """Tokenize arguments from either JSON or shell-like raw text."""
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed = None
    else:
        if isinstance(parsed, (dict, list)):
            return _flatten_json_scalars(parsed)
        if parsed is not None:
            return [{"value": _stringify_scalar(parsed), "path": "$", "source": "json_scalar"}]

    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = [token.strip("\"'") for token in _FALLBACK_TOKEN_RE.findall(raw)]

    return [{"value": token, "path": "", "source": "shell_token"} for token in tokens if token]


def _top_counts(counter_map: dict[str, int], total: int, limit: int = TOP_N) -> list[dict]:
    """Convert a frequency map into a sorted top-N list with counts and percentages."""
    return [
        {
            "value": value,
            "count": count,
            "pct": round(count / total * 100, 1) if total else 0.0,
        }
        for value, count in sorted(counter_map.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _build_expected_static_lookup(context: dict) -> dict[tuple[str, int], str]:
    """Build (command_name, position) -> expected_value map from registry."""
    lookup: dict[tuple[str, int], str] = {}
    registry = context.get("behavior_registry")
    if not registry:
        return lookup
    for rule in registry.command_rules:
        cmd = rule.match.get("command_name", "")
        expected_static = rule.argument_position_profile.get("expected_static", [])
        for entry in expected_static:
            pos = int(entry["position"])
            value = str(entry["value"])
            lookup[(cmd, pos)] = value
    return lookup


def analyze(
    task_events: list[dict],
    result_events: list[dict],
    context: dict | None = None,
) -> dict:
    """Profile argument positions across all task events and detect anomalies.

    Args:
        task_events: Normalized task event dicts.
        result_events: Not used (task-only analyzer).
        context: Optional analyzer context with behavior registry.

    Returns:
        Dict with summary, per_command positions, depth distribution, and findings.
    """
    del result_events  # Task-only analyzer.
    expected_statics = _build_expected_static_lookup(context or {})

    total_tasks = len(task_events)
    tasks_with_arguments = 0
    tokenization_sources: dict[str, int] = {}

    # Per-command tracking
    command_depths: dict[str, list[int]] = defaultdict(list)

    # Per-command, per-position tracking
    position_values: dict[tuple[str, int], Counter] = defaultdict(Counter)
    position_task_counts: dict[tuple[str, int], int] = defaultdict(int)

    # Per-command task counts
    command_task_counts: Counter = Counter()

    # Task refs: (command, position, value) -> list of task ref dicts
    # Only populated for positions that match expected_statics keys to limit memory
    _tracked_positions = set(expected_statics.keys())
    position_task_refs: dict[tuple[str, int, str], list[dict]] = defaultdict(list)

    def _task_ref(task: dict) -> dict:
        """Extract a lightweight task reference for findings."""
        ref: dict = {"task_id": task.get("task_id")}
        if task.get("display_id"):
            ref["display_id"] = task["display_id"]
        if task.get("callback_id"):
            ref["callback_id"] = task["callback_id"]
        if task.get("callback_display_id"):
            ref["callback_display_id"] = task["callback_display_id"]
        if task.get("timestamp"):
            ref["timestamp"] = task["timestamp"]
        return ref

    for task in task_events:
        raw = task.get("arguments_raw") or ""
        command_name = task.get("command_name", "") or "unknown"
        slots = _tokenize_arguments(raw)

        command_task_counts[command_name] += 1

        if not slots:
            command_depths[command_name].append(0)
            continue

        tasks_with_arguments += 1
        depth = len(slots)
        command_depths[command_name].append(depth)

        for slot in slots:
            src = slot["source"]
            tokenization_sources[src] = tokenization_sources.get(src, 0) + 1

        for pos_0 in range(min(depth, MAX_PROFILE_DEPTH)):
            pos_1 = pos_0 + 1
            value = slots[pos_0]["value"]
            position_values[(command_name, pos_1)][value] += 1
            position_task_counts[(command_name, pos_1)] += 1
            # Track task refs for positions we'll need context for
            if (command_name, pos_1) in _tracked_positions:
                position_task_refs[(command_name, pos_1, value)].append(_task_ref(task))

    # ------------------------------------------------------------------
    # Depth distribution per command
    # ------------------------------------------------------------------
    depth_distribution = []
    for cmd in sorted(command_depths.keys()):
        depths = command_depths[cmd]
        task_count = len(depths)
        if not depths:
            continue
        nonzero = [d for d in depths if d > 0]
        depth_distribution.append({
            "command_name": cmd,
            "task_count": task_count,
            "tasks_with_args": len(nonzero),
            "min_depth": min(depths),
            "max_depth": max(depths),
            "mean_depth": round(statistics.mean(depths), 2),
            "median_depth": round(statistics.median(depths), 2),
            "stdev_depth": round(statistics.stdev(depths), 2) if len(depths) >= 2 else 0.0,
        })
    depth_distribution.sort(key=lambda d: (-d["task_count"], d["command_name"]))

    # ------------------------------------------------------------------
    # Per-command position profiles (primary output)
    # Shows volume, reach %, and value distribution per command × position
    # ------------------------------------------------------------------
    # Collect all positions per command
    cmd_positions: dict[str, list[int]] = defaultdict(list)
    for (cmd, pos) in position_task_counts.keys():
        cmd_positions[cmd].append(pos)

    per_command: dict[str, dict] = {}
    total_positions_profiled = 0
    for cmd in sorted(cmd_positions.keys(), key=lambda c: -command_task_counts[c]):
        cmd_total = command_task_counts[cmd]
        positions = []
        for pos in sorted(cmd_positions[cmd]):
            tasks_reaching = position_task_counts[(cmd, pos)]
            counter = position_values[(cmd, pos)]
            unique = len(counter)
            positions.append({
                "position": pos,
                "tasks_reaching": tasks_reaching,
                "reach_pct": round(tasks_reaching / cmd_total * 100, 1) if cmd_total else 0.0,
                "unique_values": unique,
                "top_values": _top_counts(dict(counter), tasks_reaching),
            })
            total_positions_profiled += 1
        per_command[cmd] = {
            "task_count": cmd_total,
            "positions": positions,
        }

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    findings: list[dict] = []

    # 1. Static arguments
    seen_expected: set[tuple[str, int]] = set()
    for (cmd, pos), counter in position_values.items():
        tasks_at_pos = position_task_counts[(cmd, pos)]
        if tasks_at_pos < STATIC_MIN_TASKS:
            continue
        most_common_value, most_common_count = counter.most_common(1)[0]
        fraction = most_common_count / tasks_at_pos

        expected_value = expected_statics.get((cmd, pos))

        if fraction >= STATIC_THRESHOLD:
            finding = {
                "type": "static_argument",
                "command_name": cmd,
                "position": pos,
                "value": most_common_value,
                "occurrences": most_common_count,
                "tasks_at_position": tasks_at_pos,
                "reach_pct": round(tasks_at_pos / command_task_counts[cmd] * 100, 1),
                "fraction": round(fraction, 4),
            }
            if expected_value is not None and most_common_value == expected_value:
                finding["expected"] = True
                seen_expected.add((cmd, pos))
            findings.append(finding)

        # Check for deviations from expected static value
        if expected_value is not None:
            seen_expected.add((cmd, pos))
            deviation_count = tasks_at_pos - counter.get(expected_value, 0)
            if deviation_count > 0:
                deviating_values = {
                    v: c for v, c in counter.items() if v != expected_value
                }
                # Collect task refs for deviating tasks
                dev_task_refs = []
                for dev_val in deviating_values:
                    dev_task_refs.extend(position_task_refs.get((cmd, pos, dev_val), []))
                finding = {
                    "type": "unexpected_static_deviation",
                    "command_name": cmd,
                    "position": pos,
                    "expected_value": expected_value,
                    "deviation_count": deviation_count,
                    "tasks_at_position": tasks_at_pos,
                    "deviation_pct": round(deviation_count / tasks_at_pos * 100, 1),
                    "deviating_values": _top_counts(deviating_values, deviation_count),
                }
                if dev_task_refs:
                    finding["task_refs"] = dev_task_refs
                findings.append(finding)

    # 2. High-diversity positions
    for (cmd, pos), counter in position_values.items():
        tasks_at_pos = position_task_counts[(cmd, pos)]
        if tasks_at_pos < DIVERSITY_MIN_TASKS:
            continue
        unique = len(counter)
        ratio = unique / tasks_at_pos
        if ratio >= DIVERSITY_THRESHOLD:
            findings.append({
                "type": "high_diversity",
                "command_name": cmd,
                "position": pos,
                "unique_values": unique,
                "tasks_at_position": tasks_at_pos,
                "reach_pct": round(tasks_at_pos / command_task_counts[cmd] * 100, 1),
                "diversity_ratio": round(ratio, 4),
                "top_values": _top_counts(dict(counter), tasks_at_pos),
            })

    # 3. Depth anomalies
    for entry in depth_distribution:
        cmd = entry["command_name"]
        if entry["task_count"] < DEPTH_ANOMALY_MIN_TASKS:
            continue
        mean = entry["mean_depth"]
        stdev = entry["stdev_depth"]
        if mean > 0 and stdev / mean >= DEPTH_ANOMALY_CV_THRESHOLD:
            findings.append({
                "type": "depth_anomaly",
                "command_name": cmd,
                "task_count": entry["task_count"],
                "min_depth": entry["min_depth"],
                "max_depth": entry["max_depth"],
                "mean_depth": entry["mean_depth"],
                "stdev_depth": entry["stdev_depth"],
                "cv": round(stdev / mean, 4),
            })

    # 4. Sparse trailing positions
    for (cmd, pos), tasks_at_pos in position_task_counts.items():
        total_cmd_tasks = command_task_counts[cmd]
        if total_cmd_tasks < SPARSE_TRAILING_MIN_TASKS:
            continue
        fraction = tasks_at_pos / total_cmd_tasks
        if fraction < SPARSE_TRAILING_THRESHOLD:
            counter = position_values[(cmd, pos)]
            findings.append({
                "type": "sparse_trailing",
                "command_name": cmd,
                "position": pos,
                "tasks_at_position": tasks_at_pos,
                "total_command_tasks": total_cmd_tasks,
                "reach_pct": round(fraction * 100, 1),
                "unique_values": len(counter),
                "top_values": _top_counts(dict(counter), tasks_at_pos),
            })

    # Sort findings: static first (most actionable), then by task volume
    finding_type_order = {
        "unexpected_static_deviation": 0,
        "static_argument": 1,
        "depth_anomaly": 2,
        "high_diversity": 3,
        "sparse_trailing": 4,
    }
    findings.sort(key=lambda f: (
        finding_type_order.get(f["type"], 99),
        -f.get("tasks_at_position", f.get("task_count", 0)),
    ))

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    max_depth = 0
    for depths in command_depths.values():
        for d in depths:
            if d > max_depth:
                max_depth = d

    all_depths = [d for depths in command_depths.values() for d in depths]
    mean_depth = round(statistics.mean(all_depths), 2) if all_depths else 0.0

    finding_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        finding_counts[f["type"]] += 1

    return {
        "analyzer": "argument_position_profile",
        "summary": {
            "total_tasks": total_tasks,
            "tasks_with_arguments": tasks_with_arguments,
            "commands_profiled": len(command_depths),
            "max_depth_observed": max_depth,
            "mean_argument_depth": mean_depth,
            "positions_profiled": total_positions_profiled,
            "total_findings": len(findings),
            "findings_by_type": dict(finding_counts),
        },
        "metadata": {
            "thresholds": {
                "static_threshold": STATIC_THRESHOLD,
                "static_min_tasks": STATIC_MIN_TASKS,
                "diversity_threshold": DIVERSITY_THRESHOLD,
                "diversity_min_tasks": DIVERSITY_MIN_TASKS,
                "depth_anomaly_cv_threshold": DEPTH_ANOMALY_CV_THRESHOLD,
                "sparse_trailing_threshold": SPARSE_TRAILING_THRESHOLD,
                "max_profile_depth": MAX_PROFILE_DEPTH,
            },
            "tokenization": {
                "shell_text": "shlex.split with regex fallback",
                "json": "depth-first scalar leaf flattening",
            },
            "tokenization_sources": tokenization_sources,
        },
        "per_command": per_command,
        "findings": findings,
        "depth_distribution": depth_distribution,
    }
