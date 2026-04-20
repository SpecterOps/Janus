"""
Per-command analyzer grouping keys.

PTY in-session synthetic tasks (``pty_synthetic``) are shell lines inside an
interactive session; their wall-clock duration and argument structure are not
comparable to standalone Mythic tasks with the same ``command_name``. They
are grouped under ``PTY_SESSION_NESTED_BUCKET`` so duration, failure, and
argument-profile analyzers do not mix them with real ``cd`` / ``pwd`` / etc.
"""

from __future__ import annotations

# Roll-up bucket for PTY in-session synthetics (matches analyzer_registry.yml)
PTY_SESSION_NESTED_BUCKET = "pty_in_session"


def analyzer_command_group(task: dict) -> str:
    """Return the command key used for per-command statistics and registry rules."""
    if task.get("pty_synthetic"):
        return PTY_SESSION_NESTED_BUCKET
    name = (task.get("command_name") or "").strip()
    return name if name else "unknown"


def argument_profile_command_key(task: dict) -> str:
    """Key for argument position profiling only.

    PTY in-session synthetics are split by **shell command** (``pty_in_session::cd``,
    ``pty_in_session::ls``, …) so position/value stats are not one meaningless merge.
    All other tasks use :func:`analyzer_command_group`.
    """
    if task.get("pty_synthetic"):
        shell = (task.get("command_name") or "").strip() or "unknown"
        return f"{PTY_SESSION_NESTED_BUCKET}::{shell}"
    return analyzer_command_group(task)


def task_event_for_registry_resolve(task: dict) -> dict:
    """Task-shaped dict with ``command_name`` overridden for behavior registry matching."""
    g = analyzer_command_group(task)
    if g == task.get("command_name"):
        return task
    return {**task, "command_name": g}


def retry_sequence_group_key(task: dict) -> tuple:
    """Group key for CommandRetrySuccess: never merge distinct shell lines inside PTY."""
    op = task.get("operation_id", 0)
    if task.get("pty_synthetic"):
        shell = (task.get("command_name") or "").strip() or "unknown"
        return (op, PTY_SESSION_NESTED_BUCKET, shell)
    return (op, (task.get("command_name") or "").strip() or "unknown")
