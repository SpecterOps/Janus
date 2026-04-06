"""
Canonical event models for Janus.

Task and result events are the normalized output from all parsers.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _from_epoch(epoch_value: float) -> datetime:
    """Convert an epoch value (seconds or milliseconds) to UTC datetime."""
    # Values above ~1e11 are almost certainly milliseconds.
    if abs(epoch_value) >= 1e11:
        epoch_value /= 1000.0
    return datetime.fromtimestamp(epoch_value, tz=timezone.utc)


def normalize_timestamp(raw: str | int | float | datetime) -> str:
    """Parse a timestamp string and return ISO 8601 UTC with Z suffix.

    Mythic timestamps are naive ISO strings assumed to be UTC.
    Output: '2025-11-04T16:56:55.525191Z'
    """
    if isinstance(raw, datetime):
        dt = raw
    elif isinstance(raw, (int, float)):
        dt = _from_epoch(float(raw))
    else:
        if raw is None:
            raise ValueError("timestamp is None")
        value = str(raw).strip()
        if not value:
            raise ValueError("timestamp is empty")
        if value.endswith("Z"):
            value = f"{value[:-1]}+00:00"
        if value.lstrip("-").replace(".", "", 1).isdigit():
            dt = _from_epoch(float(value))
        else:
            dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class TaskEvent:
    """Operator-issued command event."""

    event_type: str = "task"
    source: str = "mythic"
    operation_id: int = 0
    callback_id: int = 0
    callback_display_id: int = 0
    task_id: int = 0
    display_id: int = 0
    timestamp: str = ""
    tool_name: str = "mythic"
    command_name: str = ""
    arguments_raw: str = ""
    processing_timestamp: str = ""
    callback_sleep_info: str = ""
    issued_command_name: str = ""  # set when command_name was translated (e.g. forge → inline_assembly)
    parent_task_id: int | None = None  # Mythic parent_task_id; set for sub-tasks
    orphaned_subtask: bool = False  # True when parent_task_id is set but parent could not be resolved
    c2_task_id: str = ""  # raw entry_identifier from Ghostwriter; used for Phase 4 cross-linking
    retention_meta: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        d = {
            "event_type": self.event_type,
            "source": self.source,
            "operation_id": self.operation_id,
            "callback_id": self.callback_id,
            "callback_display_id": self.callback_display_id,
            "task_id": self.task_id,
            "display_id": self.display_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "command_name": self.command_name,
            "arguments_raw": self.arguments_raw,
        }
        if self.processing_timestamp:
            d["processing_timestamp"] = self.processing_timestamp
        if self.callback_sleep_info:
            d["callback_sleep_info"] = self.callback_sleep_info
        if self.issued_command_name:
            d["issued_command_name"] = self.issued_command_name
        if self.parent_task_id is not None:
            d["parent_task_id"] = self.parent_task_id
        if self.orphaned_subtask:
            d["orphaned_subtask"] = True
        if self.c2_task_id:
            d["c2_task_id"] = self.c2_task_id
        if self.retention_meta:
            d.update(self.retention_meta)
        return d


@dataclass
class ResultEvent:
    """Tool response event."""

    event_type: str = "result"
    source: str = "mythic"
    operation_id: int = 0
    task_id: int = 0
    timestamp: str = ""
    status: str = "unknown"  # success | error | unknown
    output_text: str = ""

    dispatch_failed: bool = False  # True when error occurred before task reached the agent
    terminal_inferred_error: bool = False  # True when parser promoted terminal unknown -> error
    retention_meta: dict = field(default_factory=dict, repr=False)

    @staticmethod
    def determine_status(completed: bool, status: str) -> tuple[str, bool]:
        """Determine normalized status and dispatch_failed flag from Mythic task fields.

        dispatch_failed=True when Mythic errored during task creation (e.g. "error:
        creating task"), meaning the command was never sent to the agent.
        """
        if not completed:
            return "unknown", False
        s = status.lower()
        if s.startswith("error"):
            dispatch_failed = "creating task" in s
            return "error", dispatch_failed
        return "success", False

    def to_dict(self) -> dict:
        d = {
            "event_type": self.event_type,
            "source": self.source,
            "operation_id": self.operation_id,
            "task_id": self.task_id,
            "timestamp": self.timestamp,
            "status": self.status,
            "output_text": self.output_text,
        }
        if self.dispatch_failed:
            d["dispatch_failed"] = True
        if self.terminal_inferred_error:
            d["terminal_inferred_error"] = True
        if self.retention_meta:
            d.update(self.retention_meta)
        return d
