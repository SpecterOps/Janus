"""
Partial Mythic data adapter.

Transforms Mythic JSON exports with incomplete data (from limited GraphQL queries)
into the current canonical event model used by Janus analyzers.

Data differences from current Janus pull queries:
- Partial: tasks have embedded 'responses' array (not separate response table)
- Partial: no operation_id, parent_task_id, status_timestamp_* fields
- Partial: command.payloadtype is nested under callback.payload.payloadtype
- Current: separate task and response tables with proper foreign keys and full metadata

This adapter synthesizes missing fields to enable partial analysis:
- Uses display_id as id (task_id)
- Derives operation_id from directory name or uses provided value
- Sets all status_timestamp_* to task timestamp (reduces timing accuracy)
- Extracts embedded responses into separate ResultEvent objects
"""

import json
import re
import zlib
from pathlib import Path

from Core.models import ResultEvent, TaskEvent, normalize_timestamp
from Parsers.Mythic.mythic_pull import slugify


def parse_operation_id_from_path(json_path: Path) -> int:
    """Extract operation ID from file path.

    Examples:
      Assets/idot2508-mythic-data/idot2508-rng00.json → 2508
      Assets/atrto250811-mythic-data/... → 250811

    Falls back to 9999 if pattern not found.
    """
    path_str = str(json_path)
    # Match patterns like idot2508, atrto250811
    match = re.search(r'(idot|atrto)(\d+)', path_str)
    if match:
        return int(match.group(2))
    # Fallback to deterministic synthetic ID to reduce collisions across files.
    return 900000000 + (zlib.crc32(path_str.encode("utf-8")) % 100000000)


def _safe_int(value, default: int = 0) -> int:
    try:
        parsed = int(value)
        return parsed if parsed >= 0 else default
    except (TypeError, ValueError):
        return default


def _safe_normalize_timestamp(raw) -> str:
    try:
        return normalize_timestamp(raw)
    except (TypeError, ValueError):
        return ""


def load_partial_mythic_json(
    json_path: Path,
    operation_id: int | None = None,
    operation_name: str | None = None,
) -> tuple[list[TaskEvent], list[ResultEvent], dict]:
    """Load partial Mythic JSON export (incomplete GraphQL pull) and normalize to current event model.

    Args:
        json_path: Path to partial JSON file (e.g., idot2508-rng00-teamserver1.json)
        operation_id: Override operation ID (otherwise derived from path)
        operation_name: Override operation name (otherwise derived from filename)

    Returns:
        (task_events, result_events, metadata)
    """
    json_path = Path(json_path)

    if operation_id is None:
        operation_id = parse_operation_id_from_path(json_path)

    if operation_name is None:
        # Use filename stem as operation name
        operation_name = json_path.stem

    with open(json_path) as f:
        data = json.load(f)

    raw_tasks = data.get("task", [])

    task_events: list[TaskEvent] = []
    result_events: list[ResultEvent] = []

    skipped_task_count = 0
    fallback_task_id_count = 0

    for index, raw_task in enumerate(raw_tasks, start=1):
        # Extract core fields (partial data schema)
        display_id = _safe_int(raw_task.get("display_id", 0), default=0)
        task_id = display_id  # Use display_id as task_id in partial data
        if task_id == 0:
            raw_id = _safe_int(raw_task.get("id", 0), default=0)
            task_id = raw_id if raw_id > 0 else index
            fallback_task_id_count += 1

        callback_data = raw_task.get("callback", {})
        callback_id = _safe_int(callback_data.get("id", 0), default=0)
        callback_display_id = _safe_int(callback_data.get("display_id", 0), default=0)

        command_name = raw_task.get("command_name", "")
        original_params = raw_task.get("original_params", "")
        if original_params is None:
            original_params = ""
        elif not isinstance(original_params, str):
            original_params = json.dumps(original_params)

        timestamp_raw = raw_task.get("timestamp", "")
        timestamp = _safe_normalize_timestamp(timestamp_raw)
        if not timestamp:
            skipped_task_count += 1
            continue

        completed = raw_task.get("completed", False)
        status = raw_task.get("status", "")

        # Synthesize missing fields with best-effort defaults
        # Note: callback.sleep_info not included in partial GraphQL pull → empty string
        callback_sleep_info = ""

        # Note: status_timestamp_* fields not included in partial pull → use main timestamp
        # This loses timing accuracy but enables basic duration analysis
        processing_timestamp = timestamp

        # Note: parent_task_id not included in partial GraphQL pull → always None
        # This disables subtask attribution logic
        parent_task_id = None
        orphaned_subtask = False

        # Reconstruct command.payloadtype from callback.payload.payloadtype
        # Partial data: callback.payload.payloadtype.name
        # Current Janus query: command.payloadtype.name (also available via callback)
        # Note: This field is used for forge attribution in mythic_pull.py
        # Partial data doesn't have command.cmd for forge attribution
        # Just use command_name as-is (no forge special handling)
        issued_command_name = ""

        # Create TaskEvent
        task_events.append(
            TaskEvent(
                source="mythic-partial",
                operation_id=operation_id,
                callback_id=callback_id,
                callback_display_id=callback_display_id,
                task_id=task_id,
                display_id=display_id,
                timestamp=timestamp,
                tool_name="mythic",
                command_name=command_name,
                arguments_raw=original_params,
                processing_timestamp=processing_timestamp,
                callback_sleep_info=callback_sleep_info,
                issued_command_name=issued_command_name,
                parent_task_id=parent_task_id,
                orphaned_subtask=orphaned_subtask,
            )
        )

        # Extract embedded responses
        responses = raw_task.get("responses", [])

        # Concatenate all response_text (partial data has them as separate array items)
        output_parts = []
        for resp in responses:
            response_text = resp.get("response_text", "")
            if response_text:
                output_parts.append(response_text)

        output_text = "\n".join(output_parts)

        # Use task timestamp as result timestamp (partial data doesn't have response timestamps)
        result_timestamp = timestamp

        # Determine status using existing logic
        result_status, dispatch_failed = ResultEvent.determine_status(completed, status)

        # Create ResultEvent
        result_events.append(
            ResultEvent(
                source="mythic-partial",
                operation_id=operation_id,
                task_id=task_id,
                timestamp=result_timestamp,
                status=result_status,
                dispatch_failed=dispatch_failed,
                output_text=output_text,
            )
        )

    # Build metadata
    status_counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
    for e in result_events:
        status_counts[e.status] += 1

    metadata = {
        "source": "mythic-partial",
        "operation_id": operation_id,
        "operation_name": operation_name,
        "operation_slug": slugify(operation_name),
        "partial_data_file": str(json_path),
        "task_count": len(task_events),
        "result_count": len(result_events),
        "status_counts": status_counts,
        "skipped_task_count": skipped_task_count,
        "fallback_task_id_count": fallback_task_id_count,
    }

    return task_events, result_events, metadata
