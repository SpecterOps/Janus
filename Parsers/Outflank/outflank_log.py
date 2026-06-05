"""
Outflank implant log parser.

Outflank writes per-implant log files as line-oriented records:

    2026-05-29 14:55:56 UTC {"event_type": "task_request", ...}

This module normalizes those local files into Janus TaskEvent / ResultEvent
pairs. Live API retrieval can reuse the same normalizer once an implant-log
endpoint is available.
"""

from __future__ import annotations

import json
import re
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from Core.io import write_bundle, write_ndjson
from Core.models import ResultEvent, TaskEvent, normalize_timestamp
from Core.output_rule import (
    apply_arguments_rule_to_tasks,
    apply_output_rule_to_results,
    normalize_arguments_rule,
    normalize_output_rule,
)

SOURCE = "outflank"
TOOL_NAME = "outflank"

_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+(?P<body>\{.*\})\s*$"
)
_ERROR_RE = re.compile(r"(^|\n)\s*(err:|error:)", re.IGNORECASE)


def slugify(name: str) -> str:
    """Convert a name to a filesystem-safe slug."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-") or "outflank"


def default_operation_name(log_path: Path) -> str:
    """Return a stable default operation name for a file or directory input."""
    if log_path.is_file():
        return f"outflank-{log_path.stem}"
    return "outflank-implant-logs"


def coerce_outflank_id(raw_id: str) -> int:
    """Map an Outflank string UID to a stable positive int for Janus joins."""
    value = str(raw_id or "").strip()
    if not value:
        return 0
    hashed = zlib.crc32(value.encode("utf-8")) & 0x7FFFFFFF
    return hashed if hashed else 1


def _increment(stats: dict[str, Any], key: str, by: int = 1) -> None:
    stats[key] = int(stats.get(key, 0)) + by


def _increment_reason(stats: dict[str, Any], reason: str) -> None:
    reasons = stats.setdefault("skip_reasons", {})
    reasons[reason] = int(reasons.get(reason, 0)) + 1


def _jsonish(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _arguments_raw(task: dict[str, Any]) -> str:
    for key in ("out_arguments", "arguments"):
        text = _jsonish(task.get(key)).strip()
        if text:
            return text

    run_arguments = task.get("run_arguments")
    if isinstance(run_arguments, list):
        return " ".join(_jsonish(item).strip() for item in run_arguments if _jsonish(item).strip())
    return _jsonish(run_arguments).strip()


def _command_name(task: dict[str, Any]) -> str:
    for key in ("name", "out_name"):
        value = _jsonish(task.get(key)).strip()
        if value:
            return value
    return "unknown"


def _line_timestamp_to_iso(raw: str) -> str:
    return normalize_timestamp(f"{raw.replace(' ', 'T')}+00:00")


def _normalize_timestamp_or_none(raw: Any) -> str | None:
    if raw is None:
        return None
    try:
        return normalize_timestamp(raw)
    except (TypeError, ValueError):
        return None


def _format_delay(implant: dict[str, Any]) -> str:
    value = implant.get("delay")
    if value is None or isinstance(value, bool):
        return ""
    try:
        delay = float(value)
    except (TypeError, ValueError):
        return ""
    if delay < 0:
        return ""
    if delay.is_integer():
        return f"{int(delay)}s"
    return f"{delay:g}s"


def _parse_log_line(line: str) -> tuple[str | None, dict[str, Any] | None, str | None]:
    match = _LINE_RE.match(line.rstrip("\n"))
    if not match:
        return None, None, "malformed line"
    try:
        line_ts = _line_timestamp_to_iso(match.group("timestamp"))
    except (TypeError, ValueError) as exc:
        return None, None, f"bad line timestamp: {exc}"
    try:
        body = json.loads(match.group("body"))
    except json.JSONDecodeError as exc:
        return line_ts, None, f"bad json: {exc.msg}"
    if not isinstance(body, dict):
        return line_ts, None, "json body is not an object"
    return line_ts, body, None


def _iter_log_files(log_path: Path) -> list[Path]:
    if log_path.is_file():
        return [log_path]
    if log_path.is_dir():
        return sorted(p for p in log_path.rglob("*.json") if p.is_file())
    return []


def _infer_result_status(output_text: str) -> str:
    if not output_text:
        return "unknown"
    if _ERROR_RE.search(output_text):
        return "error"
    return "success"


class OutflankLogParser:
    """Normalize local Outflank implant log files."""

    SOURCE = SOURCE
    TOOL_NAME = TOOL_NAME

    def __init__(self, log_path: Path | str) -> None:
        self.log_path = Path(log_path)

    def normalize(
        self,
        operation_id: int,
        operation_name: str,
    ) -> tuple[list[TaskEvent], list[ResultEvent], dict[str, Any]]:
        files = _iter_log_files(self.log_path)
        if not files:
            raise FileNotFoundError(f"no Outflank log file(s) found at {self.log_path}")

        task_events: list[TaskEvent] = []
        result_events: list[ResultEvent] = []
        seen_task_uids: set[str] = set()
        implant_uids: set[str] = set()
        stats: dict[str, Any] = {
            "raw_line_count": 0,
            "parsed_line_count": 0,
            "malformed_line_count": 0,
            "bad_json_count": 0,
            "invalid_timestamp_count": 0,
            "skipped_event_count": 0,
            "task_request_count": 0,
            "task_response_count": 0,
            "new_implant_count": 0,
            "duplicate_task_rows": 0,
            "synthetic_task_from_response_count": 0,
            "missing_task_uid_count": 0,
            "skip_reasons": {},
        }

        for path in files:
            with path.open(encoding="utf-8") as f:
                for line in f:
                    _increment(stats, "raw_line_count")
                    line_ts, record, error = _parse_log_line(line)
                    if error:
                        if error.startswith("bad json"):
                            _increment(stats, "bad_json_count")
                        elif error.startswith("bad line timestamp"):
                            _increment(stats, "invalid_timestamp_count")
                        else:
                            _increment(stats, "malformed_line_count")
                        _increment_reason(stats, error)
                        continue
                    if record is None or line_ts is None:
                        _increment(stats, "malformed_line_count")
                        _increment_reason(stats, "missing parsed record")
                        continue

                    _increment(stats, "parsed_line_count")
                    event_type = _jsonish(record.get("event_type")).strip()
                    implant = record.get("implant") if isinstance(record.get("implant"), dict) else {}
                    task = record.get("task") if isinstance(record.get("task"), dict) else {}
                    implant_uid = _jsonish(implant.get("uid")).strip()
                    if implant_uid:
                        implant_uids.add(implant_uid)

                    if event_type == "new_implant":
                        _increment(stats, "new_implant_count")
                        continue
                    if event_type == "task_request":
                        _increment(stats, "task_request_count")
                        self._add_task_event(
                            task_events,
                            seen_task_uids,
                            stats,
                            operation_id,
                            implant,
                            task,
                            line_ts,
                            synthetic=False,
                        )
                        continue
                    if event_type == "task_response":
                        _increment(stats, "task_response_count")
                        task_uid = _jsonish(task.get("uid")).strip()
                        if task_uid and task_uid not in seen_task_uids:
                            self._add_task_event(
                                task_events,
                                seen_task_uids,
                                stats,
                                operation_id,
                                implant,
                                task,
                                line_ts,
                                synthetic=True,
                            )
                        result = self._build_result_event(operation_id, task, line_ts)
                        if result is not None:
                            result_events.append(result)
                        continue

                    _increment(stats, "skipped_event_count")
                    _increment_reason(stats, f"unsupported event_type: {event_type or '(empty)'}")

        status_counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
        for event in result_events:
            status_counts[event.status] = status_counts.get(event.status, 0) + 1

        metadata: dict[str, Any] = {
            "source": self.SOURCE,
            "tool_name": self.TOOL_NAME,
            "operation_id": operation_id,
            "operation_name": operation_name,
            "operation_slug": slugify(operation_name),
            "outflank_log_path": str(self.log_path),
            "outflank_log_files": [str(p) for p in files],
            "log_file_count": len(files),
            "implant_count": len(implant_uids),
            "implant_uids": sorted(implant_uids),
            "task_count": len(task_events),
            "result_count": len(result_events),
            "status_counts": status_counts,
            **stats,
        }
        return task_events, result_events, metadata

    def _add_task_event(
        self,
        task_events: list[TaskEvent],
        seen_task_uids: set[str],
        stats: dict[str, Any],
        operation_id: int,
        implant: dict[str, Any],
        task: dict[str, Any],
        line_ts: str,
        *,
        synthetic: bool,
    ) -> None:
        task_uid = _jsonish(task.get("uid")).strip()
        if not task_uid:
            _increment(stats, "missing_task_uid_count")
            _increment_reason(stats, "missing task uid")
            return
        if task_uid in seen_task_uids:
            _increment(stats, "duplicate_task_rows")
            return

        task_ts = _normalize_timestamp_or_none(task.get("timestamp")) or line_ts
        if not task_ts:
            _increment(stats, "invalid_timestamp_count")
            _increment_reason(stats, "missing task timestamp")
            return

        implant_uid = _jsonish(implant.get("uid")).strip()
        callback_id = coerce_outflank_id(implant_uid)
        task_id = coerce_outflank_id(task_uid)
        if task_id == 0:
            _increment(stats, "missing_task_uid_count")
            _increment_reason(stats, "task uid coerced to 0")
            return

        if synthetic:
            _increment(stats, "synthetic_task_from_response_count")

        seen_task_uids.add(task_uid)
        task_events.append(
            TaskEvent(
                source=self.SOURCE,
                operation_id=operation_id,
                callback_id=callback_id,
                callback_display_id=callback_id,
                task_id=task_id,
                display_id=task_id,
                timestamp=task_ts,
                tool_name=self.TOOL_NAME,
                command_name=_command_name(task),
                arguments_raw=_arguments_raw(task),
                callback_sleep_info=_format_delay(implant),
                c2_task_id=task_uid,
            )
        )

    def _build_result_event(
        self,
        operation_id: int,
        task: dict[str, Any],
        line_ts: str,
    ) -> ResultEvent | None:
        task_uid = _jsonish(task.get("uid")).strip()
        if not task_uid:
            return None
        task_id = coerce_outflank_id(task_uid)
        if task_id == 0:
            return None

        response_raw = task.get("response")
        output_text = "" if response_raw is None else _jsonish(response_raw)
        result_ts = (
            _normalize_timestamp_or_none(task.get("response_timestamp"))
            or _normalize_timestamp_or_none(task.get("timestamp"))
            or line_ts
        )
        return ResultEvent(
            source=self.SOURCE,
            operation_id=operation_id,
            task_id=task_id,
            timestamp=result_ts,
            status=_infer_result_status(output_text),
            output_text=output_text,
        )


def run_outflank_log_ingest(
    log_path: Path | str,
    operation_id: int,
    operation_name: str,
    out_dir: Path,
    analysis_timestamp: datetime | None = None,
    output_rule: str = "all",
    arguments_rule: str = "all",
) -> dict[str, Any]:
    """Normalize Outflank logs, apply retention policy, and write artifacts."""
    parser = OutflankLogParser(log_path)
    task_events, result_events, metadata = parser.normalize(
        operation_id=operation_id,
        operation_name=operation_name,
    )
    apply_arguments_rule_to_tasks(task_events, arguments_rule)
    apply_output_rule_to_results(result_events, output_rule)
    rule_applied = normalize_output_rule(output_rule)
    args_rule_applied = normalize_arguments_rule(arguments_rule)

    if not task_events and not result_events:
        raise RuntimeError(f"no Outflank task or result events found in {log_path}")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if analysis_timestamp is None:
        analysis_timestamp = datetime.now(timezone.utc)

    events_path = out_dir / "events.ndjson"
    bundle_path = out_dir / "bundle.json"

    all_events = [e.to_dict() for e in task_events] + [e.to_dict() for e in result_events]
    write_ndjson(all_events, events_path)

    meta = dict(metadata)
    meta["output_rule"] = rule_applied
    meta["arguments_rule"] = args_rule_applied
    meta["events_path"] = events_path.name
    write_bundle(meta, bundle_path, analysis_timestamp)
    return meta

