"""
PTY-aware normalization helpers for Mythic pull ingest.

Interactive wire protocol (Mythic docs): message_type 0=Input, 1=Output, 2=Error,
3=Exit, 4+=terminal control. Input is operator→agent; output/error are agent→Mythic.

Hasura GraphQL: optional root field ``interactive`` (table public.interactive when
exposed). Verified optional against Mythic 3.x — many deployments only persist PTY
child task rows plus task.stdout/stderr; when ``interactive`` is absent, ingest falls
back to parsing UI-entered lines from child ``pty`` tasks.
"""

from __future__ import annotations

import base64
import json
from collections import defaultdict
from typing import Any

from Core.models import ResultEvent, TaskEvent, normalize_timestamp

# Mythic interactive tasking message_type (see Mythic interactive tasking docs)
MSG_INPUT = 0
MSG_OUTPUT = 1
MSG_ERROR = 2
MSG_EXIT = 3


def make_synthetic_pty_task_id(parent_task_id: int, sequence: int) -> int:
    """Deterministic negative task_id: cannot collide with Mythic positive ids."""
    return -(parent_task_id * 1_000_000 + sequence)


def decode_interactive_data(row: dict) -> bytes:
    """Decode base64 ``data`` field from an interactive message row."""
    raw = row.get("data")
    if raw is None:
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    s = str(raw).strip()
    if not s:
        return b""
    return base64.b64decode(s, validate=False)


def parse_pty_input_line(line: str) -> tuple[str, str, str] | None:
    """Parse a single shell-like line into (command_name, arguments_raw, pty_input_raw)."""
    s = line.strip()
    if not s:
        return None
    parts = s.split(None, 1)
    cmd = parts[0]
    args = parts[1] if len(parts) > 1 else ""
    if not cmd:
        return None
    return cmd, args, s


def group_interactive_by_parent_task_id(
    rows: list[dict],
    task_by_id: dict[int, dict],
) -> dict[int, list[dict]]:
    """Group interactive rows by Mythic numeric parent task ``id``."""
    by_parent: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        tid = row.get("task_id")
        if tid is None:
            continue
        parent = task_by_id.get(int(tid))
        if not parent:
            continue
        by_parent[int(tid)].append(row)
    for plist in by_parent.values():
        plist.sort(key=lambda r: normalize_timestamp(r.get("timestamp", "")))
    return dict(by_parent)


def _split_lines_from_buffer(buf: bytearray) -> list[bytes]:
    """Take complete \\n-terminated lines from buf; keep remainder in buf."""
    lines: list[bytes] = []
    while True:
        try:
            idx = buf.index(b"\n")
        except ValueError:
            break
        chunk = bytes(buf[:idx])
        del buf[: idx + 1]
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        lines.append(chunk)
    return lines


def _bytes_to_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _parse_exit_code(data: bytes) -> int | None:
    text = _bytes_to_text(data).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def build_synthetics_from_interactive_stream(
    operation_id: int,
    parent_row: dict,
    messages: list[dict],
    *,
    start_sequence: int = 1,
) -> tuple[list[TaskEvent], list[ResultEvent], list[int], str, dict[str, Any]]:
    """
    Build synthetic task/result pairs from ordered interactive messages for one PTY parent.

    Returns (task_events, result_events, message_ids_used, preface_output_before_first_command, exit_info).
    """
    messages = sorted(messages, key=lambda r: normalize_timestamp(r.get("timestamp", "")))
    parent_id = int(parent_row["id"])
    callback_id = parent_row.get("callback_id") or 0
    callback_data = parent_row.get("callback") or {}
    callback_display_id = callback_data.get("display_id") or 0
    callback_sleep_info = callback_data.get("sleep_info") or ""
    processing_ts_raw = parent_row.get("status_timestamp_processing")
    processing_timestamp = normalize_timestamp(processing_ts_raw) if processing_ts_raw else ""

    input_buf = bytearray()
    input_msg_ids: list[int] = []
    preface_parts: list[str] = []
    cmds: list[dict[str, Any]] = []
    msg_ids_used: list[int] = []
    exit_info: dict[str, Any] = {}
    seq = start_sequence

    def flush_input_buffer(
        as_eof: bool, completed_at: str, current_msg_id: int | None = None
    ) -> None:
        nonlocal seq, input_buf, input_msg_ids
        lines = _split_lines_from_buffer(input_buf)
        if as_eof and input_buf:
            lines.append(bytes(input_buf))
            input_buf.clear()
        for line_b in lines:
            text = _bytes_to_text(line_b).strip("\r")
            parsed = parse_pty_input_line(text)
            if parsed is None:
                continue
            cmd_name, args_raw, raw_line = parsed
            sequence = seq
            stid = make_synthetic_pty_task_id(parent_id, seq)
            seq += 1
            cmds.append(
                {
                    "task_id": stid,
                    "sequence": sequence,
                    "command_name": cmd_name,
                    "arguments_raw": args_raw,
                    "pty_input_raw": raw_line,
                    "input_message_ids": list(input_msg_ids),
                    "output_parts": [],
                    "output_message_ids": [],
                    "output_timestamps": [],
                    "error_observed": False,
                    "task_timestamp": completed_at,
                }
            )
        if lines:
            input_msg_ids = [current_msg_id] if input_buf and current_msg_id is not None else []

    for row in messages:
        mt = row.get("message_type")
        try:
            mt_int = int(mt) if mt is not None else -1
        except (TypeError, ValueError):
            mt_int = -1
        rid = row.get("id")
        rid_int = int(rid) if rid is not None else None
        row_ts = normalize_timestamp(row.get("timestamp", ""))
        raw_b = decode_interactive_data(row)
        if rid_int is not None:
            msg_ids_used.append(rid_int)

        if mt_int == MSG_INPUT:
            if rid_int is not None and rid_int not in input_msg_ids:
                input_msg_ids.append(rid_int)
            input_buf.extend(raw_b)
            flush_input_buffer(as_eof=False, completed_at=row_ts, current_msg_id=rid_int)
            if input_buf and rid_int is not None and rid_int not in input_msg_ids:
                input_msg_ids.append(rid_int)
        elif mt_int in (MSG_OUTPUT, MSG_ERROR):
            text = _bytes_to_text(raw_b)
            if not cmds:
                if text:
                    preface_parts.append(text)
            else:
                cmds[-1]["output_parts"].append(text)
                if rid_int is not None:
                    cmds[-1]["output_message_ids"].append(rid_int)
                cmds[-1]["output_timestamps"].append(row_ts)
                if mt_int == MSG_ERROR:
                    cmds[-1]["error_observed"] = True
        elif mt_int == MSG_EXIT:
            flush_input_buffer(as_eof=True, completed_at=row_ts, current_msg_id=rid_int)
            exit_info = {
                "pty_exit_observed": True,
                "pty_exit_timestamp": row_ts,
            }
            exit_code = _parse_exit_code(raw_b)
            if exit_code is not None:
                exit_info["pty_exit_code"] = exit_code
            break
        # control codes (>=4): ignore for command synthesis (v1)

    final_ts_raw = parent_row.get("status_timestamp_processed") or parent_row.get("timestamp")
    final_ts = normalize_timestamp(final_ts_raw)
    flush_input_buffer(as_eof=True, completed_at=exit_info.get("pty_exit_timestamp", final_ts))
    preface = "".join(preface_parts)

    task_events: list[TaskEvent] = []
    result_events: list[ResultEvent] = []

    for i, c in enumerate(cmds):
        te = TaskEvent(
            source="mythic",
            operation_id=operation_id,
            callback_id=callback_id,
            callback_display_id=callback_display_id,
            task_id=c["task_id"],
            display_id=0,
            timestamp=c["task_timestamp"],
            tool_name="mythic",
            command_name=c["command_name"],
            arguments_raw=c["arguments_raw"],
            processing_timestamp=processing_timestamp,
            callback_sleep_info=callback_sleep_info,
            issued_command_name="",
            parent_task_id=parent_id,
            pty_synthetic=True,
            pty_parent_task_id=parent_id,
            pty_sequence=c["sequence"],
            pty_input_raw=c.get("pty_input_raw", ""),
            pty_input_message_ids=c.get("input_message_ids", []),
        )
        task_events.append(te)

        out_text = "".join(c["output_parts"])
        if c["output_timestamps"]:
            result_ts = c["output_timestamps"][-1]
        elif i + 1 < len(cmds):
            result_ts = cmds[i + 1]["task_timestamp"]
        else:
            result_ts = exit_info.get("pty_exit_timestamp", c["task_timestamp"])
        res_status: str = "error" if c["error_observed"] else "success"
        result_events.append(
            ResultEvent(
                source="mythic",
                operation_id=operation_id,
                task_id=c["task_id"],
                timestamp=result_ts,
                status=res_status,
                output_text=out_text,
                pty_synthetic=True,
                pty_parent_task_id=parent_id,
                pty_sequence=c["sequence"],
                pty_output_message_ids=c.get("output_message_ids", []),
            )
        )

    return task_events, result_events, msg_ids_used, preface, exit_info


def build_synthetics_from_child_pty_tasks(
    operation_id: int,
    parent_row: dict,
    child_rows: list[dict],
    *,
    start_sequence: int = 1,
) -> tuple[list[TaskEvent], list[ResultEvent], set[int]]:
    """One synthetic per child row when ``arguments_raw`` parses as a command line."""
    parent_id = int(parent_row["id"])
    callback_id = parent_row.get("callback_id") or 0
    callback_data = parent_row.get("callback") or {}
    callback_display_id = callback_data.get("display_id") or 0
    callback_sleep_info = callback_data.get("sleep_info") or ""
    processing_ts_raw = parent_row.get("status_timestamp_processing")
    processing_timestamp = normalize_timestamp(processing_ts_raw) if processing_ts_raw else ""

    child_rows = sorted(child_rows, key=lambda t: normalize_timestamp(t.get("status_timestamp_submitted") or t["timestamp"]))
    task_events: list[TaskEvent] = []
    result_events: list[ResultEvent] = []
    suppressed: set[int] = set()
    seq = start_sequence

    for ch in child_rows:
        ch_id = int(ch["id"])
        op = ch.get("original_params")
        if op is None:
            line_src = ""
        elif isinstance(op, str):
            line_src = op
        else:
            line_src = json.dumps(op)
        parsed = parse_pty_input_line(line_src.replace("\x00", ""))
        if parsed is None:
            continue
        cmd_name, args_raw, raw_line = parsed
        stid = make_synthetic_pty_task_id(parent_id, seq)
        seq += 1
        suppressed.add(ch_id)

        submitted_ts = ch.get("status_timestamp_submitted")
        task_ts = normalize_timestamp(submitted_ts if submitted_ts else ch["timestamp"])

        task_events.append(
            TaskEvent(
                source="mythic",
                operation_id=operation_id,
                callback_id=ch.get("callback_id") or callback_id,
                callback_display_id=ch.get("callback", {}).get("display_id") or callback_display_id,
                task_id=stid,
                display_id=ch.get("display_id") or 0,
                timestamp=task_ts,
                tool_name="mythic",
                command_name=cmd_name,
                arguments_raw=args_raw,
                processing_timestamp=processing_timestamp,
                callback_sleep_info=ch.get("callback", {}).get("sleep_info") or callback_sleep_info,
                issued_command_name="pty",
                parent_task_id=parent_id,
                pty_synthetic=True,
                pty_parent_task_id=parent_id,
                pty_input_task_id=ch_id,
                pty_sequence=seq - 1,
                pty_input_raw=raw_line,
            )
        )
        status_ts = ch.get("status_timestamp_processed")
        res_ts = normalize_timestamp(status_ts) if status_ts else task_ts
        status, dispatch_failed = ResultEvent.determine_status(ch["completed"], ch["status"])
        result_events.append(
            ResultEvent(
                source="mythic",
                operation_id=operation_id,
                task_id=stid,
                timestamp=res_ts,
                status=status if not dispatch_failed else "error",
                dispatch_failed=dispatch_failed,
                output_text="",
                pty_synthetic=True,
                pty_parent_task_id=parent_id,
                pty_sequence=seq - 1,
            )
        )

    return task_events, result_events, suppressed
