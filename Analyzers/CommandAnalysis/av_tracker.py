"""
AV Tracker - Analyzer 50.

Scans process-list (`ps`) results for known AV executable names from the
signature registry and reports detections by callback and vendor.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections import defaultdict

from Core.av_signature_registry import AVSignatureRegistry

_PS_JSON_TEXT_KEYS = (
    "name",
    "bin_path",
    "command_line",
    "description",
    "company_name",
    "window_title",
    "user",
    "signer",
    "architecture",
)


def _task_key(event: dict) -> tuple[int, int]:
    return (event.get("operation_id", 0), event["task_id"])


_MIN_STEM_LENGTH = 6  # stems shorter than this are too generic for safe substring matching


def _match_needles_for_executable(exe_name: str) -> tuple[str, ...]:
    """Substrings to search for (lowercase).

    The full ``name.exe`` form is always included. The bare stem (without
    ``.exe``) is added only when it is long enough to be distinctive — short
    stems like ``amsvc`` (5 chars) or ``smc`` (3 chars) appear as accidental
    substrings in unrelated process names, paths, and descriptions, causing
    false-positive vendor detections.
    """
    lower = exe_name.lower()
    needles = [lower]
    if lower.endswith(".exe"):
        stem = lower[:-4]
        if len(stem) >= _MIN_STEM_LENGTH:
            needles.append(stem)
    return tuple(dict.fromkeys(needles))


def _process_like_dict(row: object) -> bool:
    if not isinstance(row, dict) or not row.get("name"):
        return False
    return (
        "process_id" in row
        or "pid" in row
        or "parent_process_id" in row
    )


def _text_from_process_rows(rows: list[object]) -> str:
    fragments: list[str] = []
    for row in rows:
        if not _process_like_dict(row):
            continue
        d = row
        for key in _PS_JSON_TEXT_KEYS:
            val = d.get(key)
            if isinstance(val, str) and val.strip():
                fragments.append(val)
    return "\n".join(fragments)


def _search_corpus_for_ps_output(output_text: str) -> str:
    """
    Build a lowercase blob for substring matching.

    Mythic Apollo often returns `ps` as base64-encoded JSON: a list of objects
    with `name` (no .exe suffix) and `process_id`. Plain text `ps` output is
    passed through as-is (both forms are combined so registry .exe names and
    stems match).
    """
    raw = output_text or ""
    compact = re.sub(r"\s+", "", raw.strip())
    if len(compact) < 32:
        return raw.lower()
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return raw.lower()
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return raw.lower()

    # Decoded content is authoritative for base64 payloads. Scanning the raw
    # base64 text can create accidental substring hits (e.g., short exe stems).
    parts: list[str] = [text]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "\n".join(parts).lower()
    if isinstance(data, list) and data:
        extracted = _text_from_process_rows(data)
        if extracted:
            parts.append(extracted)
    return "\n".join(parts).lower()


def analyze(task_events: list[dict], result_events: list[dict]) -> dict:
    registry = AVSignatureRegistry.from_path()
    task_by_id: dict[tuple[int, int], dict] = {}
    for task in task_events:
        task_by_id[_task_key(task)] = task

    detection_groups: dict[tuple[int, int, str, tuple[str, ...]], dict] = {}
    vendor_hits: dict[str, dict] = {}
    callback_hits: dict[str, dict] = {}
    ps_tasks_scanned = 0
    matching_ps_outputs = 0

    for vendor_key, vendor in registry.vendors.items():
        vendor_hits[vendor_key] = {
            "display_name": vendor.display_name,
            "detection_count": 0,
            "callbacks": [],
            "executables": {exe_name: 0 for exe_name in vendor.executables},
        }

    callback_vendor_execs: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    vendor_callback_keys: dict[str, set[str]] = defaultdict(set)

    for result in result_events:
        task = task_by_id.get(_task_key(result))
        if task is None or task.get("command_name") != "ps":
            continue

        ps_tasks_scanned += 1
        output_text = str(result.get("output_text") or "")
        if not output_text:
            continue

        output_corpus = _search_corpus_for_ps_output(output_text)
        result_had_match = False
        for vendor_key, vendor in registry.vendors.items():
            matched_execs = []
            for exe_name in vendor.executables:
                if any(needle in output_corpus for needle in _match_needles_for_executable(exe_name)):
                    matched_execs.append(exe_name)
            if not matched_execs:
                continue

            result_had_match = True
            callback_scope = f"{task.get('operation_id', 0)}:{task.get('callback_id', 0)}"
            vendor_callback_keys[vendor_key].add(callback_scope)

            operation_id = task.get("operation_id", 0)
            callback_id = task.get("callback_id", 0)
            sorted_execs = tuple(sorted(matched_execs))
            group_key = (operation_id, callback_id, vendor_key, sorted_execs)
            if group_key not in detection_groups:
                detection_groups[group_key] = {
                    "operation_id": operation_id,
                    "callback_id": callback_id,
                    "callback_display_id": task.get("callback_display_id", 0),
                    "task_id": task["task_id"],
                    "display_id": task.get("display_id", 0),
                    "timestamp": result.get("timestamp", task.get("timestamp", "")),
                    "status": result.get("status", "unknown"),
                    "vendor_key": vendor_key,
                    "vendor_name": vendor.display_name,
                    "matched_executables": list(sorted_execs),
                    "occurrence_count": 1,
                }
            else:
                detection_groups[group_key]["occurrence_count"] += 1
                if (
                    not detection_groups[group_key].get("callback_display_id")
                    and task.get("callback_display_id")
                ):
                    detection_groups[group_key]["callback_display_id"] = task.get("callback_display_id", 0)

            vendor_hits[vendor_key]["detection_count"] += 1
            for exe_name in matched_execs:
                vendor_hits[vendor_key]["executables"][exe_name] += 1
                callback_vendor_execs[callback_scope][vendor_key].add(exe_name)
        if result_had_match:
            matching_ps_outputs += 1

    detections = list(detection_groups.values())

    for callback_scope, vendor_map in sorted(callback_vendor_execs.items()):
        operation_id_str, callback_id_str = callback_scope.split(":", 1)
        callback_detection = {
            "operation_id": int(operation_id_str),
            "callback_id": int(callback_id_str),
            "callback_display_id": 0,
            "vendors": [],
        }

        for detection in detections:
            if (
                detection["operation_id"] == callback_detection["operation_id"]
                and detection["callback_id"] == callback_detection["callback_id"]
                and detection.get("callback_display_id")
            ):
                callback_detection["callback_display_id"] = detection["callback_display_id"]
                break

        for vendor_key, exec_names in sorted(vendor_map.items()):
            callback_detection["vendors"].append({
                "vendor_key": vendor_key,
                "vendor_name": registry.vendors[vendor_key].display_name,
                "matched_executables": sorted(exec_names),
            })

        callback_hits[callback_scope] = callback_detection

    for vendor_key, data in vendor_hits.items():
        data["callbacks"] = sorted(vendor_callback_keys.get(vendor_key, set()))

    detections.sort(
        key=lambda item: (
            item.get("timestamp", ""),
            item.get("operation_id", 0),
            item.get("callback_id", 0),
            item.get("task_id", 0),
        )
    )

    return {
        "analyzer": "av_tracker",
        "summary": {
            "ps_tasks_scanned": ps_tasks_scanned,
            "matching_ps_outputs": matching_ps_outputs,
            "detection_count": len(detections),
            "callbacks_with_detections": len(callback_hits),
            "vendors_detected": [
                vendor_hits[vendor_key]["display_name"]
                for vendor_key in sorted(vendor_hits)
                if vendor_hits[vendor_key]["detection_count"] > 0
            ],
        },
        "callbacks": callback_hits,
        "vendors": vendor_hits,
        "detections": detections,
        "registry": registry.metadata(),
    }
