"""
Parser/source data-quality summaries for Janus reports and bundles.

The functions in this module intentionally work from plain dictionaries so they
can summarize parser metadata, merged bundle entries, and older bundles with
only events.ndjson available.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


STATUS_KEYS = ("success", "error", "unknown")

SKIPPED_FIELDS = (
    "skipped_entry_count",
    "skipped_entries",
    "skipped_task_count",
    "skipped_event_count",
    "skipped_task_rows",
    "skipped_list_rows",
)

PARSER_COUNT_FIELDS = (
    "skipped_entry_count",
    "skipped_task_count",
    "skipped_event_count",
    "skipped_task_rows",
    "skipped_list_rows",
    "malformed_line_count",
    "bad_json_count",
    "task_fetch_errors",
    "beacon_list_skipped_rows",
    "beacon_list_fetch_errors",
    "beacon_detail_fetch_errors",
    "duplicate_task_rows",
    "synthetic_task_from_response_count",
    "missing_task_uid_count",
)

WARNING_LIST_FIELDS = ("parser_warnings", "ingest_warnings")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _source(metadata: dict[str, Any]) -> str:
    value = metadata.get("source")
    if value is None or str(value).strip() == "":
        return "unknown"
    return str(value)


def _status_distribution(status_counts: Any) -> dict[str, int]:
    counts = {"success": 0, "error": 0, "unknown": 0, "other": 0}
    if not isinstance(status_counts, dict):
        return counts
    for key, value in status_counts.items():
        count = _safe_int(value)
        if key in STATUS_KEYS:
            counts[str(key)] += count
        else:
            counts["other"] += count
    return counts


def _status_counts_from_events(result_events: list[dict[str, Any]] | None) -> dict[str, int]:
    counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
    for event in result_events or []:
        status = str(event.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _events_parsed(
    metadata: dict[str, Any],
    task_events: list[dict[str, Any]] | None,
    result_events: list[dict[str, Any]] | None,
) -> int:
    explicit = metadata.get("events_parsed")
    if explicit is not None:
        return _safe_int(explicit)
    if task_events is not None or result_events is not None:
        return len(task_events or []) + len(result_events or [])
    task_count = metadata.get("task_count")
    result_count = metadata.get("result_count")
    if task_count is not None or result_count is not None:
        return _safe_int(task_count) + _safe_int(result_count)
    return _safe_int(metadata.get("event_count"))


def _sum_fields(metadata: dict[str, Any], fields: tuple[str, ...]) -> int:
    return sum(_safe_int(metadata.get(field)) for field in fields)


def _parser_invalid_counts(metadata: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for field in PARSER_COUNT_FIELDS:
        value = _safe_int(metadata.get(field), default=0)
        if value:
            counts[field] = value

    skip_reasons = metadata.get("skip_reasons")
    if isinstance(skip_reasons, dict):
        for reason, value in skip_reasons.items():
            count = _safe_int(value)
            if count:
                counts[f"skip_reason:{reason}"] = count

    return counts


def _list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _parser_warnings(metadata: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    for field in WARNING_LIST_FIELDS:
        warnings.extend(_list_strings(metadata.get(field)))
    return warnings


def _metadata_incomplete(metadata: dict[str, Any]) -> bool:
    required = ("source", "status_counts", "arguments_rule", "output_rule")
    has_counts = metadata.get("events_parsed") is not None or (
        metadata.get("task_count") is not None and metadata.get("result_count") is not None
    )
    return not has_counts or any(metadata.get(key) in (None, "") for key in required)


def _append_unique(values: list[str], text: str) -> None:
    if text and text not in values:
        values.append(text)


def add_interpretation_warnings(entry: dict[str, Any]) -> dict[str, Any]:
    """Add factual confidence warnings to a data-quality entry."""
    entry = dict(entry)
    warnings = list(entry.get("warnings") or [])
    source = str(entry.get("source") or "unknown")

    unknown_percent = float(entry.get("unknown_status_percent") or 0.0)
    unknown_count = _safe_int((entry.get("status_distribution") or {}).get("unknown"))
    if unknown_percent >= 80.0 and unknown_count:
        if unknown_percent == 100.0:
            suffix = "all results"
        else:
            suffix = f"{unknown_percent:.1f}% of results"
        _append_unique(
            warnings,
            "Failure-rate and retry-success analysis are low-confidence "
            f"because this source emits unknown status for {suffix}.",
        )

    invalid_timestamps = _safe_int(entry.get("invalid_timestamps"))
    if invalid_timestamps:
        _append_unique(
            warnings,
            "Timeline and dwell-time analysis may be affected because "
            f"{invalid_timestamps} invalid timestamp"
            f"{'' if invalid_timestamps == 1 else 's'} were observed.",
        )

    fallback_task_ids = _safe_int(entry.get("fallback_task_ids"))
    if fallback_task_ids:
        _append_unique(
            warnings,
            "Task correlation may be incomplete because "
            f"{fallback_task_ids} fallback/generated task ID"
            f"{'' if fallback_task_ids == 1 else 's'} were used.",
        )

    argument_retention = str(entry.get("argument_retention") or "unknown")
    if argument_retention in {"drop", "dropped", "features_only"}:
        _append_unique(
            warnings,
            "Argument-level analysis is limited because argument retention "
            f"mode is {argument_retention}.",
        )

    output_retention = str(entry.get("output_retention") or "unknown")
    if output_retention == "none":
        _append_unique(
            warnings,
            "Output and error-signature analysis is limited because output "
            "retention mode is none.",
        )
    elif output_retention == "errors_only":
        _append_unique(
            warnings,
            "Success-output analysis is unavailable or limited because output "
            "retention mode is errors_only.",
        )

    if entry.get("metadata_incomplete"):
        _append_unique(
            warnings,
            f"Parser quality metadata for {source} was incomplete; metrics are best-effort.",
        )

    entry["warnings"] = warnings
    return entry


def build_data_quality_entry(
    metadata: dict[str, Any] | None,
    task_events: list[dict[str, Any]] | None = None,
    result_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one source/parser data-quality entry from metadata and optional events."""
    metadata = dict(metadata or {})
    status_counts = metadata.get("status_counts")
    if not isinstance(status_counts, dict) and result_events is not None:
        status_counts = _status_counts_from_events(result_events)
    status_distribution = _status_distribution(status_counts)
    status_total = sum(status_distribution.values())
    unknown_percent = (
        round((status_distribution["unknown"] / status_total) * 100.0, 1)
        if status_total
        else 0.0
    )

    entry = {
        "source": _source(metadata),
        "events_parsed": _events_parsed(metadata, task_events, result_events),
        "skipped_entries": _sum_fields(metadata, SKIPPED_FIELDS),
        "invalid_timestamps": _safe_int(metadata.get("invalid_timestamp_count")),
        "fallback_task_ids": _safe_int(metadata.get("fallback_task_id_count")),
        "invalid_record_counts": _parser_invalid_counts(metadata),
        "status_distribution": status_distribution,
        "unknown_status_percent": unknown_percent,
        "argument_retention": str(metadata.get("arguments_rule") or "unknown"),
        "output_retention": str(metadata.get("output_rule") or "unknown"),
        "warnings": _parser_warnings(metadata),
        "metadata_incomplete": _metadata_incomplete(metadata),
    }
    return add_interpretation_warnings(entry)


def _entries_from_events(
    metadata: dict[str, Any],
    task_events: list[dict[str, Any]] | None,
    result_events: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    grouped_tasks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_results: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in task_events or []:
        grouped_tasks[str(event.get("source") or _source(metadata))].append(event)
    for event in result_events or []:
        grouped_results[str(event.get("source") or _source(metadata))].append(event)

    sources = sorted(set(grouped_tasks) | set(grouped_results))
    if not sources:
        return [build_data_quality_entry(metadata, task_events, result_events)]

    entries = []
    for source in sources:
        source_metadata = dict(metadata)
        source_metadata["source"] = source
        source_metadata["task_count"] = len(grouped_tasks.get(source, []))
        source_metadata["result_count"] = len(grouped_results.get(source, []))
        source_metadata["status_counts"] = _status_counts_from_events(
            grouped_results.get(source, [])
        )
        entries.append(
            build_data_quality_entry(
                source_metadata,
                grouped_tasks.get(source, []),
                grouped_results.get(source, []),
            )
        )
    return entries


def build_data_quality(
    metadata: dict[str, Any] | None,
    task_events: list[dict[str, Any]] | None = None,
    result_events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return normalized data-quality entries for a bundle or event set."""
    metadata = dict(metadata or {})
    existing = metadata.get("data_quality")
    if isinstance(existing, list) and existing:
        return [
            add_interpretation_warnings(dict(entry))
            for entry in existing
            if isinstance(entry, dict)
        ]
    if task_events is not None or result_events is not None:
        return _entries_from_events(metadata, task_events, result_events)
    return [build_data_quality_entry(metadata)]


def aggregate_data_quality(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate data-quality entries by source for merged reports."""
    grouped: dict[str, dict[str, Any]] = {}
    retention_modes: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"argument": set(), "output": set()}
    )

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source") or "unknown")
        current = grouped.setdefault(
            source,
            {
                "source": source,
                "events_parsed": 0,
                "skipped_entries": 0,
                "invalid_timestamps": 0,
                "fallback_task_ids": 0,
                "invalid_record_counts": {},
                "status_distribution": {"success": 0, "error": 0, "unknown": 0, "other": 0},
                "warnings": [],
                "metadata_incomplete": False,
            },
        )
        for field in ("events_parsed", "skipped_entries", "invalid_timestamps", "fallback_task_ids"):
            current[field] += _safe_int(entry.get(field))
        for key, value in (entry.get("invalid_record_counts") or {}).items():
            current["invalid_record_counts"][key] = (
                current["invalid_record_counts"].get(key, 0) + _safe_int(value)
            )
        for key, value in (entry.get("status_distribution") or {}).items():
            bucket = key if key in {"success", "error", "unknown", "other"} else "other"
            current["status_distribution"][bucket] += _safe_int(value)
        if entry.get("metadata_incomplete"):
            current["metadata_incomplete"] = True
        for warning in _list_strings(entry.get("warnings")):
            _append_unique(current["warnings"], warning)
        arg_mode = str(entry.get("argument_retention") or "unknown")
        out_mode = str(entry.get("output_retention") or "unknown")
        if arg_mode:
            retention_modes[source]["argument"].add(arg_mode)
        if out_mode:
            retention_modes[source]["output"].add(out_mode)

    output: list[dict[str, Any]] = []
    for source, entry in sorted(grouped.items()):
        status_total = sum(entry["status_distribution"].values())
        entry["unknown_status_percent"] = (
            round((entry["status_distribution"]["unknown"] / status_total) * 100.0, 1)
            if status_total
            else 0.0
        )
        arg_modes = retention_modes[source]["argument"]
        out_modes = retention_modes[source]["output"]
        entry["argument_retention"] = next(iter(arg_modes)) if len(arg_modes) == 1 else "mixed"
        entry["output_retention"] = next(iter(out_modes)) if len(out_modes) == 1 else "mixed"
        output.append(add_interpretation_warnings(entry))
    return output
