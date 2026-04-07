#!/usr/bin/env python3
"""
Janus - Turn red team and purple team operational logs into actionable intelligence.

CLI entry point for Mythic pull-mode and other source parsers.
"""

import argparse
import json
import os
import re
import sys
import zlib
import traceback
from datetime import datetime, timezone
from pathlib import Path

if sys.version_info < (3, 12):
    print(
        "error: Janus requires Python 3.12 or newer. Use the Go janus-cli wrapper or a newer Python runtime.",
        file=sys.stderr,
    )
    raise SystemExit(2)

import requests
import yaml

from Analyzers.SummaryAnalysis.summary_visualization import (
    analyze as summary_visualization,
)
from Analyzers.CommandAnalysis.command_failure_summary import (
    analyze as command_failure_summary,
)
from Analyzers.CommandAnalysis.command_retry_success import (
    analyze as command_retry_success,
)
from Analyzers.CommandAnalysis.command_duration import (
    analyze as command_duration,
)
from Analyzers.CommandAnalysis.outlier_context import (
    analyze as outlier_context,
)
from Analyzers.WorkflowAnalysis.callback_health import (
    analyze as callback_health,
)
from Analyzers.CommandAnalysis.av_tracker import (
    analyze as av_tracker,
)
from Analyzers.WorkflowAnalysis.dwell_time import (
    analyze as dwell_time,
)
from Analyzers.WorkflowAnalysis.parameter_entropy import (
    analyze as parameter_entropy,
)
from Analyzers.ToolingAnalysis.argument_position_profile import (
    analyze as argument_position_profile,
)
from Analyzers.ToolingAnalysis.tool_dump import (
    analyze as tool_dump,
)
from Core.analyzer_registry import (
    ALL_ANALYZERS,
    ANALYZER_OUTPUTS,
    MULTI_ANALYZE_ANALYZERS,
    PARTIAL_LOAD_ANALYZERS,
)
from Core.analyzer_behavior_registry import build_analyzer_context
from Core.html_output import generate_html
from Core.io import (
    EventValidationError,
    create_latest_symlink,
    get_versioned_output_dir,
    validate_events,
    write_bundle,
    write_ndjson,
)
from Core.output_rule import (
    apply_output_rule_to_results,
    apply_arguments_rule_to_tasks,
    apply_retention_policy,
    detect_retention_from_events,
    privacy_warnings_for_analyzer,
    resolve_output_rule,
    resolve_arguments_rule,
    resolve_retention_policy,
    RetentionPolicy,
)
from Parsers.Mythic.mythic_pull import MythicPullParser, slugify
from Parsers.Mythic.partial_data_adapter import load_partial_mythic_json
from Parsers.Ghostwriter.client import GhostwriterSchemaError
from Parsers.Ghostwriter.ghostwriter_pull import GhostwriterPullParser
from Parsers.Ghostwriter.ghostwriter_pull import slugify as gw_slugify
from Parsers.CobaltStrike.cobalt_strike_rest import (
    CobaltStrikeRestPullParser,
    slugify as cs_slugify,
    run_cobaltstrike_rest_ingest,
)


DEFAULT_MYTHIC_ENDPOINT = "https://10.0.0.217:7443/graphql/"
DEFAULT_GHOSTWRITER_ENDPOINT = "https://127.0.0.1"
DEFAULT_COBALT_STRIKE_REST_ENDPOINT = "https://127.0.0.1:50050"
DEFAULT_CONFIG_PATH = Path("Config/janus.yml")
GW_API_TOKEN_ENV = "GHOSTWRITER_API_KEY"


def _format_file_uri(path: Path) -> str:
    """Return a file:// URI for a local path."""
    return path.resolve().as_uri()


def _print_mythic_request_hints(endpoint: str, verify_tls: bool, exc_text: str) -> None:
    """Print focused troubleshooting hints for Mythic request failures."""
    exc_lower = exc_text.lower()
    print(f"hint: configured endpoint is '{endpoint}'", file=sys.stderr)
    print("hint: verify mythic.endpoint in Config/janus.yml matches your Mythic URL and port.", file=sys.stderr)
    protocol_mismatch = (
        "record layer failure" in exc_lower
        or "wrong version number" in exc_lower
        or "unknown protocol" in exc_lower
    )
    if protocol_mismatch:
        print(
            "hint: this usually means an HTTP/HTTPS mismatch (for example https://... pointed at an HTTP service).",
            file=sys.stderr,
        )
        print(
            "hint: if Mythic is HTTP, use an endpoint like 'http://<host>:<port>/graphql/'.",
            file=sys.stderr,
        )
    cert_verify_failed = (
        "certificate_verify_failed" in exc_lower
        or "certificate verify failed" in exc_lower
        or "self-signed certificate" in exc_lower
    )
    if verify_tls:
        if cert_verify_failed:
            print(
                "hint: TLS certificate validation failed (likely self-signed or untrusted cert).",
                file=sys.stderr,
            )
            print(
                "hint: set mythic.verify_tls: false in Config/janus.yml for lab/self-signed Mythic endpoints.",
                file=sys.stderr,
            )
            print(
                "hint: or rerun this command with --insecure for a one-off test.",
                file=sys.stderr,
            )
        else:
            print(
                "hint: if Mythic uses a self-signed cert, retry with '--insecure' after confirming the endpoint protocol.",
                file=sys.stderr,
            )

ANALYZER_FUNCTIONS = {
    "summary-visualization": summary_visualization,
    "command-failure-summary": command_failure_summary,
    "command-retry-success": command_retry_success,
    "command-duration": command_duration,
    "outlier-context": outlier_context,
    "callback-health": callback_health,
    "av-tracker": av_tracker,
    "dwell-time": dwell_time,
    "parameter-entropy": parameter_entropy,
    "argument-position-profile": argument_position_profile,
    "tool-dump": tool_dump,
}

REGISTRY_AWARE_ANALYZERS = {
    "command-duration",
    "parameter-entropy",
    "outlier-context",
    "argument-position-profile",
    "tool-dump",
}


def _build_runtime_analyzer_context(output_dir: Path | None = None) -> dict:
    context = build_analyzer_context()
    if output_dir is not None:
        context["output_dir"] = str(output_dir)
    return context


def load_config(config_path: Path | None) -> dict:
    """Load YAML config if path provided."""
    if config_path is None or not config_path.exists():
        return {}
    with config_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _resolve_cli_source(config: dict, requested_source: str | None) -> str:
    if requested_source:
        return requested_source

    configured = config.get("source")
    if configured in {"mythic", "ghostwriter", "cobaltstrike"}:
        return configured

    has_mythic = bool(config.get("mythic"))
    has_ghostwriter = bool(config.get("ghostwriter"))
    has_cobaltstrike = bool(config.get("cobaltstrike"))

    if has_ghostwriter and not has_mythic:
        return "ghostwriter"
    if has_cobaltstrike and not has_mythic and not has_ghostwriter:
        return "cobaltstrike"
    return "mythic"


def _merge_common_metadata(result: dict, common_metadata: dict) -> dict:
    merged = dict(result)
    merged["analyzer"] = common_metadata["analyzer"]
    merged_metadata = dict(result.get("metadata", {}))
    merged_metadata.update(common_metadata.get("metadata", {}))
    merged["metadata"] = merged_metadata
    return merged


def _run_analyzer(analyzer_name: str, analyzer_func, task_events: list[dict], result_events: list[dict], context: dict) -> dict:
    if analyzer_name in REGISTRY_AWARE_ANALYZERS:
        return analyzer_func(task_events, result_events, context)
    return analyzer_func(task_events, result_events)


def find_previous_versions(
    base_dir: Path, operation_slug: str, current_version: str
) -> list[dict]:
    """
    Scan for other {slug}_* directories, return sorted list (newest first).

    ``operation_slug`` is the filesystem-safe slug stored in ``bundle.json``
    (falls back to ``op-{id}`` for legacy directories).

    Returns list of dicts with keys: version, dir_name, report_path
    """
    if not base_dir.exists():
        return []

    pattern = re.compile(
        rf"^{re.escape(operation_slug)}_(\d{{8}}_\d{{6}})(?:_[a-f0-9]{{8}})?$"
    )
    versions = []

    for item in base_dir.iterdir():
        if not item.is_dir():
            continue
        match = pattern.match(item.name)
        if match:
            version = match.group(1)
            if version != current_version:
                report_path = item / "report.html"
                if report_path.exists():
                    versions.append({
                        "version": version,
                        "dir_name": item.name,
                        "report_path": report_path,
                    })

    # Sort by version string (YYYYMMDD_HHMMSS format is naturally sortable)
    versions.sort(key=lambda v: v["version"], reverse=True)
    return versions


def run_mythic(
    operation_id: int,
    endpoint: str | None,
    api_token: str | None,
    verify_tls: bool,
    out_dir: Path,
    config: dict,
    debug: bool = False,
    no_versioning: bool = False,
    output_rule_cli: str | None = None,
    arguments_rule_cli: str | None = None,
) -> int:
    """Run Mythic pull-mode parser."""
    mythic_cfg = config.get("mythic", {})
    endpoint = endpoint or mythic_cfg.get("endpoint") or DEFAULT_MYTHIC_ENDPOINT
    api_token = api_token or mythic_cfg.get("api_token")
    if not api_token:
        print(
            "error: API token required. Set --api-token or mythic.api_token in config.",
            file=sys.stderr,
        )
        return 1

    if not verify_tls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = MythicPullParser(endpoint=endpoint, api_token=api_token, verify_tls=verify_tls, debug=debug)

    print("Preflight: connectivity/auth (Mythic)...")
    try:
        parser.preflight(operation_id=operation_id)
    except requests.exceptions.RequestException as exc:
        exc_text = str(exc)
        print(
            f"error: Mythic preflight failed before ingest for operation {operation_id}: {exc_text}",
            file=sys.stderr,
        )
        _print_mythic_request_hints(endpoint, verify_tls, exc_text)
        if debug:
            traceback.print_exc()
        return 1
    except Exception as exc:
        print(f"error: Mythic preflight failed: {exc}", file=sys.stderr)
        if debug:
            traceback.print_exc()
        return 1

    print("Preflight: OK")

    # Resolve the real operation name from Mythic before creating the
    # output directory so the slug appears in the directory name.
    operation_name = parser.fetch_operation_name(operation_id)
    op_slug = slugify(operation_name)
    print(f"Operation: {operation_name} (ID: {operation_id}, slug: {op_slug})")

    # Generate analysis timestamp and versioned directory
    analysis_timestamp = datetime.now(timezone.utc)

    if no_versioning:
        target_dir = out_dir
    else:
        target_dir = get_versioned_output_dir(out_dir, op_slug, analysis_timestamp)
        target_dir.mkdir(parents=True, exist_ok=True)

    policy = resolve_retention_policy(config, output_rule_cli, arguments_rule_cli)
    try:
        metadata = parser.run(
            operation_id=operation_id,
            out_dir=target_dir,
            analysis_timestamp=analysis_timestamp,
            operation_name=operation_name,
            output_rule=policy.output_rule,
            arguments_rule=policy.arguments_rule,
        )
    except requests.exceptions.RequestException as exc:
        exc_text = str(exc)
        print(f"error: Mythic request failed while pulling operation {operation_id}: {exc_text}", file=sys.stderr)
        _print_mythic_request_hints(endpoint, verify_tls, exc_text)
        if debug:
            traceback.print_exc()
        return 1
    except Exception as exc:
        print(f"error: Mythic pull failed: {exc}", file=sys.stderr)
        if debug:
            traceback.print_exc()
        return 1

    # Create 'latest' symlink/marker unless versioning is disabled
    if not no_versioning:
        create_latest_symlink(out_dir, target_dir)

    task_count = metadata["task_count"]
    result_count = metadata["result_count"]
    status_counts = metadata["status_counts"]

    print(f"Output directory: {target_dir}")
    print(f"Tasks pulled: {task_count}")
    print(f"Results pulled: {result_count}")
    print(f"Status: success={status_counts['success']}, error={status_counts['error']}, unknown={status_counts['unknown']}")

    return 0


def run_ghostwriter(
    oplog_id: int,
    endpoint: str | None,
    api_token: str | None,
    verify_tls: bool,
    out_dir: Path,
    config: dict,
    debug: bool = False,
    no_versioning: bool = False,
    output_rule_cli: str | None = None,
    arguments_rule_cli: str | None = None,
) -> int:
    """Run Ghostwriter raw export."""
    gw_cfg = config.get("ghostwriter", {})
    endpoint = endpoint or gw_cfg.get("endpoint") or DEFAULT_GHOSTWRITER_ENDPOINT

    # Auth resolution: CLI --api-token > env GHOSTWRITER_API_KEY > legacy env > config api_token
    api_token = (
        api_token
        or os.environ.get(GW_API_TOKEN_ENV)
        or os.environ.get("GW_API_TOKEN")
        or gw_cfg.get("api_token")
    )

    if not verify_tls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not api_token:
        print(
            "error: Ghostwriter API token required. Set --api-token, GHOSTWRITER_API_KEY, or ghostwriter.api_token in config.",
            file=sys.stderr,
        )
        return 1
    parser = GhostwriterPullParser(
        endpoint=endpoint, api_token=api_token, verify_tls=verify_tls, debug=debug
    )

    print("Preflight: connectivity/auth (Ghostwriter)...")
    try:
        parser.require_oplog_access()
        oplog_name = parser.fetch_oplog_name(oplog_id)
    except GhostwriterSchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except requests.exceptions.SSLError as exc:
        print(f"error: Ghostwriter preflight failed (TLS): {exc}", file=sys.stderr)
        print(f"hint: configured endpoint is '{endpoint}'", file=sys.stderr)
        print(
            "hint: if this is a lab/self-signed endpoint, set ghostwriter.verify_tls: false in Config/janus.yml "
            "or rerun with --insecure.",
            file=sys.stderr,
        )
        return 1
    except requests.exceptions.RequestException as exc:
        print(f"error: Ghostwriter preflight failed (connectivity/auth): {exc}", file=sys.stderr)
        print(f"hint: configured endpoint is '{endpoint}'", file=sys.stderr)
        print(
            "hint: verify ghostwriter.endpoint and credentials/token in Config/janus.yml, then retry.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(f"error: Ghostwriter preflight failed: {exc}", file=sys.stderr)
        return 1
    print("Preflight: OK")

    op_slug = gw_slugify(oplog_name)
    print(f"Oplog export target: {oplog_name} (ID: {oplog_id}, slug: {op_slug})")

    analysis_timestamp = datetime.now(timezone.utc)

    if no_versioning:
        target_dir = out_dir
    else:
        target_dir = get_versioned_output_dir(out_dir, op_slug, analysis_timestamp)
        target_dir.mkdir(parents=True, exist_ok=True)

    policy = resolve_retention_policy(config, output_rule_cli, arguments_rule_cli)
    metadata = parser.run(
        oplog_id=oplog_id,
        out_dir=target_dir,
        analysis_timestamp=analysis_timestamp,
        oplog_name=oplog_name,
        output_rule=policy.output_rule,
        arguments_rule=policy.arguments_rule,
    )

    if not no_versioning:
        create_latest_symlink(out_dir, target_dir)

    print(f"Output directory: {target_dir}")
    print(f"Raw export: {target_dir / metadata['raw_export_path']}")
    print(f"Events: {target_dir / metadata['events_path']}")
    print(f"Entries exported: {metadata['entry_count']}")
    print(f"Tasks normalized: {metadata['task_count']}")
    print(f"Results normalized: {metadata['result_count']}")
    status_counts = metadata["status_counts"]
    print(f"Status: success={status_counts['success']}, error={status_counts['error']}, unknown={status_counts['unknown']}")

    return 0


def load_events(events_path: Path, validate: bool = False) -> tuple[list[dict], list[dict]]:
    """Read events.ndjson and split into task and result event lists.

    Args:
        events_path: Path to NDJSON events file.
        validate: When True, enforce required event schema.
    """
    task_events = []
    result_events = []
    unknown_event_types = set()
    with events_path.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{events_path}:{line_number}: malformed JSON: {exc.msg}"
                ) from exc

            event_type = event.get("event_type")
            if event_type == "task":
                task_events.append(event)
            elif event_type == "result":
                result_events.append(event)
            else:
                unknown_event_types.add(str(event_type))

    if unknown_event_types:
        unknown_list = ", ".join(sorted(unknown_event_types))
        print(
            f"warning: skipped events with unknown event_type(s): {unknown_list}",
            file=sys.stderr,
        )

    if validate:
        try:
            validate_events(task_events + result_events)
        except EventValidationError as exc:
            raise ValueError(f"{events_path}: invalid event schema: {exc}") from exc

    return task_events, result_events


def _derive_unique_operation_id(
    used_operation_ids: set[int],
    base_id: int,
    source_key: str,
) -> int:
    """Generate a deterministic unique operation_id for merged datasets."""
    if base_id > 0 and base_id not in used_operation_ids:
        return base_id

    candidate = 1000000000 + (zlib.crc32(source_key.encode("utf-8")) % 1000000000)
    while candidate in used_operation_ids or candidate <= 0:
        candidate += 1
    return candidate


def _remap_operation_id(events: list[dict], operation_id: int) -> None:
    """Rewrite operation_id for all events in-place."""
    for event in events:
        event["operation_id"] = operation_id


def _expand_input_pattern(pattern: str) -> list[Path]:
    """Expand an input glob pattern with light path normalization.

    On Windows, patterns ending in duplicated separators like ``out/complete//``
    can fail to match even though the equivalent normalized directory exists.
    We try the original pattern first, then a normalized variant, and finally
    accept a direct directory path when the normalized form names one.
    """
    import glob

    candidates: list[str] = []
    seen: set[str] = set()

    def add_candidate(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            candidates.append(value)

    add_candidate(pattern)

    normalized = os.path.normpath(pattern)
    add_candidate(normalized)

    stripped = normalized.rstrip("/\\")
    add_candidate(stripped)

    matches: list[Path] = []
    matched_paths: set[Path] = set()
    for candidate in candidates:
        for matched in glob.glob(candidate, recursive=True):
            path = Path(matched)
            if path in matched_paths:
                continue
            matched_paths.add(path)
            matches.append(path)

    direct_dir = Path(normalized)
    if direct_dir.is_dir() and direct_dir not in matched_paths:
        matches.append(direct_dir)

    return [path for path in matches if path.is_dir()]


def load_ghostwriter_raw_export(
    raw_export_path: Path,
    out_dir: Path | None = None,
    analysis_timestamp: datetime | None = None,
    config: dict | None = None,
    output_rule_cli: str | None = None,
    arguments_rule_cli: str | None = None,
) -> int:
    """Normalize an existing Ghostwriter raw_export.json into events.ndjson."""
    if not raw_export_path.exists():
        print(f"error: raw export not found: {raw_export_path}", file=sys.stderr)
        return 1

    try:
        with raw_export_path.open(encoding="utf-8") as f:
            raw_export = json.load(f)
    except Exception as exc:
        print(f"error: failed to read Ghostwriter raw export: {exc}", file=sys.stderr)
        return 1

    output_dir = out_dir or raw_export_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    task_events, result_events, normalized = GhostwriterPullParser.normalize_export(raw_export)
    events_path = output_dir / "events.ndjson"
    bundle_path = output_dir / "bundle.json"

    policy = resolve_retention_policy(config or {}, output_rule_cli, arguments_rule_cli)
    apply_retention_policy(task_events, result_events, policy)

    all_events = [e.to_dict() for e in task_events] + [e.to_dict() for e in result_events]
    write_ndjson(all_events, events_path)

    status_counts = {"success": 0, "error": 0, "unknown": 0}
    for event in result_events:
        status_counts[event.status] += 1

    existing_bundle = {}
    if bundle_path.exists():
        try:
            with bundle_path.open(encoding="utf-8") as f:
                existing_bundle = json.load(f)
        except Exception:
            existing_bundle = {}

    op_name = raw_export.get("oplog_name") or existing_bundle.get("operation_name") or f"oplog-{raw_export.get('oplog_id', 0)}"
    metadata = {
        "source": "ghostwriter",
        "operation_id": int(raw_export.get("oplog_id") or existing_bundle.get("operation_id") or 0),
        "operation_name": op_name,
        "operation_slug": gw_slugify(op_name),
        "ghostwriter_endpoint": existing_bundle.get("ghostwriter_endpoint", ""),
        "export_format": raw_export.get("export_format", "ghostwriter_raw"),
        "entry_count": len(raw_export.get("entries", [])),
        "task_count": len(task_events),
        "result_count": len(result_events),
        "status_counts": status_counts,
        "skipped_entry_count": normalized["skipped_entries"],
        "schema_probe": raw_export.get("schema_probe", {}),
        "raw_export_path": raw_export_path.name,
        "events_path": events_path.name,
        "output_rule": policy.output_rule,
        "arguments_rule": policy.arguments_rule,
    }
    write_bundle(metadata, bundle_path, analysis_timestamp)

    print(f"Wrote: {events_path}")
    print(f"Tasks loaded: {metadata['task_count']}")
    print(f"Results loaded: {metadata['result_count']}")
    print(f"Status: success={status_counts['success']}, error={status_counts['error']}, unknown={status_counts['unknown']}")
    return 0


def run_analyze(
    analyzer: str,
    events_path: Path,
    out_dir: Path,
    analysis_timestamp: str | None = None,
) -> int:
    """Run an analyzer against an existing events.ndjson file."""
    if not events_path.exists():
        raw_export_path = events_path.parent / "raw_export.json"
        if raw_export_path.exists():
            print(f"events.ndjson missing; normalizing existing Ghostwriter export from {raw_export_path}")
            rc = load_ghostwriter_raw_export(raw_export_path, out_dir=events_path.parent)
            if rc != 0:
                return rc
        else:
            print(f"error: events file not found: {events_path}", file=sys.stderr)
            return 1

    # Try to load bundle.json from same directory to extract operation metadata
    bundle_path = events_path.parent / "bundle.json"
    bundle_metadata = {}
    if bundle_path.exists():
        try:
            with bundle_path.open(encoding="utf-8") as f:
                bundle_metadata = json.load(f)
        except Exception:
            pass

    task_events, result_events = load_events(events_path)
    analyzer_context = _build_runtime_analyzer_context(out_dir)

    retention_info = detect_retention_from_events(
        task_events,
        result_events,
        bundle_metadata=bundle_metadata,
    )

    # Common metadata section for all analyzers
    analyzer_metadata = {
        "analyzer": analyzer,
        "metadata": {
            "events_analyzed": len(task_events) + len(result_events),
        },
    }

    # Enrich with operation metadata if available
    for key in ("operation_id", "operation_name", "operation_slug",
                "mythic_endpoint", "ghostwriter_endpoint",
                "analysis_version", "analysis_timestamp",
                "janus_version"):
        if key in bundle_metadata:
            analyzer_metadata["metadata"][key] = bundle_metadata[key]

    # Inject retention/privacy metadata
    if retention_info.get("privacy_limited"):
        analyzer_metadata["metadata"]["retention"] = {
            "arguments_retained": retention_info["arguments_retained"],
            "output_retained": retention_info["output_retained"],
            "observed_arguments_rules": retention_info["observed_arguments_rules"],
            "observed_output_rules": retention_info["observed_output_rules"],
        }
        pw = privacy_warnings_for_analyzer(analyzer, retention_info)
        if pw:
            analyzer_metadata["metadata"]["privacy_warnings"] = pw

    if analyzer == "summary-visualization":
        result = summary_visualization(task_events, result_events)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "summary_visualization.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        sd = result["status_distribution"]
        print(f"Status: {sd['success']} success, {sd['error']} error, {sd['unknown']} unknown")
        summary = result["summary"]
        print(f"Timeline: {summary['timeline_buckets']} buckets over {summary['span_hours']}h")
    elif analyzer == "command-failure-summary":
        result = command_failure_summary(task_events, result_events)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "command_failure_summary.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        for cmd_name, stats in result["commands"].items():
            rate = f"{stats['failure_rate']:.1%}"
            print(f"  {cmd_name}: {stats['execution_count']} executions, {rate} failure")
    elif analyzer == "command-retry-success":
        result = command_retry_success(task_events, result_events)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "command_retry_success.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        summary = result["summary"]
        print(f"Found {summary['total_retry_sequences']} retry sequences")
        if summary["most_retried_command"]:
            print(f"Most retried command: {summary['most_retried_command']}")
            print(f"Average retries to success: {summary['avg_retries_to_success']}")
    elif analyzer == "command-duration":
        result = command_duration(task_events, result_events, analyzer_context)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "command_duration.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        durations = result["durations"]
        if durations:
            # Find slowest and fastest commands
            slowest = max(durations.items(), key=lambda x: x[1]["mean_seconds"])
            fastest = min(durations.items(), key=lambda x: x[1]["mean_seconds"])
            print(f"Slowest command: {slowest[0]} (avg: {slowest[1]['mean_seconds']}s)")
            print(f"Fastest command: {fastest[0]} (avg: {fastest[1]['mean_seconds']}s)")
    elif analyzer == "outlier-context":
        result = outlier_context(task_events, result_events, analyzer_context)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "outlier_context_analysis.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        outliers = result.get("outliers", [])
        print(f"Enriched {len(outliers)} outlier(s) with context")
        agg = result.get("aggregations", {})
        prec = agg.get("most_common_preceding_command", {})
        if prec:
            top_prec = max(prec.items(), key=lambda x: x[1])
            print(f"Most common preceding command: {top_prec[0]} ({top_prec[1]}x)")
    elif analyzer == "callback-health":
        result = callback_health(task_events, result_events)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "callback_health.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        summary = result.get("summary", {})
        print(f"Callbacks: {summary.get('total_callbacks', 0)} total, "
              f"{summary.get('healthy_count', 0)} healthy, "
              f"{summary.get('degraded_count', 0)} degraded, "
              f"{summary.get('dead_count', 0)} dead")
    elif analyzer == "av-tracker":
        result = av_tracker(task_events, result_events)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "av_tracker.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        summary = result.get("summary", {})
        print(f"Scanned {summary.get('ps_tasks_scanned', 0)} ps result(s)")
        print(f"Detections: {summary.get('detection_count', 0)} across {summary.get('callbacks_with_detections', 0)} callback(s)")
        vendors = summary.get("vendors_detected", [])
        if vendors:
            print("Vendors detected: " + ", ".join(vendors))
    elif analyzer == "dwell-time":
        result = dwell_time(task_events, result_events)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "dwell_time.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        stats = result["global_statistics"]
        print(f"Dwell measurements: {stats['dwell_count']}")
        print(f"Mean dwell time: {stats['mean_seconds']}s")
        print(f"P95 dwell time: {stats['p95_seconds']}s")
        print(f"Max dwell time: {stats['max_seconds']}s")
        print(f"Outliers detected: {stats['outlier_count']}")
    elif analyzer == "parameter-entropy":
        result = parameter_entropy(task_events, result_events, analyzer_context)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "parameter_entropy.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        summary = result["summary"]
        print(f"Total findings: {summary['total_findings']}")
        print(f"Tasks with findings: {summary['tasks_with_findings']}")
        for ftype, count in summary.get("by_type", {}).items():
            print(f"  {ftype}: {count}")
        if summary.get("repeated_high_entropy_tokens"):
            print(f"Repeated high-entropy tokens: {summary['repeated_high_entropy_tokens']}")
    elif analyzer == "argument-position-profile":
        result = argument_position_profile(task_events, result_events, analyzer_context)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "argument_position_profile.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        summary = result["summary"]
        print(f"Commands profiled: {summary['commands_profiled']}")
        print(f"Max argument depth: {summary['max_depth_observed']}")
        print(f"Positions profiled: {summary['positions_profiled']}")
        print(f"Findings: {summary['total_findings']}")
        for ftype, count in summary.get("findings_by_type", {}).items():
            print(f"  {ftype}: {count}")
    elif analyzer == "tool-dump":
        result = tool_dump(task_events, result_events, analyzer_context)
        result = _merge_common_metadata(result, analyzer_metadata)
        out_path = out_dir / "tool_dump.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")
        summary = result["summary"]
        print(f"Groups defined: {summary['groups_defined']}")
        print(f"Groups with matches: {summary['groups_with_matches']}")
        print(f"Total matches: {summary['total_matches']}")
        for group in result.get("groups", []):
            if group.get("match_count", 0) == 0:
                continue
            dump_path = group.get("dump_path") or "<not written>"
            print(f"  {group['name']}: {group['match_count']} match(es) -> {dump_path}")
    else:
        print(f"error: unknown analyzer: {analyzer}", file=sys.stderr)
        return 1

    return 0


def run_analyze_all(
    events_path: Path,
    out_dir: Path,
    analysis_timestamp: str | None = None,
) -> int:
    """Run all analyzers against an existing events.ndjson file."""
    for analyzer_name in ALL_ANALYZERS:
        print(f"\nRunning analyzer: {analyzer_name}")
        rc = run_analyze(
            analyzer=analyzer_name,
            events_path=events_path,
            out_dir=out_dir,
            analysis_timestamp=analysis_timestamp,
        )
        if rc != 0:
            return rc
    return 0


def run_partial_load(
    partial_json_path: Path,
    operation_id: int | None,
    operation_name: str | None,
    out_dir: Path,
    no_versioning: bool = False,
    run_analyzers: bool = True,
    config: dict | None = None,
    output_rule_cli: str | None = None,
    arguments_rule_cli: str | None = None,
) -> int:
    """Load partial Mythic JSON (incomplete GraphQL pulls), normalize, run analyzers, and generate HTML report."""
    if not partial_json_path.exists():
        print(f"error: JSON file not found: {partial_json_path}", file=sys.stderr)
        return 1

    print(f"Loading partial Mythic data from: {partial_json_path}")

    # Load and normalize partial data
    task_events, result_events, metadata = load_partial_mythic_json(
        partial_json_path,
        operation_id=operation_id,
        operation_name=operation_name,
    )

    policy = resolve_retention_policy(config or {}, output_rule_cli, arguments_rule_cli)
    apply_retention_policy(task_events, result_events, policy)
    metadata = dict(metadata)
    metadata["output_rule"] = policy.output_rule
    metadata["arguments_rule"] = policy.arguments_rule

    operation_id = metadata["operation_id"]
    operation_name = metadata["operation_name"]
    op_slug = metadata["operation_slug"]

    print(f"Operation: {operation_name} (ID: {operation_id}, slug: {op_slug})")
    print(f"Tasks loaded: {metadata['task_count']}")
    print(f"Results loaded: {metadata['result_count']}")
    status_counts = metadata["status_counts"]
    print(f"Status: success={status_counts['success']}, error={status_counts['error']}, unknown={status_counts['unknown']}")

    # Generate analysis timestamp and versioned directory
    analysis_timestamp = datetime.now(timezone.utc)

    if no_versioning:
        target_dir = out_dir
    else:
        target_dir = get_versioned_output_dir(out_dir, op_slug, analysis_timestamp)
        target_dir.mkdir(parents=True, exist_ok=True)

    # Write events.ndjson
    events_path = target_dir / "events.ndjson"
    all_events = [e.to_dict() for e in task_events] + [e.to_dict() for e in result_events]
    write_ndjson(all_events, events_path)
    print(f"Wrote: {events_path}")

    # Write bundle.json
    bundle_path = target_dir / "bundle.json"
    write_bundle(metadata, bundle_path, analysis_timestamp)
    print(f"Wrote: {bundle_path}")

    # Create 'latest' symlink unless versioning is disabled
    if not no_versioning:
        create_latest_symlink(out_dir, target_dir)

    print(f"\nOutput directory: {target_dir}")

    # Run analyzers if requested
    if run_analyzers:
        print("\nRunning analyzers...")

        # Convert to dict format for analyzers
        task_dicts = [e.to_dict() for e in task_events]
        result_dicts = [e.to_dict() for e in result_events]
        analyzer_context = _build_runtime_analyzer_context(target_dir)

        # Load bundle metadata for analyzer enrichment
        with bundle_path.open(encoding="utf-8") as f:
            bundle_metadata = json.load(f)

        analyzers_to_run = [
            (name, ANALYZER_FUNCTIONS[name], ANALYZER_OUTPUTS[name])
            for name in PARTIAL_LOAD_ANALYZERS
        ]

        for analyzer_name, analyzer_func, output_filename in analyzers_to_run:
            print(f"  Running {analyzer_name}...")
            try:
                result = _run_analyzer(analyzer_name, analyzer_func, task_dicts, result_dicts, analyzer_context)

                # Add common metadata
                result = _merge_common_metadata(result, {
                    "analyzer": analyzer_name,
                    "metadata": {
                        "events_analyzed": len(task_dicts) + len(result_dicts),
                    },
                })
                

                # Enrich with operation metadata
                for key in ("operation_id", "operation_name", "operation_slug",
                            "analysis_version", "analysis_timestamp", "janus_version"):
                    if key in bundle_metadata:
                        result["metadata"][key] = bundle_metadata[key]

                out_path = target_dir / output_filename
                with out_path.open("w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"    - {out_path}")
            except Exception as e:
                print(f"    ! Failed: {e}", file=sys.stderr)

        # Generate HTML report
        print("\nGenerating HTML report...")
        html_path = target_dir / "report.html"
        try:
            run_html(target_dir, html_path, include_version_links=True)
        except Exception as e:
            print(f"error: failed to generate HTML report: {e}", file=sys.stderr)
            return 1

        report_path = target_dir / "report.html"
        print(f"\n- Complete! Report: {report_path}")
        print(f"Open report: {_format_file_uri(report_path)}")
    else:
        print("\n- Ingest complete (analyzers skipped; no report.html yet).")
        print(f"  Events: {target_dir / 'events.ndjson'}")
        print(f"  Bundle: {target_dir / 'bundle.json'}")
        print("  Next: janus-cli analyze && janus-cli report")
    return 0


def run_cobaltstrike_rest_load(
    endpoint: str | None,
    username: str | None,
    password: str | None,
    api_token: str | None,
    duration_ms: int | None,
    operation_id: int | None,
    operation_name: str | None,
    out_dir: Path,
    verify_tls: bool,
    debug: bool = False,
    no_versioning: bool = False,
    run_analyzers: bool = True,
    config: dict | None = None,
    output_rule_cli: str | None = None,
    arguments_rule_cli: str | None = None,
) -> int:
    """Pull Cobalt Strike tasks via REST API, normalize, run analyzers, and generate HTML."""
    cfg = config or {}
    cs_cfg = cfg.get("cobaltstrike", {})
    endpoint = (
        endpoint
        or cs_cfg.get("rest_endpoint")
        or DEFAULT_COBALT_STRIKE_REST_ENDPOINT
    )
    username = username or cs_cfg.get("username")
    password = password or cs_cfg.get("password")
    api_token = (
        api_token
        or cs_cfg.get("api_token")
        or cs_cfg.get("rest_api_token")
    )
    op_id = operation_id if operation_id is not None else int(cs_cfg.get("operation_id") or 0)
    op_name = operation_name or cs_cfg.get("operation_name") or "cobaltstrike-rest"
    token_ttl = (
        int(duration_ms)
        if duration_ms is not None
        else int(cs_cfg.get("duration_ms") or 86400000)
    )

    if not api_token and (not username or not password):
        print(
            "error: Cobalt Strike REST auth required. Set --api-token, or provide "
            "--username/--password or cobaltstrike.username/password in config.",
            file=sys.stderr,
        )
        return 1

    if not verify_tls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = CobaltStrikeRestPullParser(
        endpoint=endpoint,
        username=username,
        password=password,
        api_token=api_token,
        duration_ms=token_ttl,
        verify_tls=verify_tls,
        debug=debug,
    )

    print("Preflight: connectivity/auth (Cobalt Strike REST)...")
    try:
        parser.preflight()
    except requests.exceptions.RequestException as exc:
        print(f"error: Cobalt Strike REST preflight failed: {exc}", file=sys.stderr)
        print(f"hint: configured endpoint is '{endpoint}'", file=sys.stderr)
        print(
            "hint: verify teamserver REST base URL (scheme, host, port) in config or "
            "--endpoint; enable REST API on the teamserver if needed.",
            file=sys.stderr,
        )
        if debug:
            traceback.print_exc()
        return 1
    except Exception as exc:
        print(f"error: Cobalt Strike REST preflight failed: {exc}", file=sys.stderr)
        if debug:
            traceback.print_exc()
        return 1
    print("Preflight: OK")

    analysis_timestamp = datetime.now(timezone.utc)
    op_slug = cs_slugify(op_name)

    if no_versioning:
        target_dir = out_dir
        target_dir.mkdir(parents=True, exist_ok=True)
    else:
        target_dir = get_versioned_output_dir(out_dir, op_slug, analysis_timestamp)
        target_dir.mkdir(parents=True, exist_ok=True)

    policy = resolve_retention_policy(cfg, output_rule_cli, arguments_rule_cli)

    print(f"Operation: {op_name} (ID: {op_id}, slug: {op_slug})")
    print(f"Cobalt Strike REST endpoint: {endpoint}")

    try:
        metadata = run_cobaltstrike_rest_ingest(
            parser,
            operation_id=op_id,
            operation_name=op_name,
            out_dir=target_dir,
            analysis_timestamp=analysis_timestamp,
            output_rule=policy.output_rule,
            arguments_rule=policy.arguments_rule,
        )
    except requests.exceptions.RequestException as exc:
        print(f"error: Cobalt Strike REST request failed: {exc}", file=sys.stderr)
        if debug:
            traceback.print_exc()
        return 1
    except Exception as exc:
        print(f"error: Cobalt Strike REST ingest failed: {exc}", file=sys.stderr)
        if debug:
            traceback.print_exc()
        return 1

    if not no_versioning:
        create_latest_symlink(out_dir, target_dir)

    task_count = metadata["task_count"]
    result_count = metadata["result_count"]
    status_counts = metadata["status_counts"]
    skipped = metadata.get("skipped_task_rows", 0)
    fetch_err = metadata.get("task_fetch_errors", 0)

    print(f"Output directory: {target_dir}")
    print(f"Tasks loaded:   {task_count}")
    print(f"Results loaded: {result_count}")
    if skipped:
        print(f"Skipped task rows: {skipped}")
    if fetch_err:
        print(f"Task detail fetch errors: {fetch_err}", file=sys.stderr)
    print(
        f"Status: success={status_counts['success']}, error={status_counts['error']}, "
        f"unknown={status_counts['unknown']}"
    )

    if run_analyzers:
        print("\nRunning analyzers...")
        events_path = target_dir / "events.ndjson"
        task_events, result_events = load_events(events_path)
        analyzer_context = _build_runtime_analyzer_context(target_dir)
        bundle_path = target_dir / "bundle.json"
        with bundle_path.open(encoding="utf-8") as f:
            bundle_metadata = json.load(f)
        analyzers_to_run = [
            (name, ANALYZER_FUNCTIONS[name], ANALYZER_OUTPUTS[name])
            for name in PARTIAL_LOAD_ANALYZERS
        ]
        for analyzer_name, analyzer_func, output_filename in analyzers_to_run:
            print(f"  Running {analyzer_name}...")
            try:
                result = _run_analyzer(
                    analyzer_name, analyzer_func, task_events, result_events, analyzer_context
                )
                result = _merge_common_metadata(result, {
                    "analyzer": analyzer_name,
                    "metadata": {
                        "events_analyzed": len(task_events) + len(result_events),
                    },
                })
                for key in ("operation_id", "operation_name", "operation_slug",
                            "analysis_version", "analysis_timestamp", "janus_version"):
                    if key in bundle_metadata:
                        result["metadata"][key] = bundle_metadata[key]
                out_path = target_dir / output_filename
                with out_path.open("w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"    - {out_path}")
            except Exception as e:
                print(f"    ! Failed: {e}", file=sys.stderr)

        print("\nGenerating HTML report...")
        html_path = target_dir / "report.html"
        try:
            run_html(target_dir, html_path, include_version_links=True)
        except Exception as e:
            print(f"error: failed to generate HTML report: {e}", file=sys.stderr)
            return 1

        report_path = target_dir / "report.html"
        print(f"\n- Complete! Report: {report_path}")
        print(f"Open report: {_format_file_uri(report_path)}")
    else:
        print("\n- Ingest complete (analyzers skipped; no report.html yet).")
        print(f"  Events: {target_dir / 'events.ndjson'}")
        print(f"  Bundle: {target_dir / 'bundle.json'}")
        print("  Next: janus-cli analyze && janus-cli report")
    return 0


def run_merge(
    input_paths: list[Path],
    output_dir: Path,
    operation_name: str = "Multi-Operation Analysis",
) -> int:
    """Merge events from multiple operation directories into a unified dataset."""
    import glob

    # Collect all events.ndjson files from input paths
    events_files = []
    for path in input_paths:
        if path.is_dir():
            events_file = path / "events.ndjson"
            if events_file.exists():
                events_files.append(events_file)
        elif path.is_file() and path.name == "events.ndjson":
            events_files.append(path)

    if not events_files:
        print("error: no events.ndjson files found in input paths", file=sys.stderr)
        return 1

    print(f"Found {len(events_files)} operation(s) to merge")

    # Load all events and bundle metadata
    all_task_events = []
    all_result_events = []
    operation_metadata = []
    operation_ids_seen = set()
    merged_arguments_rules = set()
    merged_output_rules = set()

    for events_path in events_files:
        print(f"  Loading: {events_path}")
        task_events, result_events = load_events(events_path, validate=True)

        # Load corresponding bundle.json for metadata
        bundle_path = events_path.parent / "bundle.json"
        bundle_metadata = {}
        if bundle_path.exists():
            try:
                with bundle_path.open(encoding="utf-8") as f:
                    bundle_metadata = json.load(f)
            except Exception as e:
                print(f"    warning: could not load bundle metadata: {e}", file=sys.stderr)

        input_retention_info = detect_retention_from_events(
            task_events,
            result_events,
            bundle_metadata=bundle_metadata,
        )
        merged_arguments_rules.update(input_retention_info["observed_arguments_rules"])
        merged_output_rules.update(input_retention_info["observed_output_rules"])

        # Extract operation metadata
        op_id = int(bundle_metadata.get("operation_id", 0) or 0)
        op_name = bundle_metadata.get("operation_name", "unknown")
        op_slug = bundle_metadata.get("operation_slug", f"op-{op_id}")

        original_op_id = op_id
        source_key = str(events_path.parent.resolve())
        remapped_operation_id = False
        if op_id <= 0 or op_id in operation_ids_seen:
            op_id = _derive_unique_operation_id(operation_ids_seen, op_id, source_key)
            remapped_operation_id = True
            if original_op_id <= 0:
                print(
                    f"    warning: missing/invalid operation_id; remapped to {op_id}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"    warning: duplicate operation_id {original_op_id}; remapped to {op_id}",
                    file=sys.stderr,
                )
            _remap_operation_id(task_events, op_id)
            _remap_operation_id(result_events, op_id)

        operation_ids_seen.add(op_id)

        # Count status for this operation
        status_counts = {"success": 0, "error": 0, "unknown": 0}
        for result in result_events:
            status = result.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        operation_metadata.append({
            "id": op_id,
            "original_id": original_op_id,
            "remapped_operation_id": remapped_operation_id,
            "name": op_name,
            "slug": op_slug,
            "task_count": len(task_events),
            "status_counts": status_counts,
            "arguments_rule": input_retention_info["arguments_retained"],
            "output_rule": input_retention_info["output_retained"],
        })

        all_task_events.extend(task_events)
        all_result_events.extend(result_events)

        print(f"    - {len(task_events)} tasks, {len(result_events)} results")

    # Sort merged events by timestamp
    all_task_events.sort(key=lambda e: e.get("timestamp", ""))
    all_result_events.sort(key=lambda e: e.get("timestamp", ""))

    # Calculate aggregated status counts
    total_status_counts = {"success": 0, "error": 0, "unknown": 0}
    for op_meta in operation_metadata:
        for status, count in op_meta["status_counts"].items():
            total_status_counts[status] += count

    retention_info = detect_retention_from_events(
        all_task_events,
        all_result_events,
        bundle_metadata={
            "arguments_rule": "mixed" if len(merged_arguments_rules) > 1 else None,
            "output_rule": "mixed" if len(merged_output_rules) > 1 else None,
            "observed_arguments_rules": sorted(merged_arguments_rules),
            "observed_output_rules": sorted(merged_output_rules),
        },
    )

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write merged events.ndjson
    events_path = output_dir / "events.ndjson"
    all_events = all_task_events + all_result_events
    write_ndjson(all_events, events_path)
    print(f"\nWrote: {events_path}")

    # Create merged bundle.json
    analysis_timestamp = datetime.now(timezone.utc)
    merged_metadata = {
        "source": "multi-operation",
        "operation_name": operation_name,
        "operation_slug": slugify(operation_name),
        "operation_count": len(operation_metadata),
        "operations": operation_metadata,
        "task_count": len(all_task_events),
        "result_count": len(all_result_events),
        "status_counts": total_status_counts,
        "output_rule": retention_info["output_retained"],
        "arguments_rule": retention_info["arguments_retained"],
        "observed_output_rules": retention_info["observed_output_rules"],
        "observed_arguments_rules": retention_info["observed_arguments_rules"],
    }

    bundle_path = output_dir / "bundle.json"
    write_bundle(merged_metadata, bundle_path, analysis_timestamp)
    print(f"Wrote: {bundle_path}")

    print(f"\n- Merged {len(operation_metadata)} operations ({len(all_task_events)} tasks) -> {output_dir}/")

    return 0


def run_multi_analyze(
    input_paths: list[Path],
    output_dir: Path,
    operation_name: str = "Multi-Operation Analysis",
) -> int:
    """Convenience command: merge events, run the multi-op analyzer set, and generate HTML report."""
    # Step 1: Merge events
    print("=" * 60)
    print("Step 1: Merging operations")
    print("=" * 60)
    result = run_merge(input_paths, output_dir, operation_name)
    if result != 0:
        return result

    # Step 2: Run registry-defined analyzers for multi-operation datasets
    print("\n" + "=" * 60)
    print("Step 2: Running analyzers")
    print("=" * 60)

    events_path = output_dir / "events.ndjson"
    if not events_path.exists():
        print("error: merged events.ndjson not found", file=sys.stderr)
        return 1

    task_events, result_events = load_events(events_path)
    analyzer_context = _build_runtime_analyzer_context(output_dir)

    # Load bundle metadata for analyzer enrichment
    bundle_path = output_dir / "bundle.json"
    bundle_metadata = {}
    if bundle_path.exists():
        try:
            with bundle_path.open(encoding="utf-8") as f:
                bundle_metadata = json.load(f)
        except Exception as e:
            print(f"warning: could not load bundle metadata: {e}", file=sys.stderr)

    # Multi-operation analyzer set is defined in Config/analyzers.yml.
    analyzers_to_run = [
        (name, ANALYZER_FUNCTIONS[name], ANALYZER_OUTPUTS[name])
        for name in MULTI_ANALYZE_ANALYZERS
    ]

    for analyzer_name, analyzer_func, output_filename in analyzers_to_run:
        print(f"\n  Running {analyzer_name}...")
        try:
            result_data = _run_analyzer(analyzer_name, analyzer_func, task_events, result_events, analyzer_context)

            # Add common metadata
            result_data = _merge_common_metadata(result_data, {
                "analyzer": analyzer_name,
                "metadata": {
                    "events_analyzed": len(task_events) + len(result_events),
                },
            })

            # Enrich with operation metadata
            for key in ("operation_name", "operation_slug", "operation_count",
                        "analysis_timestamp", "janus_version", "source"):
                if key in bundle_metadata:
                    result_data["metadata"][key] = bundle_metadata[key]

            out_path = output_dir / output_filename
            with out_path.open("w", encoding="utf-8") as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            print(f"    - {out_path}")
        except Exception as e:
            print(f"    ! Failed: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()

    # Step 3: Generate HTML report
    print("\n" + "=" * 60)
    print("Step 3: Generating HTML report")
    print("=" * 60)

    html_path = output_dir / "report.html"
    result = run_html(output_dir, html_path, include_version_links=False)
    if result != 0:
        return result

    print(f"\n{'=' * 60}")
    print("- Multi-operation analysis complete!")
    print(f"{'=' * 60}")
    print(f"Report: {html_path}")
    print(f"Open report: {_format_file_uri(html_path)}")

    return 0


def run_html(
    analysis_dir: Path,
    output_path: Path,
    include_version_links: bool = True,
) -> int:
    """Generate HTML report from analysis JSON files."""
    analysis_files = {
        analyzer_name: analysis_dir / output_name
        for analyzer_name, output_name in ANALYZER_OUTPUTS.items()
    }

    # Check if at least one analysis file exists
    existing_files = [path for path in analysis_files.values() if path.exists()]
    if not existing_files:
        print(f"error: no analysis files found in {analysis_dir}", file=sys.stderr)
        print("Run 'janus analyze' first to generate analysis data.", file=sys.stderr)
        return 1

    # Load bundle.json for version metadata
    bundle_path = analysis_dir / "bundle.json"
    version_metadata = None
    previous_versions = []

    if bundle_path.exists():
        try:
            with bundle_path.open(encoding="utf-8") as f:
                version_metadata = json.load(f)

            # Find previous versions if versioning is enabled
            if include_version_links and "analysis_version" in version_metadata:
                op_slug = version_metadata.get("operation_slug")
                if not op_slug and "operation_id" in version_metadata:
                    op_slug = f"op-{version_metadata['operation_id']}"
                if op_slug:
                    current_version = version_metadata["analysis_version"]
                    base_dir = analysis_dir.parent
                    previous_versions = find_previous_versions(base_dir, op_slug, current_version)
        except Exception as e:
            print(f"warning: could not load bundle metadata: {e}", file=sys.stderr)

    try:
        generate_html(
            analysis_files,
            output_path,
            version_metadata=version_metadata,
            previous_versions=previous_versions,
        )
        print(f"HTML report generated: {output_path}")
        print(f"Open report: {_format_file_uri(output_path)}")

        # Report which sections were included
        for name, path in analysis_files.items():
            if path.exists():
                print(f"  - {name}")
            else:
                print(f"  ! {name} (missing)")

        if previous_versions:
            print(f"  - {len(previous_versions)} previous version(s) linked")

        return 0
    except Exception as e:
        print(f"error: failed to generate HTML report: {e}", file=sys.stderr)
        return 1


def main() -> None:
    """CLI entry point for both ``python janus.py`` and the installed ``janus`` console script."""
    sys.exit(_cli())


def _cli() -> int:
    parser = argparse.ArgumentParser(prog="janus", description="Janus operational log intelligence")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a parser for a given source")
    run_parser.add_argument(
        "--source",
        choices=["mythic", "ghostwriter", "cobaltstrike"],
        default=None,
        help="Data source to pull from (default: config source or inferred)",
    )
    run_parser.add_argument(
        "--operation-id",
        type=int,
        default=None,
        help="Operation/oplog ID to pull (required for mythic; for ghostwriter use --oplog-id; synthetic operation_id for cobaltstrike)",
    )
    run_parser.add_argument(
        "--oplog-id",
        type=int,
        default=None,
        help="Ghostwriter oplog ID to pull (alias for --operation-id when --source ghostwriter)",
    )
    run_parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help=(
            "Source endpoint/base URL "
            f"(Mythic default: {DEFAULT_MYTHIC_ENDPOINT}; "
            f"Ghostwriter default: {DEFAULT_GHOSTWRITER_ENDPOINT}/v1/graphql; "
            f"Cobalt Strike default: {DEFAULT_COBALT_STRIKE_REST_ENDPOINT})"
        ),
    )
    run_parser.add_argument(
        "--api-token",
        type=str,
        default=None,
        help=(
            "API token / bearer token (--api-token or source api_token in config; "
            f"Ghostwriter also accepts {GW_API_TOKEN_ENV} in the environment)"
        ),
    )
    run_parser.add_argument(
        "--username",
        type=str,
        default=None,
        help="Cobalt Strike username",
    )
    run_parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Cobalt Strike password",
    )
    run_parser.add_argument(
        "--duration-ms",
        type=int,
        default=None,
        help="Cobalt Strike login token lifetime in milliseconds (default: config or 86400000)",
    )
    run_parser.add_argument(
        "--operation-name",
        type=str,
        default=None,
        help="Cobalt Strike operation/display name override",
    )
    run_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification and relax SSL negotiation (for self-signed certs or legacy TLS configs)",
    )
    run_parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to YAML config file (default: Config/janus.yml)",
    )
    run_parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out/complete"),
        help="Output directory (default: out/complete)",
    )
    run_parser.add_argument(
        "--debug",
        action="store_true",
        help="Print request/response for troubleshooting",
    )
    run_parser.add_argument(
        "--no-versioning",
        action="store_true",
        help="Disable versioning (use flat output directory structure)",
    )
    run_parser.add_argument(
        "--output-rule",
        choices=["all", "errors_only", "none"],
        default=None,
        help=(
            "Override output_rule from config: keep all result output_text (default), "
            "errors_only (drop output_text when status is success), or "
            "none (drop all output_text)"
        ),
    )
    run_parser.add_argument(
        "--arguments-rule",
        choices=["all", "drop", "hash", "features_only"],
        default=None,
        help=(
            "Override arguments_rule from config: keep all arguments_raw (default), "
            "drop (clear arguments), hash (SHA-256 digest only), or "
            "features_only (derived metadata without raw content)"
        ),
    )

    # -- analyze subcommand ---------------------------------------------------
    analyze_parser = subparsers.add_parser("analyze", help="Run an analyzer on existing events")
    analyze_mode_group = analyze_parser.add_mutually_exclusive_group(required=True)
    analyze_mode_group.add_argument(
        "--analyzer",
        choices=ALL_ANALYZERS,
        help="Run a single analyzer",
    )
    analyze_mode_group.add_argument(
        "--all",
        dest="analyze_all",
        action="store_true",
        help="Run all analyzers in registry order",
    )
    analyze_parser.add_argument(
        "--events",
        type=Path,
        required=True,
        help="Path to events.ndjson file",
    )
    analyze_parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out/complete"),
        help="Output directory (default: out/complete)",
    )
    analyze_parser.add_argument(
        "--analysis-timestamp",
        type=str,
        default=None,
        help="Analysis timestamp (for matching parent run timestamp)",
    )

    # -- html subcommand ------------------------------------------------------
    html_parser = subparsers.add_parser("html", help="Generate HTML report from analysis results")
    html_parser.add_argument(
        "--analysis-dir",
        type=Path,
        default=Path("out/complete"),
        help="Directory containing analysis JSON files (default: out/complete)",
    )
    html_parser.add_argument(
        "--output",
        type=Path,
        default=Path("out/complete/report.html"),
        help="Output HTML file path (default: out/complete/report.html)",
    )
    html_parser.add_argument(
        "--include-version-links",
        action="store_true",
        default=True,
        help="Include links to previous analysis versions (default: true)",
    )

    # -- partial-load subcommand -----------------------------------------------
    partial_parser = subparsers.add_parser(
        "partial-load",
        help="Load partial Mythic JSON (incomplete GraphQL pulls with embedded responses) and run analysis pipeline",
    )
    partial_parser.add_argument(
        "json_path",
        type=Path,
        help="Path to partial Mythic JSON file (e.g., idot2508-rng00-teamserver1.json)",
    )
    partial_parser.add_argument(
        "--operation-id",
        type=int,
        default=None,
        help="Override operation ID (otherwise auto-detected from filename)",
    )
    partial_parser.add_argument(
        "--operation-name",
        type=str,
        default=None,
        help="Override operation name (otherwise derived from filename)",
    )
    partial_parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out/partial"),
        help="Output directory (default: out/partial)",
    )
    partial_parser.add_argument(
        "--no-versioning",
        action="store_true",
        help="Disable versioning (use flat output directory structure)",
    )
    partial_parser.add_argument(
        "--no-analyzers",
        action="store_true",
        help="Skip running analyzers (only convert to normalized format)",
    )
    partial_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="YAML config path (for output_rule; mounted as /config/janus.yml in Docker)",
    )
    partial_parser.add_argument(
        "--output-rule",
        choices=["all", "errors_only", "none"],
        default=None,
        help="Override output_rule from config (see run --output-rule)",
    )
    partial_parser.add_argument(
        "--arguments-rule",
        choices=["all", "drop", "hash", "features_only"],
        default=None,
        help="Override arguments_rule from config (see run --arguments-rule)",
    )

    # -- cs-rest subcommand ----------------------------------------------------
    cs_rest_parser = subparsers.add_parser(
        "cs-rest",
        help=argparse.SUPPRESS,
    )
    cs_rest_parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help=(
            "Cobalt Strike REST base URL (no path suffix; e.g. https://teamserver:50050). "
            f"Uses config cobaltstrike.rest_endpoint when omitted "
            f"(default: {DEFAULT_COBALT_STRIKE_REST_ENDPOINT})"
        ),
    )
    cs_rest_parser.add_argument(
        "--username",
        type=str,
        default=None,
        help="REST login username (or cobaltstrike.username in config)",
    )
    cs_rest_parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="REST login password (or cobaltstrike.password in config)",
    )
    cs_rest_parser.add_argument(
        "--api-token",
        type=str,
        default=None,
        help="Bearer token for REST (skip login); or set cobaltstrike.api_token in config",
    )
    cs_rest_parser.add_argument(
        "--duration-ms",
        type=int,
        default=None,
        help="Login token duration in milliseconds (default: config or 86400000)",
    )
    cs_rest_parser.add_argument(
        "--operation-id",
        type=int,
        default=None,
        help="Synthetic operation ID for merged Janus bundles (default: 0)",
    )
    cs_rest_parser.add_argument(
        "--operation-name",
        type=str,
        default=None,
        help="Operation/display name for output paths (default: cobaltstrike-rest)",
    )
    cs_rest_parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out/partial"),
        help="Output directory (default: out/partial)",
    )
    cs_rest_parser.add_argument(
        "--no-versioning",
        action="store_true",
        help="Disable versioning (use flat output directory structure)",
    )
    cs_rest_parser.add_argument(
        "--no-analyzers",
        action="store_true",
        help="Skip running analyzers (only convert to normalized format)",
    )
    cs_rest_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="YAML config path (output_rule, cobaltstrike.*)",
    )
    cs_rest_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (self-signed REST endpoint)",
    )
    cs_rest_parser.add_argument(
        "--debug",
        action="store_true",
        help="Print REST request hints for troubleshooting",
    )
    cs_rest_parser.add_argument(
        "--output-rule",
        choices=["all", "errors_only", "none"],
        default=None,
        help="Override output_rule from config (see run --output-rule)",
    )
    cs_rest_parser.add_argument(
        "--arguments-rule",
        choices=["all", "drop", "hash", "features_only"],
        default=None,
        help="Override arguments_rule from config (see run --arguments-rule)",
    )

    ghostwriter_load_parser = subparsers.add_parser(
        "ghostwriter-load",
        help="Normalize an existing Ghostwriter raw_export.json into events.ndjson",
    )
    ghostwriter_load_parser.add_argument(
        "raw_export",
        type=Path,
        help="Path to Ghostwriter raw_export.json",
    )
    ghostwriter_load_parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for normalized events (default: raw export directory)",
    )
    ghostwriter_load_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="YAML config path (for output_rule)",
    )
    ghostwriter_load_parser.add_argument(
        "--output-rule",
        choices=["all", "errors_only", "none"],
        default=None,
        help="Override output_rule from config (see run --output-rule)",
    )
    ghostwriter_load_parser.add_argument(
        "--arguments-rule",
        choices=["all", "drop", "hash", "features_only"],
        default=None,
        help="Override arguments_rule from config (see run --arguments-rule)",
    )

    # -- merge subcommand ---------------------------------------------------------
    merge_parser = subparsers.add_parser(
        "merge",
        help="Merge events from multiple operations into a unified dataset",
    )
    merge_input_group = merge_parser.add_mutually_exclusive_group(required=True)
    merge_input_group.add_argument(
        "--inputs",
        type=Path,
        nargs="+",
        help="Paths to operation directories (each containing events.ndjson)",
    )
    merge_input_group.add_argument(
        "--pattern",
        type=str,
        help="Glob pattern to find operation directories (e.g., 'out/partial/*/')",
    )
    merge_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for merged data",
    )
    merge_parser.add_argument(
        "--operation-name",
        type=str,
        default="Multi-Operation Analysis",
        help="Name for merged operation (default: 'Multi-Operation Analysis')",
    )

    # -- multi-analyze subcommand ---------------------------------------------
    multi_analyze_parser = subparsers.add_parser(
        "multi-analyze",
        help="Merge operations, run the multi-op analyzer set, and generate HTML report",
    )
    multi_analyze_input_group = multi_analyze_parser.add_mutually_exclusive_group(required=True)
    multi_analyze_input_group.add_argument(
        "--inputs",
        type=Path,
        nargs="+",
        help="Paths to operation directories (each containing events.ndjson)",
    )
    multi_analyze_input_group.add_argument(
        "--pattern",
        type=str,
        help="Glob pattern to find operation directories (e.g., 'out/partial/*/')",
    )
    multi_analyze_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for merged data and report",
    )
    multi_analyze_parser.add_argument(
        "--operation-name",
        type=str,
        default="Multi-Operation Analysis",
        help="Name for merged operation (default: 'Multi-Operation Analysis')",
    )

    args = parser.parse_args()

    if args.command == "run":
        config = load_config(args.config)
        source = _resolve_cli_source(config, args.source)
        if source == "ghostwriter" and (getattr(args, "username", None) or getattr(args, "password", None)):
            print(
                "error: Ghostwriter uses API token auth only. Use --api-token or ghostwriter.api_token.",
                file=sys.stderr,
            )
            return 1
        if source == "mythic":
            operation_id = args.operation_id or config.get("mythic", {}).get("operation_id")
            if not operation_id:
                print("error: --operation-id is required for --source mythic or mythic.operation_id must be set in config", file=sys.stderr)
                return 1
            return run_mythic(
                operation_id=operation_id,
                endpoint=args.endpoint,
                api_token=args.api_token,
                verify_tls=not args.insecure,
                out_dir=args.out_dir,
                config=config,
                debug=args.debug,
                no_versioning=args.no_versioning,
                output_rule_cli=args.output_rule,
                arguments_rule_cli=args.arguments_rule,
            )
        elif source == "ghostwriter":
            oplog_id = args.oplog_id or args.operation_id
            if not oplog_id:
                # Fall back to config
                oplog_id = config.get("ghostwriter", {}).get("oplog_id")
            if not oplog_id:
                print("error: --oplog-id (or --operation-id) is required for --source ghostwriter", file=sys.stderr)
                return 1
            return run_ghostwriter(
                oplog_id=oplog_id,
                endpoint=args.endpoint,
                api_token=args.api_token,
                verify_tls=not args.insecure,
                out_dir=args.out_dir,
                config=config,
                debug=args.debug,
                no_versioning=args.no_versioning,
                output_rule_cli=args.output_rule,
                arguments_rule_cli=args.arguments_rule,
            )
        elif source == "cobaltstrike":
            return run_cobaltstrike_rest_load(
                endpoint=args.endpoint,
                username=getattr(args, "username", None),
                password=getattr(args, "password", None),
                api_token=getattr(args, "api_token", None),
                duration_ms=getattr(args, "duration_ms", None),
                operation_id=args.operation_id,
                operation_name=getattr(args, "operation_name", None),
                out_dir=args.out_dir,
                verify_tls=not args.insecure,
                debug=args.debug,
                no_versioning=args.no_versioning,
                run_analyzers=False,
                config=config,
                output_rule_cli=args.output_rule,
                arguments_rule_cli=args.arguments_rule,
            )
    elif args.command == "analyze":
        if args.analyze_all:
            return run_analyze_all(
                events_path=args.events,
                out_dir=args.out_dir,
                analysis_timestamp=args.analysis_timestamp,
            )
        return run_analyze(
            analyzer=args.analyzer,
            events_path=args.events,
            out_dir=args.out_dir,
            analysis_timestamp=args.analysis_timestamp,
        )
    elif args.command == "ghostwriter-load":
        gw_load_cfg = load_config(args.config)
        return load_ghostwriter_raw_export(
            raw_export_path=args.raw_export,
            out_dir=args.out_dir,
            analysis_timestamp=datetime.now(timezone.utc),
            config=gw_load_cfg,
            output_rule_cli=args.output_rule,
            arguments_rule_cli=args.arguments_rule,
        )
    elif args.command == "html":
        return run_html(
            analysis_dir=args.analysis_dir,
            output_path=args.output,
            include_version_links=args.include_version_links,
        )
    elif args.command == "partial-load":
        partial_cfg = load_config(args.config)
        return run_partial_load(
            partial_json_path=args.json_path,
            operation_id=args.operation_id,
            operation_name=args.operation_name,
            out_dir=args.out_dir,
            no_versioning=args.no_versioning,
            run_analyzers=not args.no_analyzers,
            config=partial_cfg,
            output_rule_cli=args.output_rule,
            arguments_rule_cli=args.arguments_rule,
        )
    elif args.command == "cs-rest":
        cs_rest_cfg = load_config(args.config)
        return run_cobaltstrike_rest_load(
            endpoint=args.endpoint,
            username=getattr(args, "username", None),
            password=getattr(args, "password", None),
            api_token=getattr(args, "api_token", None),
            duration_ms=getattr(args, "duration_ms", None),
            operation_id=args.operation_id,
            operation_name=args.operation_name,
            out_dir=args.out_dir,
            verify_tls=not args.insecure,
            debug=getattr(args, "debug", False),
            no_versioning=args.no_versioning,
            run_analyzers=not args.no_analyzers,
            config=cs_rest_cfg,
            output_rule_cli=args.output_rule,
            arguments_rule_cli=args.arguments_rule,
        )
    elif args.command == "merge":
        # Resolve input paths from --inputs or --pattern
        input_paths = []
        if args.inputs:
            input_paths = args.inputs
        elif args.pattern:
            input_paths = _expand_input_pattern(args.pattern)
            if not input_paths:
                print(f"error: no directories matched pattern: {args.pattern}", file=sys.stderr)
                return 1

        return run_merge(
            input_paths=input_paths,
            output_dir=args.output,
            operation_name=args.operation_name,
        )
    elif args.command == "multi-analyze":
        # Resolve input paths from --inputs or --pattern
        input_paths = []
        if args.inputs:
            input_paths = args.inputs
        elif args.pattern:
            input_paths = _expand_input_pattern(args.pattern)
            if not input_paths:
                print(f"error: no directories matched pattern: {args.pattern}", file=sys.stderr)
                return 1

        return run_multi_analyze(
            input_paths=input_paths,
            output_dir=args.output,
            operation_name=args.operation_name,
        )

    return 0


if __name__ == "__main__":
    main()
