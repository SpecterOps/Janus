"""
HTML report generator for Janus analysis results.

Generates a simple, self-contained HTML report from JSON analysis outputs.
"""

import base64
import html
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit


def _decode_base64_output(text: str) -> str:
    """Attempt to decode base64-encoded output text.

    Args:
        text: Potentially base64-encoded string (may contain multiple lines)

    Returns:
        Decoded text if valid base64, otherwise original text
    """
    if not text or not text.strip():
        return text

    # Process each line separately (Mythic sends each response as separate line)
    lines = text.split('\n')
    decoded_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            decoded_lines.append('')
            continue

        # Check if line looks like base64 (ends with = or contains only base64 chars)
        # Base64 pattern: alphanumeric + + / and optional = padding
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', line):
            try:
                decoded_bytes = base64.b64decode(line, validate=True)
                # Check if result is valid UTF-8 text
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                # Check if result contains mostly printable characters
                if _is_printable_text(decoded_str):
                    decoded_lines.append(decoded_str.rstrip('\n\r'))
                else:
                    # Binary data - keep as base64 or show indicator
                    decoded_lines.append(f"<binary data: {len(decoded_bytes)} bytes>")
            except Exception:
                # Not valid base64 or not UTF-8 - use original
                decoded_lines.append(line)
        else:
            # Doesn't look like base64 - use as-is
            decoded_lines.append(line)

    return '\n'.join(decoded_lines)


def _is_printable_text(s: str, min_printable_ratio: float = 0.8) -> bool:
    """Check if string contains mostly printable characters.

    Args:
        s: String to check
        min_printable_ratio: Minimum ratio of printable chars (0.0-1.0)

    Returns:
        True if string appears to be readable text
    """
    if not s:
        return True

    printable_count = sum(1 for c in s if c.isprintable() or c in '\n\r\t')
    ratio = printable_count / len(s)
    return ratio >= min_printable_ratio


def _fmt_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string (e.g. '1h 33m', '4m 12s', '45s')."""
    seconds = int(seconds)
    if seconds >= 3600:
        h, rem = divmod(seconds, 3600)
        m = rem // 60
        return f"{h}h {m}m" if m else f"{h}h"
    if seconds >= 60:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s" if s else f"{m}m"
    return f"{seconds}s"


def _fmt_args_cell(arguments_raw: str, preview_len: int = 60, event: dict | None = None) -> str:
    """Render arguments_raw as an HTML table cell — collapsible if long.

    When *event* is provided and contains retention metadata, the cell
    distinguishes between genuinely empty arguments and arguments that
    were removed by a retention policy.
    """
    retained = (event or {}).get("arguments_retained")
    if not arguments_raw:
        if retained == "drop":
            return '<em class="privacy-filtered" title="arguments_raw removed by retention policy (drop)">redacted</em>'
        if retained == "hash":
            digest = (event or {}).get("arguments_digest", "")
            short = html.escape(digest[:20] + "..." if len(digest) > 20 else digest)
            return f'<em class="privacy-filtered" title="arguments_raw replaced with digest (hash)">hash: {short}</em>'
        if retained == "features_only":
            shape = (event or {}).get("arguments_shape", "")
            length = (event or {}).get("arguments_length", 0)
            summary = f"{shape}, {length} chars" if shape else f"{length} chars"
            return f'<em class="privacy-filtered" title="arguments_raw replaced with derived features">{html.escape(summary)}</em>'
        return "<em>none</em>"
    escaped = html.escape(arguments_raw)
    if len(arguments_raw) <= preview_len:
        return f"<code>{escaped}</code>"
    preview = html.escape(arguments_raw[:preview_len])
    return (
        f"<details><summary><code>{preview}...</code></summary>"
        f"<pre style='white-space:pre-wrap;word-break:break-all;margin:4px 0'>{escaped}</pre>"
        f"</details>"
    )


def _arguments_retention_summary(event: dict | None = None, *, prefix: str = "") -> str:
    """Return a concise plain-text summary for withheld arguments."""
    retained = (event or {}).get(f"{prefix}arguments_retained")
    if retained == "drop":
        return "[arguments redacted]"
    if retained == "hash":
        digest = str((event or {}).get(f"{prefix}arguments_digest", "") or "")
        short = digest[:20] + "..." if len(digest) > 20 else digest
        return f"[args hash: {short}]" if short else "[args hash]"
    if retained == "features_only":
        shape = str((event or {}).get(f"{prefix}arguments_shape", "") or "")
        length = (event or {}).get(f"{prefix}arguments_length", 0)
        summary = f"{shape}, {length} chars" if shape else f"{length} chars"
        return f"[args features: {summary}]"
    return ""


def _output_retention_summary(event: dict | None = None, *, prefix: str = "") -> str:
    """Return a concise plain-text summary for withheld output."""
    retained = (event or {}).get(f"{prefix}output_retained")
    status = str((event or {}).get("status", "") or "")
    if retained == "none":
        base = "output withheld by retention policy (none)"
    elif retained == "errors_only" and status == "success":
        base = "successful output withheld by retention policy (errors_only)"
    else:
        return ""

    length = (event or {}).get(f"{prefix}output_length")
    line_count = (event or {}).get(f"{prefix}output_line_count")
    details: list[str] = []
    if isinstance(length, int):
        details.append(f"{length} chars")
    if isinstance(line_count, int) and line_count > 0:
        details.append(f"{line_count} line{'s' if line_count != 1 else ''}")
    if details:
        return f"{base}; {', '.join(details)}"
    return base


def _wrap_cell_text(value: object, *, use_code: bool = False) -> str:
    """Render long table text with a marker class so it can wrap cleanly."""
    escaped = html.escape("" if value is None else str(value))
    tag = "code" if use_code else "span"
    return f'<{tag} class="wrap-cell-text">{escaped}</{tag}>'


def _format_retention_rule_list(rules: object) -> str:
    """Render a small list of observed retention rules for report text."""
    if not isinstance(rules, list):
        return ""
    values = [html.escape(str(rule)) for rule in rules if rule]
    if not values:
        return ""
    return ", ".join(f"<code>{value}</code>" for value in values)


def _retention_metadata_from_analysis(analysis_data: dict) -> dict | None:
    """Best-effort retention summary derived from analyzer metadata."""
    observed_args_rules: set[str] = set()
    observed_output_rules: set[str] = set()

    for payload in analysis_data.values():
        if not isinstance(payload, dict):
            continue
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        retention = metadata.get("retention", {})
        if not isinstance(retention, dict):
            continue

        args_rule = retention.get("arguments_retained")
        out_rule = retention.get("output_retained")
        if args_rule:
            observed_args_rules.add(str(args_rule))
        if out_rule:
            observed_output_rules.add(str(out_rule))

        for rule in retention.get("observed_arguments_rules", []):
            if rule:
                observed_args_rules.add(str(rule))
        for rule in retention.get("observed_output_rules", []):
            if rule:
                observed_output_rules.add(str(rule))

    if not observed_args_rules and not observed_output_rules:
        return None

    def _canonical(observed: set[str]) -> str:
        if not observed:
            return "all"
        if len(observed) > 1:
            return "mixed"
        return next(iter(observed))

    return {
        "arguments_rule": _canonical(observed_args_rules),
        "output_rule": _canonical(observed_output_rules),
        "observed_arguments_rules": sorted(observed_args_rules),
        "observed_output_rules": sorted(observed_output_rules),
        "_derived_from_analyzers": True,
    }


def _mythic_base_url(endpoint: str) -> str:
    """Strip trailing path (e.g. /graphql) from the Mythic endpoint to get the UI base URL."""
    if not endpoint:
        return ""
    after_scheme = endpoint.split("://", 1)[-1]
    return endpoint.rsplit("/", 1)[0] if "/" in after_scheme else endpoint


def _safe_external_href(base_url: str, path: str) -> str:
    """Build a safe absolute HTTP(S) href or return an empty string."""
    if not base_url:
        return ""
    try:
        parsed = urlsplit(base_url)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    safe_base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
    safe_path = quote(path.lstrip("/"), safe="/")
    return html.escape(f"{safe_base}/{safe_path}", quote=True)


def _safe_relative_report_href(dir_name: str) -> str:
    """Build a safe relative href for previous-version links or return an empty string."""
    safe_dir = re.sub(r"[^A-Za-z0-9_.-]", "", str(dir_name))
    if not safe_dir:
        return ""
    return html.escape(f"../{safe_dir}/report.html", quote=True)


def _cb_link(base_url: str, cb_id: str, display_id=None) -> str:
    """Render callback ID as a Mythic hyperlink, or plain text if no base URL.

    ``display_id`` is the callback's per-operation sequential counter.  When
    provided and non-zero it is used as both the visible label and the URL
    identifier, since Mythic's ``/new/callbacks/:callbackDisplayId`` route
    resolves by ``display_id``.  Falls back to the database PK (``cb_id``)
    only when ``display_id`` is unavailable.
    """
    if display_id:
        label = f"CB {html.escape(str(display_id))}"
    else:
        label = f"CB {html.escape(str(cb_id))}"
    if not base_url:
        return label
    raw_id = str(display_id) if display_id else str(cb_id)
    url = _safe_external_href(base_url, f"new/callbacks/{raw_id}")
    if not url:
        return label
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{label}</a>'


def _task_link(base_url: str, task_id, display_id=None) -> str:
    """Render task ID as a Mythic hyperlink, or plain text if no base URL.

    ``display_id`` is Mythic's per-operation sequential counter (shown as T-N
    in the Mythic UI).  When provided and non-zero it is used as both the
    visible label and the URL identifier, since Mythic's ``/new/task/:taskId``
    route resolves by ``display_id``.  Falls back to the database PK
    (``task_id``) only when ``display_id`` is unavailable.
    """
    if display_id:
        label = f"T-{html.escape(str(display_id))}"
    else:
        label = f"Task {html.escape(str(task_id))}"
    if not base_url:
        return label
    raw_id = str(display_id) if display_id else str(task_id)
    url = _safe_external_href(base_url, f"new/task/{raw_id}")
    if not url:
        return label
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{label}</a>'


def _format_duration_from_timestamps(first_ts: str, last_ts: str) -> str:
    """Compute human-readable duration from two ISO timestamps."""
    if not first_ts or not last_ts:
        return ""
    try:
        first = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
        last = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    delta = last - first
    total_seconds = int(delta.total_seconds())
    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        m, s = divmod(total_seconds, 60)
        return f"{m}m {s}s" if s else f"{m}m"
    elif total_seconds < 86400:
        h, r = divmod(total_seconds, 3600)
        m, s = divmod(r, 60)
        return f"{h}h {m}m {s}s" if s else f"{h}h {m}m"
    else:
        d, r = divmod(total_seconds, 86400)
        h, r = divmod(r, 3600)
        m, _ = divmod(r, 60)
        return f"{d}d {h}h {m}m"


def _format_short_timestamp(iso_str: str) -> str:
    """Format ISO timestamp as short human-readable string (e.g. 'Feb 10, 14:43')."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %H:%M")
    except (ValueError, TypeError):
        return iso_str[:16]


def _ts_html(iso_str: str) -> str:
    """Render a short formatted timestamp with full ISO string in tooltip."""
    if not iso_str:
        return ""
    short = _format_short_timestamp(iso_str)
    return f'<abbr title="{html.escape(iso_str)}">{html.escape(short)}</abbr>'


def _collapsible_section(title: str, content: str, *, open_by_default: bool = False, extra_class: str = "") -> str:
    """Wrap content in a collapsible details/summary panel."""
    open_attr = " open" if open_by_default else ""
    cls = f"section-panel {extra_class}".strip()
    return f"""
    <details class="{cls}"{open_attr}>
        <summary>{title}</summary>
        <div class="section-body">
            {content}
        </div>
    </details>
    """


# Folder-aligned analyzer groups: display title -> ordered analyzer keys
# matching Analyzers/{Summary,Command,Workflow,Tooling}Analysis/ layout.
_ANALYZER_GROUPS: list[tuple[str, list[str]]] = [
    ("Summary Analysis", ["summary-visualization"]),
    (
        "Command Analysis",
        [
            "command-failure-summary",
            "command-retry-success",
            "command-duration",
            "friction-score",
            "outlier-context",
            "av-tracker",
        ],
    ),
    (
        "Workflow Analysis",
        [
            "callback-health",
            "dwell-time",
            "parameter-entropy",
        ],
    ),
    (
        "Tooling Analysis",
        [
            "argument-position-profile",
            "tool-dump",
        ],
    ),
]


def _render_analyzer_panel(
    analyzer_key: str,
    *,
    analysis_files: dict[str, Path],
    analysis_data: dict[str, dict],
    quality: dict,
    callback_data: dict[str, dict],
    base_url: str,
) -> str:
    """Return HTML for one analyzer subsection, or empty string if not applicable."""
    suppressed_sections = quality.get("suppressed_sections", {})

    if analyzer_key == "summary-visualization":
        if analyzer_key in analysis_data:
            return _render_summary_analysis_static(analysis_data[analyzer_key])
        return ""

    if analyzer_key not in analysis_files:
        return ""

    if analyzer_key == "command-failure-summary":
        if analyzer_key in suppressed_sections:
            return _render_suppressed_section(
                "Command Failure Summary", suppressed_sections[analyzer_key]
            )
        if analyzer_key in analysis_data:
            return _render_command_failure_summary(
                analysis_data[analyzer_key], callback_data or None, base_url
            )
        return _render_missing_section(
            "Command Failure Summary", analysis_files[analyzer_key]
        )

    if analyzer_key == "command-retry-success":
        if analyzer_key in suppressed_sections:
            return _render_suppressed_section(
                "Command Retry Success", suppressed_sections[analyzer_key]
            )
        if analyzer_key in analysis_data:
            return _render_command_retry_success(analysis_data[analyzer_key], base_url)
        return _render_missing_section(
            "Command Retry Success", analysis_files[analyzer_key]
        )

    if analyzer_key == "command-duration":
        if analyzer_key in analysis_data:
            outlier_context_data = analysis_data.get("outlier-context")
            return _render_command_duration(
                analysis_data[analyzer_key], base_url, outlier_context_data
            )
        return _render_missing_section(
            "Command Duration", analysis_files[analyzer_key]
        )

    if analyzer_key == "friction-score":
        if analyzer_key in analysis_data:
            return _render_friction_score(analysis_data[analyzer_key])
        return _render_missing_section(
            "Top Friction Candidates", analysis_files[analyzer_key]
        )

    if analyzer_key == "outlier-context":
        # Enrichment is folded into Command Duration when present; only show a
        # standalone section when the analyzer JSON exists (avoid noise).
        if analyzer_key in analysis_data:
            return _render_outlier_context(analysis_data[analyzer_key], base_url)
        return ""

    if analyzer_key == "callback-health":
        if analyzer_key in suppressed_sections:
            return _render_suppressed_section(
                "Callback Health", suppressed_sections[analyzer_key]
            )
        if analyzer_key in analysis_data:
            return _render_callback_health(analysis_data[analyzer_key], base_url)
        return _render_missing_section(
            "Callback Health", analysis_files[analyzer_key]
        )

    if analyzer_key == "av-tracker":
        if analyzer_key in analysis_data:
            return _render_av_tracker(analysis_data[analyzer_key], base_url)
        return _render_missing_section("AV Tracker", analysis_files[analyzer_key])

    if analyzer_key == "dwell-time":
        if analyzer_key in analysis_data:
            return _render_dwell_time(analysis_data[analyzer_key], base_url)
        return _render_missing_section("Dwell Time", analysis_files[analyzer_key])

    if analyzer_key == "parameter-entropy":
        if analyzer_key in analysis_data:
            return _render_parameter_entropy(analysis_data[analyzer_key], base_url)
        return _render_missing_section(
            "Parameter Entropy", analysis_files[analyzer_key]
        )

    if analyzer_key == "argument-position-profile":
        if analyzer_key in analysis_data:
            return _render_argument_position_profile(
                analysis_data[analyzer_key], base_url
            )
        return _render_missing_section(
            "Argument Position Profile", analysis_files[analyzer_key]
        )

    if analyzer_key == "tool-dump":
        if analyzer_key in analysis_data:
            return _render_tool_dump(analysis_data[analyzer_key], base_url)
        return _render_missing_section("Tool Dump", analysis_files[analyzer_key])

    return ""


def generate_html(
    analysis_files: dict[str, Path],
    output_path: Path,
    version_metadata: dict | None = None,
    previous_versions: list[dict] | None = None,
) -> None:
    """
    Generate HTML report from analysis JSON files.

    Args:
        analysis_files: Dict mapping analyzer names to their JSON file paths
        output_path: Where to write the HTML report
        version_metadata: Optional bundle metadata with version info
        previous_versions: Optional list of previous analysis versions
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Derive Mythic UI base URL for hyperlinking callback/task IDs
    base_url = _mythic_base_url(
        (version_metadata or {}).get("mythic_endpoint", "")
    )

    # Pre-load all analysis JSON files so we can aggregate for key findings
    analysis_data: dict[str, dict] = {}
    for name, path in analysis_files.items():
        if path.exists():
            with path.open(encoding="utf-8") as f:
                analysis_data[name] = json.load(f)

    # Build callback data map for cross-referencing
    callback_data: dict[str, dict] = {}
    for cb_id, cb_info in analysis_data.get("callback-health", {}).get("callbacks", {}).items():
        callback_data[str(cb_id)] = cb_info

    quality = _assess_report_quality(version_metadata or {}, analysis_data)

    report_overview = _render_report_header(
        version_metadata,
        previous_versions or [],
        analysis_data,
        quality,
        report_generated_at=timestamp,
    )

    sections: list[str] = []
    for group_title, analyzer_keys in _ANALYZER_GROUPS:
        inner_parts: list[str] = []
        for key in analyzer_keys:
            block = _render_analyzer_panel(
                key,
                analysis_files=analysis_files,
                analysis_data=analysis_data,
                quality=quality,
                callback_data=callback_data,
                base_url=base_url,
            )
            if block.strip():
                inner_parts.append(block)
        if not inner_parts:
            continue
        # Single Summary block is already a static section with its own heading
        if group_title == "Summary Analysis":
            sections.extend(inner_parts)
            continue
        sections.append(
            _collapsible_section(
                html.escape(group_title),
                "\n".join(inner_parts),
                extra_class="analyzer-group",
            )
        )

    # Generate final HTML (overview + title above global table search)
    html_content = _get_html_template(report_overview, "\n".join(sections))

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write(html_content)


def _render_report_header(
    metadata: dict | None,
    previous_versions: list[dict],
    analysis_data: dict,
    quality: dict | None = None,
    *,
    report_generated_at: str = "",
) -> str:
    """Render combined Report Overview: title, generated time, run info, and key findings."""

    gen_esc = html.escape(report_generated_at) if report_generated_at else "-"
    title_html = (
        '<h2 class="report-overview-title">Janus Analysis Report '
        f'<span class="report-generated-sub">· Generated: {gen_esc}</span></h2>'
    )

    # --- Run information as a definition list with <code>-styled values ---
    meta_html = ""
    if metadata:
        # Check if this is a multi-operation analysis
        is_multi_op = metadata.get("source") == "multi-operation"

        if is_multi_op:
            # Multi-operation header
            op_name = html.escape(str(metadata.get("operation_name", "Multi-Operation Analysis")))
            op_count = metadata.get("operation_count", 0)
            analysis_ts = html.escape(str(metadata.get("analysis_timestamp", "N/A")))
            janus_ver = html.escape(str(metadata.get("janus_version", "N/A")))
            task_count = metadata.get("task_count", 0)
            result_count = metadata.get("result_count", 0)
            status_counts = metadata.get("status_counts", {})

            # Build operations list
            operations = metadata.get("operations", [])
            ops_list_html = ""
            if operations:
                ops_items = []
                for op in operations:
                    op_slug = html.escape(op.get("slug", "unknown"))
                    op_tasks = op.get("task_count", 0)
                    op_status = op.get("status_counts", {})
                    op_success = op_status.get("success", 0)
                    op_error = op_status.get("error", 0)
                    ops_items.append(
                        f"<li><code>{op_slug}</code> ({op_tasks} tasks, {op_success} success, {op_error} error)</li>"
                    )
                ops_list_html = f"<ul class='operations-list'>{''.join(ops_items)}</ul>"

            # Build scope summary
            scope_dd = f"<code>{task_count:,}</code> tasks across <code>{op_count}</code> operations"
            if status_counts:
                s = status_counts.get("success", 0)
                e = status_counts.get("error", 0)
                u = status_counts.get("unknown", 0)
                scope_dd += f" ({s:,} success, {e:,} error, {u:,} unknown)"

            meta_html = f"""
            <dl class="meta-grid">
                <dt>Analysis Scope</dt><dd><code>{op_name}</code></dd>
                <dt>Operations</dt><dd>{op_count} operations analyzed</dd>
                <dt>Analyzed</dt><dd><code>{analysis_ts}</code></dd>
                <dt>Janus Version</dt><dd><code>{janus_ver}</code></dd>
                <dt>Total Scope</dt><dd>{scope_dd}</dd>
            </dl>
            <details open>
                <summary>Included Operations</summary>
                {ops_list_html}
            </details>
            """
        else:
            # Single-operation header (existing logic)
            op_name = html.escape(str(metadata.get("operation_name", "N/A")))
            op_id = metadata.get("operation_id", "N/A")
            source_endpoint = metadata.get("mythic_endpoint", "") or metadata.get("ghostwriter_endpoint", "")
            analysis_ts = html.escape(str(metadata.get("analysis_timestamp", "N/A")))
            analysis_ver = html.escape(str(metadata.get("analysis_version", "N/A")))
            janus_ver = html.escape(str(metadata.get("janus_version", "N/A")))
            task_count = metadata.get("task_count", "N/A")
            result_count = metadata.get("result_count", "N/A")
            status_counts = metadata.get("status_counts", {})

            endpoint_row = ""
            if source_endpoint:
                ep = html.escape(str(source_endpoint))
                endpoint_row = f"<dt>Source</dt><dd><code>{ep}</code></dd>"

            scope_dd = f"<code>{task_count}</code> tasks &middot; <code>{result_count}</code> results"
            if status_counts:
                s = status_counts.get("success", 0)
                e = status_counts.get("error", 0)
                u = status_counts.get("unknown", 0)
                scope_dd += f" ({s} success, {e} error, {u} unknown)"

            meta_html = f"""
            <dl class="meta-grid">
                <dt>Operation</dt><dd><code>{op_name}</code> (ID: <code>{op_id}</code>)</dd>
                {endpoint_row}
                <dt>Analyzed</dt><dd><code>{analysis_ts}</code></dd>
                <dt>Versions</dt><dd>Analysis <code>{analysis_ver}</code> &middot; Janus <code>{janus_ver}</code></dd>
                <dt>Scope</dt><dd>{scope_dd}</dd>
            </dl>
            """

    # --- Key findings ---
    findings: list[str] = []
    quality = quality or {"warnings": [], "suppressed_sections": {}}
    cmd_data = analysis_data.get("command-failure-summary", {})
    commands = cmd_data.get("commands", {})
    if commands and "command-failure-summary" not in quality["suppressed_sections"]:
        total_cmds = len(commands)
        failing_cmds = {n: s for n, s in commands.items() if s["failure_rate"] > 0}
        high_fail = {n: s for n, s in commands.items() if s["failure_rate"] >= 0.5}
        if failing_cmds:
            msg = f"{len(failing_cmds)} of {total_cmds} commands have failures"
            if high_fail:
                msg += f" ({len(high_fail)} with &gt;50% failure rate)"
            findings.append(msg)
            worst_name, worst = max(failing_cmds.items(), key=lambda x: x[1]["failure_rate"])
            cb_count = len(worst.get("callback_breakdown", {}))
            findings.append(
                f"Top concern: <code>{html.escape(worst_name)}</code> at "
                f"{worst['failure_rate']:.1%} failure rate "
                f"({worst['error_count']} errors in {worst['execution_count']} executions"
                + (f" across {cb_count} callbacks)" if cb_count else ")")
            )

    friction_data = analysis_data.get("friction-score", {})
    friction_commands = friction_data.get("commands", [])
    if friction_commands:
        top = friction_commands[0]
        findings.append(
            "Top friction candidate: "
            f"<code>{html.escape(str(top.get('command_name', 'unknown')))}</code> "
            f"score {float(top.get('score', 0)):.1f}, "
            f"action {html.escape(str(top.get('recommended_action', 'investigate')))}"
        )

    cb_data = analysis_data.get("callback-health", {})
    cb_summary = cb_data.get("summary", {})
    if cb_summary and "callback-health" not in quality["suppressed_sections"]:
        consecutive_failures = cb_summary.get("callbacks_with_consecutive_failures", 0)
        if consecutive_failures:
            findings.append(f"{consecutive_failures} callback{'s' if consecutive_failures != 1 else ''} with 3+ consecutive failures (potential crash)")

    arg_profile = analysis_data.get("argument-position-profile", {})
    arg_summary = arg_profile.get("summary", {})
    if arg_summary:
        total_findings = arg_summary.get("total_findings", 0)
        by_type = arg_summary.get("findings_by_type", {})
        if total_findings:
            parts = []
            static_count = by_type.get("static_argument", 0)
            if static_count:
                parts.append(f"{static_count} static argument{'s' if static_count != 1 else ''} (automation candidates)")
            diversity_count = by_type.get("high_diversity", 0)
            if diversity_count:
                parts.append(f"{diversity_count} high-diversity position{'s' if diversity_count != 1 else ''}")
            depth_count = by_type.get("depth_anomaly", 0)
            if depth_count:
                parts.append(f"{depth_count} depth anomal{'ies' if depth_count != 1 else 'y'}")
            if parts:
                findings.append(f"Argument profiling: {', '.join(parts)}")
        elif arg_summary.get("commands_profiled", 0):
            findings.append(
                f"Argument profiling: {arg_summary['commands_profiled']} commands profiled, "
                f"max depth {arg_summary.get('max_depth_observed', 0)} - no anomalies detected"
            )

    warnings = quality.get("warnings", [])
    suppressed_sections = quality.get("suppressed_sections", {})
    warnings_html = ""
    if warnings or suppressed_sections:
        warning_items = [f"<li>{html.escape(w)}</li>" for w in warnings]
        for section, reason in suppressed_sections.items():
            title = section.replace("-", " ").title()
            warning_items.append(
                f"<li><strong>{html.escape(title)} suppressed:</strong> {html.escape(reason)}</li>"
            )
        warnings_html = f"""
        <div class="quality-warning">
            <h3>Data Quality Warning</h3>
            <ul class="findings-list">{"".join(warning_items)}</ul>
        </div>
        """

    # --- Privacy/retention banner ---
    privacy_html = ""
    retention_metadata = dict(metadata or {})
    derived_retention = _retention_metadata_from_analysis(analysis_data)
    use_derived_retention = (
        derived_retention is not None
        and (
            not metadata
            or not retention_metadata.get("arguments_rule")
            or not retention_metadata.get("output_rule")
        )
    )
    if use_derived_retention and derived_retention:
        for key, value in derived_retention.items():
            retention_metadata.setdefault(key, value)

    if retention_metadata:
        args_rule = retention_metadata.get("arguments_rule", "all")
        out_rule = retention_metadata.get("output_rule", "all")
        observed_args_rules = retention_metadata.get("observed_arguments_rules", [])
        observed_output_rules = retention_metadata.get("observed_output_rules", [])
        privacy_notes: list[str] = []
        if args_rule == "mixed":
            observed = _format_retention_rule_list(observed_args_rules)
            note = (
                "<code>arguments_rule: mixed</code> — merged dataset contains multiple "
                "argument-retention policies"
            )
            if observed:
                note += f" ({observed})"
            privacy_notes.append(note)
        elif args_rule and args_rule != "all":
            privacy_notes.append(
                f"<code>arguments_rule: {html.escape(args_rule)}</code> — "
                "raw task arguments were not retained in events.ndjson"
            )
        if out_rule == "mixed":
            observed = _format_retention_rule_list(observed_output_rules)
            note = (
                "<code>output_rule: mixed</code> — merged dataset contains multiple "
                "output-retention policies"
            )
            if observed:
                note += f" ({observed})"
            privacy_notes.append(note)
        elif out_rule and out_rule not in ("all", "errors_only"):
            privacy_notes.append(
                f"<code>output_rule: {html.escape(out_rule)}</code> — "
                "result output was not retained in events.ndjson"
            )
        elif out_rule == "errors_only":
            privacy_notes.append(
                '<code>output_rule: errors_only</code> — '
                'successful result output was stripped before persistence'
            )
        if privacy_notes:
            items = "".join(f"<li>{n}</li>" for n in privacy_notes)
            note_source = "bundle.json"
            if use_derived_retention and retention_metadata.get("_derived_from_analyzers"):
                note_source = "analyzer metadata (bundle.json unavailable)"
            privacy_html = f"""
            <div class="privacy-notice">
                <h3>Retention Policy</h3>
                <ul class="findings-list">{items}</ul>
                <p style="margin:4px 0 0;font-size:0.92em;opacity:0.85">
                    Some analyzer sections may show reduced detail.
                    Retention state derived from <code>{html.escape(note_source)}</code>.
                </p>
            </div>
            """

    if findings:
        items = "".join(f"<li>{f}</li>" for f in findings)
        findings_html = f'<h3>Key Findings</h3><ul class="findings-list findings-issues">{items}</ul>'
    elif warnings:
        findings_html = '<h3>Key Findings</h3><p class="findings-limited">Findings withheld where data quality would make them misleading.</p>'
    else:
        findings_html = '<h3>Key Findings</h3><p class="findings-clean">No issues detected. All commands and callbacks are healthy.</p>'

    # --- Previous versions ---
    prev_html = ""
    if previous_versions:
        links = []
        for ver in previous_versions:
            href = _safe_relative_report_href(ver.get("dir_name", ""))
            version = html.escape(str(ver.get("version", "")))
            if href:
                links.append(f'<li><a href="{href}">{version}</a></li>')
            else:
                links.append(f"<li>{version}</li>")
        prev_html = f"""
        <details>
            <summary>Previous analysis runs</summary>
            <ul>{"".join(links)}</ul>
        </details>
        """

    content = f"{title_html}{meta_html}{warnings_html}{privacy_html}{findings_html}{prev_html}"
    header_cls = "report-header has-issues" if (findings or warnings or suppressed_sections) else "report-header"
    return _collapsible_section("Report Overview", content, open_by_default=True, extra_class=header_cls)


def _summary_visualization_content(data: dict) -> str:
    """Inner HTML for summary viz: status pie + timeline grid (no section wrapper)."""
    import math

    sd = data.get("status_distribution", {})
    timeline = data.get("timeline", {})
    buckets = timeline.get("buckets", [])
    bucket_unit = timeline.get("bucket_unit", "hour")
    summary = data.get("summary", {})

    # --- Pie chart (SVG) ---
    total = sd.get("total", 0)
    slices = [
        ("Success", sd.get("success", 0), "#05CE8B"),
        ("Error", sd.get("error", 0), "#EA1412"),
        ("Unknown", sd.get("unknown", 0), "#9e9e9e"),
    ]
    # Filter out zero-count slices for cleanliness
    slices = [(label, count, color) for label, count, color in slices if count > 0]

    pie_svg = ""
    if total > 0 and slices:
        cx, cy, r = 80, 80, 70
        start_angle = -math.pi / 2  # Start at top

        paths = []
        current = start_angle
        for label, count, color in slices:
            frac = count / total
            if frac >= 1.0:
                # Full circle
                paths.append(
                    f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" stroke="#fff" stroke-width="1.5"/>'
                )
            else:
                angle = frac * 2 * math.pi
                x1 = cx + r * math.cos(current)
                y1 = cy + r * math.sin(current)
                x2 = cx + r * math.cos(current + angle)
                y2 = cy + r * math.sin(current + angle)
                large = 1 if angle > math.pi else 0
                paths.append(
                    f'<path d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large},1 {x2:.2f},{y2:.2f} Z" '
                    f'fill="{color}" stroke="#fff" stroke-width="1.5"/>'
                )
            current += frac * 2 * math.pi

        legend_items = []
        for label, count, color in slices:
            pct = count / total * 100
            legend_items.append(
                f'<div style="display:flex;align-items:center;gap:6px;margin:3px 0">'
                f'<span style="display:inline-block;width:12px;height:12px;background:{color};border-radius:2px"></span>'
                f'<span>{html.escape(label)}: <strong>{count:,}</strong> ({pct:.1f}%)</span></div>'
            )

        pie_svg = (
            f'<div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">'
            f'<svg width="160" height="160" viewBox="0 0 160 160">{"".join(paths)}</svg>'
            f'<div>{"".join(legend_items)}</div>'
            f'</div>'
        )
    elif total == 0:
        pie_svg = '<p class="muted">No result events to chart.</p>'

    # --- Timeline bar chart (SVG) ---
    timeline_svg = ""
    if buckets:
        max_count = max(b["count"] for b in buckets)
        if max_count == 0:
            max_count = 1  # avoid division by zero

        chart_w = min(max(len(buckets) * 18, 200), 900)
        chart_h = 120
        bar_w = max(chart_w / len(buckets) - 2, 4)
        padding_left = 40
        padding_bottom = 50
        svg_w = chart_w + padding_left + 10
        svg_h = chart_h + padding_bottom + 10

        bars = []
        labels = []
        # Show a reasonable number of x-axis labels
        label_every = max(1, len(buckets) // 12)

        for i, b in enumerate(buckets):
            x = padding_left + i * (chart_w / len(buckets)) + 1
            h = (b["count"] / max_count) * chart_h if b["count"] > 0 else 0
            y = chart_h - h + 5
            tooltip = html.escape(f'{b["label"]}: {b["count"]} tasks')
            bars.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
                f'fill="#4A3BD7" rx="1"><title>{tooltip}</title></rect>'
            )
            if i % label_every == 0:
                # Short label
                raw_label = b["label"]
                if bucket_unit == "hour":
                    short = raw_label[5:13]  # "MM-DD HH"
                else:
                    short = raw_label[5:]  # "MM-DD"
                lx = x + bar_w / 2
                ly = chart_h + 18
                labels.append(
                    f'<text x="{lx:.1f}" y="{ly}" text-anchor="end" font-size="10" fill="#666" '
                    f'transform="rotate(-45 {lx:.1f} {ly})">{html.escape(short)}</text>'
                )

        # Y-axis labels
        y_labels = []
        for frac in (0, 0.5, 1.0):
            val = int(max_count * (1 - frac))
            y = 5 + chart_h * frac
            y_labels.append(
                f'<text x="{padding_left - 4}" y="{y + 3}" text-anchor="end" font-size="10" fill="#6b6890">{val}</text>'
                f'<line x1="{padding_left}" y1="{y}" x2="{svg_w - 10}" y2="{y}" stroke="#e0e0e0" stroke-width="0.5"/>'
            )

        unit_label = "Tasks per hour" if bucket_unit == "hour" else "Tasks per day"
        timeline_svg = (
            f'<p style="margin:4px 0 2px;font-size:0.9em;color:#666">{unit_label}</p>'
            f'<svg width="100%" viewBox="0 0 {svg_w} {svg_h}" style="max-width:{svg_w}px">'
            f'{"".join(y_labels)}{"".join(bars)}{"".join(labels)}'
            f'</svg>'
        )
    else:
        timeline_svg = '<p class="muted">No task timestamps available for timeline.</p>'

    # --- Compose ---
    span_text = ""
    if summary.get("span_hours"):
        hours = summary["span_hours"]
        if hours >= 24:
            span_text = f" ({hours / 24:.1f} days)"
        else:
            span_text = f" ({hours:.1f} hours)"

    return (
        f'<div class="summary-viz-grid">'
        f'<div class="summary-viz-pie">'
        f'<h3>Command Status Distribution</h3>'
        f'{pie_svg}'
        f'</div>'
        f'<div class="summary-viz-timeline">'
        f'<h3>Command Volume Timeline{span_text}</h3>'
        f'{timeline_svg}'
        f'</div>'
        f'</div>'
    )


def _render_summary_analysis_static(data: dict) -> str:
    """Always-visible Summary Analysis block (no nested collapsibles)."""
    body = _summary_visualization_content(data)
    return f"""
    <div class="section-static analyzer-group-summary">
        <h2 class="analyzer-group-title">{html.escape("Summary Analysis")}</h2>
        <div class="section-body">{body}</div>
    </div>
    """


def _render_missing_section(section_name: str, path: Path) -> str:
    """Render a message for missing analysis data."""
    return _collapsible_section(
        html.escape(section_name),
        f'<p class="error">Analysis file not found: <code>{html.escape(str(path))}</code></p>',
    )


def _render_suppressed_section(section_name: str, reason: str) -> str:
    """Render a report section that was intentionally omitted due to poor data quality."""
    return _collapsible_section(
        html.escape(section_name),
        (
            '<div class="quality-warning">'
            f"<p><strong>Suppressed due to incomplete data.</strong> {html.escape(reason)}</p>"
            "</div>"
        ),
        open_by_default=False,
    )


def _assess_report_quality(metadata: dict, analysis_data: dict) -> dict:
    """Assess whether the current dataset can support each report section.

    The current priority is to avoid presenting failure-centric conclusions when the
    source data lacks reliable success/error state.
    """
    source = metadata.get("source", "")
    result_count = int(metadata.get("result_count") or 0)
    status_counts = metadata.get("status_counts") or {}
    success_count = int(status_counts.get("success") or 0)
    error_count = int(status_counts.get("error") or 0)
    unknown_count = int(status_counts.get("unknown") or 0)
    resolved_count = success_count + error_count
    unknown_ratio = (unknown_count / result_count) if result_count else 1.0

    warnings: list[str] = []
    suppressed_sections: dict[str, str] = {}

    if source == "ghostwriter":
        warnings.append(
            "Ghostwriter exports currently preserve command chronology well, but often lack reliable success/error and output fields."
        )

    if result_count and unknown_ratio >= 0.9:
        warnings.append(
            f"{unknown_count} of {result_count} results are unknown, so failure-driven analyses would be misleading."
        )

    if resolved_count == 0 and result_count > 0:
        reason = (
            "No reliable result status was available in this dataset; Janus cannot distinguish success from failure."
        )
        suppressed_sections["command-failure-summary"] = reason
        suppressed_sections["command-retry-success"] = (
            "Retry-to-success analysis requires real error/success transitions, which are absent here."
        )
        suppressed_sections["callback-health"] = (
            "Callback health depends on real result status; all tasks would otherwise appear as unknown and create false crash indicators."
        )

    return {
        "warnings": warnings,
        "suppressed_sections": suppressed_sections,
    }


def _render_command_failure_summary(data: dict, callback_data: dict[str, dict] | None = None, mythic_base_url: str = "") -> str:
    """Render command failure summary as HTML."""
    commands = data.get("commands", {})

    if not commands:
        return _collapsible_section("Command Failure Summary", "<p>No command data available.</p>")

    sorted_commands = sorted(
        commands.items(),
        key=lambda x: x[1]["failure_rate"],
        reverse=True
    )

    failing = [(n, s) for n, s in sorted_commands if s["failure_rate"] > 0]
    clean = [(n, s) for n, s in sorted_commands if s["failure_rate"] == 0]

    def _build_row(cmd_name: str, stats: dict) -> str:
        failure_rate = stats["failure_rate"]
        rate_pct = f"{failure_rate:.1%}"

        if failure_rate >= 0.5:
            rate_class = "high-failure"
            row_class = "row-high-failure"
        elif failure_rate >= 0.1:
            rate_class = "medium-failure"
            row_class = "row-medium-failure"
        else:
            rate_class = "low-failure"
            row_class = ""

        cb_breakdown = stats.get("callback_breakdown", {})
        if cb_breakdown:
            cb_total = len(cb_breakdown)
            if failure_rate == 0:
                cb_cell = f"{cb_total} callback{'s' if cb_total != 1 else ''}"
            else:
                callback_map = callback_data or {}
                cb_items = []
                for cb_id, cb_stats in cb_breakdown.items():
                    cb_info = callback_map.get(cb_id, {})
                    has_consecutive = cb_info.get("has_consecutive_failures", False)
                    warning_badge = (
                        ' <span class="consecutive-failure-warning">[consecutive failures]</span>'
                        if has_consecutive else ""
                    )
                    tc = cb_stats["task_count"]
                    sc = cb_stats["success_count"]
                    ec = cb_stats["error_count"]
                    uc = cb_stats["unknown_count"]
                    cb_items.append(
                        f"<li>{_cb_link(mythic_base_url, cb_id, cb_stats.get('callback_display_id') or None)}{warning_badge} &mdash; "
                        f"{tc} task{'s' if tc != 1 else ''}: "
                        f'<span class="status-success">{sc}&#10003;</span> '
                        f'<span class="status-error">{ec}&#10007;</span> '
                        f'<span class="status-unknown">{uc}?</span>'
                        f"</li>"
                    )
                cb_cell = f"""
                <details>
                    <summary>{cb_total} callback{'s' if cb_total != 1 else ''}</summary>
                    <ul>{"".join(cb_items)}</ul>
                </details>
                """
        else:
            cb_cell = "<em>&mdash;</em>"

        # Add failure details section
        failures = stats.get("failures", [])
        failure_cell = ""
        if failures:
            failure_items = []
            for f in failures:
                task_ref = _task_link(mythic_base_url, f["task_id"], f.get("display_id") or None)
                ts_display = _ts_html(f["timestamp"]) if f.get("timestamp") else ""
                cb_ref = _cb_link(mythic_base_url, str(f.get("callback_id", "")), f.get("callback_display_id") or None)

                # Format full command with arguments
                full_command = _format_full_command(
                    f.get("command_name", ""),
                    f.get("arguments_raw", ""),
                    event=f,
                )

                # Decode base64 error message
                error_msg_raw = f.get("error_message", "")
                error_msg = _decode_base64_output(error_msg_raw)

                # Split into lines and format nicely
                error_lines = error_msg.split('\n')
                error_lines = [line for line in error_lines if line.strip()]  # Remove empty lines

                # Format error output with line breaks
                if len(error_lines) == 0:
                    retained_output = _output_retention_summary(f)
                    if retained_output:
                        escaped_retained_output = html.escape(retained_output)
                        error_display = (
                            f'<div class="error-output"><em class="privacy-filtered">'
                            f"{escaped_retained_output}</em></div>"
                        )
                        error_full_html = (
                            f'<em class="privacy-filtered">{escaped_retained_output}</em>'
                        )
                    else:
                        error_display = '<em>(no output)</em>'
                        error_full_html = '<em>(no output)</em>'
                elif len(error_lines) == 1:
                    # Single line - show inline
                    line = error_lines[0]
                    if len(line) > 150:
                        error_display = f'<div class="error-output">{html.escape(line[:150])}...<br><em>(see full output below)</em></div>'
                    else:
                        error_display = f'<div class="error-output">{html.escape(line)}</div>'
                    error_full_html = '<br>'.join(html.escape(line) for line in error_lines)
                else:
                    # Multi-line - show first 10 lines
                    preview_lines = error_lines[:10]
                    preview_html = '<br>'.join(html.escape(line[:120]) for line in preview_lines)
                    if len(error_lines) > 10:
                        preview_html += f'<br><em>(+{len(error_lines) - 10} more lines)</em>'
                    error_display = f'<div class="error-output">{preview_html}</div>'
                    error_full_html = '<br>'.join(html.escape(line) for line in error_lines)

                # Mark dispatch failures
                dispatch_badge = ' <span class="status-error">[dispatch]</span>' if f.get("dispatch_failed") else ""

                failure_items.append(f"""
                    <li>
                        <strong><code>{html.escape(full_command)}</code></strong>
                        <br>{task_ref} @ {ts_display} ({cb_ref}){dispatch_badge}
                        {error_display}
                        <details style="margin-top: 0.5em;">
                            <summary style="font-size: 0.85em; color: #4a4570; cursor: pointer;">Full output</summary>
                            <div class="error-output-full">{error_full_html}</div>
                        </details>
                    </li>
                """)

            failure_cell = f"""
                <details>
                    <summary>View {len(failures)} failure{'s' if len(failures) != 1 else ''}</summary>
                    <ul style="font-size: 0.9em;">{"".join(failure_items)}</ul>
                </details>
                """

        return f"""
        <tr class="{row_class}">
            <td>{html.escape(cmd_name)}</td>
            <td>{stats['execution_count']}</td>
            <td>{stats['success_count']}</td>
            <td>{stats['error_count']}</td>
            <td>{stats['unknown_count']}</td>
            <td class="{rate_class}" data-sort="{failure_rate}">{rate_pct}</td>
            <td data-sort="{len(cb_breakdown)}">{cb_cell}</td>
            <td>{failure_cell}</td>
        </tr>
        """

    header_row = """
            <tr>
                <th>Command Name</th>
                <th>Executions</th>
                <th>Success</th>
                <th>Error</th>
                <th>Unknown</th>
                <th>Failure Rate</th>
                <th title="Which callbacks ran this command (health shown for reference, not causation)">Ran On</th>
                <th>Failure Details</th>
            </tr>"""

    failing_rows = "".join(_build_row(n, s) for n, s in failing)
    table = f"""
    <div class="table-wrap">
    <table class="sortable">
        <thead>{header_row}
        </thead>
        <tbody>
            {failing_rows}
        </tbody>
    </table>
    </div>
    """ if failing else "<p>No commands with failures.</p>"

    clean_html = ""
    if clean:
        clean_rows = "".join(_build_row(n, s) for n, s in clean)
        clean_html = f"""
    <details>
        <summary>{len(clean)} command{'s' if len(clean) != 1 else ''} with no failures</summary>
        <div class="table-wrap">
        <table class="sortable">
            <thead>{header_row}
            </thead>
            <tbody>
                {clean_rows}
            </tbody>
        </table>
        </div>
    </details>
        """

    content = f"""
        <p>Commands sorted by failure rate (highest first).</p>
        {table}
        {clean_html}
    """
    return _collapsible_section("Command Failure Summary", content)


def _format_attempt_detail(index: int, attempt: dict, mythic_base_url: str = "", command_name: str = "", changed_keys: set | None = None) -> str:
    """Format a single attempt for display: task_id, timestamp, status, command summary."""
    tid = attempt.get("task_id", "?")
    did = attempt.get("display_id") or None
    ts = attempt.get("timestamp", "")
    status = attempt.get("status", "unknown")
    status_badge = f' <span class="status-{status}">({status})</span>' if status else ""
    # Use provided command_name or fallback to attempt's command_name field
    cmd = command_name or attempt.get("command_name", "")
    args_raw = attempt.get("arguments_raw", "")
    full_command = _format_full_command(cmd, args_raw, event=attempt)
    task_ref = _task_link(mythic_base_url, tid, did)
    ts_display = _ts_html(ts) if ts else ""
    change_hint = ""
    if changed_keys:
        keys_str = html.escape(", ".join(sorted(changed_keys)))
        change_hint = f' <span class="diff-hint" title="Changed from previous attempt">^ {keys_str}</span>'
    return f"<li>Attempt {index + 1} ({task_ref}): <code>{html.escape(full_command)}</code>{status_badge}{change_hint} &mdash; {ts_display}</li>"


def _format_full_command(
    command_name: str,
    arguments_raw: str,
    max_length: int = 120,
    *,
    event: dict | None = None,
    prefix: str = "",
) -> str:
    """Format command with arguments as it would appear in Mythic.

    Returns a string like 'ls \\\\path\\to\\dir' or 'execute_coff MyBOF arg1=val1'
    """
    if not arguments_raw:
        retained_summary = _arguments_retention_summary(event, prefix=prefix)
        if retained_summary:
            return f"{command_name} {retained_summary}".strip()
        # Commands that typically require arguments - flag when missing
        commands_needing_args = {
            "execute_coff", "execute_assembly", "inline_assembly", "ls", "cd",
            "download", "upload", "shell", "powershell", "run", "execute"
        }
        if command_name in commands_needing_args:
            return f"{command_name} (no arguments)"
        return command_name

    try:
        args = json.loads(arguments_raw)
        if isinstance(args, dict):
            # For simple string/path arguments, display inline
            if len(args) == 1:
                key, val = next(iter(args.items()))
                # Common path/file keys - show value directly after command
                if key in ("path", "file", "cmd", "command") and isinstance(val, str):
                    full_cmd = f"{command_name} {val}"
                    if len(full_cmd) <= max_length:
                        return full_cmd
                # For coff_name, show the name prominently
                if key == "coff_name" and isinstance(val, str):
                    return f"{command_name} {val}"

            # For multiple args, show key=value pairs
            parts = []
            for k, v in args.items():
                if v is None:
                    continue
                # Truncate long values
                if isinstance(v, str) and len(v) > 40:
                    v = v[:40] + "..."
                parts.append(f"{k}={v}")

            if parts:
                args_str = " ".join(parts)
                full_cmd = f"{command_name} {args_str}"
                if len(full_cmd) <= max_length:
                    return full_cmd
                # Truncate if too long
                return full_cmd[:max_length] + "..."
    except (json.JSONDecodeError, ValueError):
        # Raw string arguments - show directly
        if len(arguments_raw) <= 80:
            return f"{command_name} {arguments_raw}"
        return f"{command_name} {arguments_raw[:80]}..."

    return command_name


def _format_duration_row_command(evt: dict, fallback_name: str, *, max_length: int = 150) -> str:
    """Show PTY in-session lines as nested (pty_in_session → shell cmd), not top-level Mythic tasks."""
    shell = evt.get("pty_shell_command")
    if shell:
        inner = _format_full_command(shell, evt.get("arguments_raw", ""), max_length=max_length, event=evt)
        return f"pty_in_session → {inner}"
    return _format_full_command(
        evt.get("command_name") or fallback_name,
        evt.get("arguments_raw", ""),
        max_length=max_length,
        event=evt,
    )


def _strip_repr_quotes(s: str) -> str:
    """Strip surrounding Python repr() single quotes from a value string."""
    s = str(s)
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1]
    return s


def _format_diff_item(change: dict) -> str:
    """Format a single diff change dict as an HTML list item."""
    change_type = change.get("type", "modified")
    path = html.escape(change.get("path", ""))
    old_val = html.escape(_strip_repr_quotes(change.get("old_value", "")))
    new_val = html.escape(_strip_repr_quotes(change.get("new_value", "")))

    if change_type == "removed":
        return (
            f'<li class="diff-removed">'
            f'<span class="diff-marker">-</span>'
            f'<code>{path}</code>: <code>{old_val}</code>'
            f'</li>'
        )
    elif change_type == "added":
        return (
            f'<li class="diff-added">'
            f'<span class="diff-marker">+</span>'
            f'<code>{path}</code>: <code>{new_val}</code>'
            f'</li>'
        )
    else:  # modified / type_changed
        return (
            f'<li class="diff-modified">'
            f'<span class="diff-marker">~</span>'
            f'<code>{path}</code>: <code>{old_val}</code> -> <code>{new_val}</code>'
            f'</li>'
        )


def _format_structured_diff(structured_changes: list[dict]) -> str:
    """Format structured diff as HTML.

    Handles two formats:
    - Per-transition (new): list of {from_attempt, to_attempt, changes: [...]}
    - Flat (legacy): list of change dicts with path/type/old_value/new_value
    """
    if not structured_changes:
        return "<p>No parameter changes detected.</p>"

    # Detect format: new format has 'from_attempt' key, old has 'path' key
    if "from_attempt" in structured_changes[0]:
        sections = []
        for transition in structured_changes:
            from_n = transition.get("from_attempt", "?")
            to_n = transition.get("to_attempt", "?")
            changes = transition.get("changes", [])
            if not changes:
                continue
            items = "".join(_format_diff_item(c) for c in changes)
            sections.append(
                f'<div class="diff-transition">'
                f'<span class="diff-transition-label">Attempt {from_n} -> {to_n}</span>'
                f'<ul class="diff-list">{items}</ul>'
                f'</div>'
            )
        return "".join(sections) if sections else "<p>No parameter changes detected.</p>"
    else:
        # Legacy flat format
        items = "".join(_format_diff_item(c) for c in structured_changes)
        return f'<ul class="diff-list">{items}</ul>'


def _render_friction_score(data: dict) -> str:
    """Render top friction candidates."""
    commands = data.get("commands", [])
    summary = data.get("summary", {})
    if not commands:
        return _collapsible_section("Top Friction Candidates", "<p>No friction candidates available.</p>")

    rows = []
    for entry in commands[:10]:
        drivers = entry.get("drivers", [])
        if drivers:
            driver_items = "".join(
                f"<li>{html.escape(str(driver.get('label', driver.get('component', ''))))}</li>"
                for driver in drivers
            )
            drivers_html = f"<ul>{driver_items}</ul>"
        else:
            drivers_html = "<em>No dominant driver</em>"

        confidence = str(entry.get("confidence", "low"))
        confidence_class = {
            "high": "status-success",
            "medium": "medium-failure",
            "low": "status-unknown",
        }.get(confidence, "status-unknown")
        confidence_details = []
        confidence_details.extend(str(r) for r in entry.get("confidence_reasons", []))
        confidence_details.extend(str(l) for l in entry.get("limitations", []))
        if confidence_details:
            detail_items = "".join(f"<li>{html.escape(item)}</li>" for item in confidence_details)
            confidence_html = (
                f'<span class="{confidence_class}">{html.escape(confidence)}</span>'
                f"<details><summary>Details</summary><ul>{detail_items}</ul></details>"
            )
        else:
            confidence_html = f'<span class="{confidence_class}">{html.escape(confidence)}</span>'

        tool_names = ", ".join(entry.get("tool_names", [])) or "unknown"
        command_cell = (
            f"<code>{html.escape(str(entry.get('command_name', 'unknown')))}</code>"
            f'<br><span class="muted">{html.escape(tool_names)}</span>'
        )
        action = html.escape(str(entry.get("recommended_action", "investigate")))
        action_override = entry.get("action_override")
        action_html = f"<code>{action}</code>"
        if isinstance(action_override, dict):
            original = html.escape(str(action_override.get("original_action", "")))
            reason = html.escape(str(action_override.get("reason", "")))
            action_html += (
                f"<details><summary>Registry override</summary>"
                f"<p>Suppressed <code>{original}</code>. {reason}</p></details>"
            )
        score = float(entry.get("score", 0.0))
        row_class = "row-high-failure" if score >= 70 else ("row-medium-failure" if score >= 40 else "")
        rows.append(f"""
        <tr class="{row_class}">
            <td>{command_cell}</td>
            <td data-sort="{score:.2f}"><strong>{score:.1f}</strong></td>
            <td data-sort="{int(entry.get('total_executions', 0))}">{int(entry.get('total_executions', 0))}</td>
            <td>{drivers_html}</td>
            <td>{confidence_html}</td>
            <td>{action_html}</td>
        </tr>
        """)

    coverage = summary.get("data_coverage", {})
    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Commands scored:</strong> {summary.get('commands_scored', len(commands))}</p>
        <p><strong>Top score:</strong> {float(summary.get('top_score', 0.0)):.1f}</p>
        <p><strong>Coverage:</strong> duration on {coverage.get('commands_with_duration', 0)} command(s),
        callback data on {coverage.get('commands_with_callback_data', 0)}, argument features on {coverage.get('commands_with_argument_features', 0)}</p>
    </div>
    """
    table = f"""
    <div class="table-wrap">
    <table class="sortable">
        <thead>
            <tr>
                <th>Command / Tool</th>
                <th>Score</th>
                <th>Executions</th>
                <th>Drivers</th>
                <th>Confidence</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
    </div>
    """
    return _collapsible_section("Top Friction Candidates", summary_html + table)


def _render_command_retry_success(data: dict, mythic_base_url: str = "") -> str:
    """Render command retry success patterns as HTML."""
    retry_patterns = data.get("retry_patterns", [])
    summary = data.get("summary", {})

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Total retry sequences:</strong> {summary.get('total_retry_sequences', 0)}</p>
        <p><strong>Commands with retries:</strong> {', '.join(summary.get('commands_with_retries', [])) or 'None'}</p>
        <p><strong>Average retries to success:</strong> {summary.get('avg_retries_to_success', 0):.1f}</p>
        <p><strong>Most retried command:</strong> {summary.get('most_retried_command', 'N/A')}</p>
    </div>
    """

    if not retry_patterns:
        return _collapsible_section("Command Retry Success", f"{summary_html}<p>No retry patterns detected.</p>")

    rows = []
    for pattern in retry_patterns:
        cmd_name = pattern["command_name"]
        attempt_count = pattern["attempt_count"]
        time_span = pattern["time_span_seconds"]
        final_status = pattern["final_status"]
        # Add argument changes section - prefer structured format if available
        structured_changes = pattern.get("argument_changes_structured", [])

        # Build per-attempt changed-key hints (new per-transition format only)
        changed_keys_by_attempt: dict[int, set[str]] = {}
        if structured_changes and "from_attempt" in (structured_changes[0] if structured_changes else {}):
            for transition in structured_changes:
                to_attempt = transition.get("to_attempt", 0)
                keys: set[str] = set()
                for c in transition.get("changes", []):
                    top_key = c.get("path", "").split("[")[0].split(".")[0]
                    if top_key:
                        keys.add(top_key)
                if keys:
                    changed_keys_by_attempt[to_attempt] = keys

        attempts = pattern.get("attempts", [])
        # Fallback to timestamps/task_ids if attempts not present (older data without display_id)
        if not attempts:
            timestamps = pattern.get("timestamps", [])
            task_ids = pattern.get("task_ids", [])
            timestamp_details = "<ul>" + "".join(
                f"<li>Attempt {i+1} ({_task_link(mythic_base_url, tid)}): {_ts_html(ts)}</li>"
                for i, (tid, ts) in enumerate(zip(task_ids, timestamps))
            ) + "</ul>"
        else:
            timestamp_details = "<ul>" + "".join(
                _format_attempt_detail(i, a, mythic_base_url, cmd_name, changed_keys=changed_keys_by_attempt.get(i + 1))
                for i, a in enumerate(attempts)
            ) + "</ul>"

        comparison_notes = pattern.get("argument_comparison_notes", [])
        comparison_unknown = pattern.get("argument_comparison_unknown", False)
        notes_html = ""
        if comparison_notes:
            notes_html = "<ul>" + "".join(
                f"<li>{html.escape(note)}</li>" for note in comparison_notes
            ) + "</ul>"

        if structured_changes:
            arg_changes_html = f"""
                <p><strong>Parameter changes:</strong></p>
                {_format_structured_diff(structured_changes)}
            """
            if notes_html:
                arg_changes_html += f"""
                <p><strong>Comparison notes:</strong></p>
                {notes_html}
                """
        else:
            # Fall back to legacy format
            arg_changes = pattern.get("argument_changes", [])
            if arg_changes:
                arg_changes_html = "<p><strong>Parameter changes:</strong></p><ul>" + "".join(
                    f"<li>{html.escape(change)}</li>" for change in arg_changes
                ) + "</ul>"
                if notes_html:
                    arg_changes_html += f"""
                    <p><strong>Comparison notes:</strong></p>
                    {notes_html}
                    """
            elif comparison_unknown:
                arg_changes_html = """
                <p><strong>Parameter changes:</strong> Unknown due to retention policy.</p>
                """
                if notes_html:
                    arg_changes_html += notes_html
            elif notes_html:
                arg_changes_html = """
                <p><strong>Parameter changes:</strong> No changes detected.</p>
                <p><strong>Comparison notes:</strong></p>
                """ + notes_html
            else:
                arg_changes_html = "<p><strong>Parameter changes:</strong> None (same arguments retried)</p>"

        # Add intervening commands section
        intervening = pattern.get("intervening_commands", [])
        intervening_html = ""
        if intervening:
            intervening_items = []
            for cmd in intervening:
                task_ref = _task_link(mythic_base_url, cmd["task_id"], cmd.get("display_id") or None)
                ts_display = _ts_html(cmd["timestamp"]) if cmd.get("timestamp") else ""
                status = cmd.get("status", "unknown")
                status_badge = f' <span class="status-{status}">({status})</span>' if status else ""
                command_name = cmd.get("command_name", "")
                full_command = _format_full_command(
                    command_name,
                    cmd.get("arguments_raw", ""),
                    event=cmd,
                )

                # Highlight certain "fix" commands that are likely relevant
                highlight_commands = {"rev2self", "make_token", "steal_token", "getprivs", "getsystem"}
                if command_name in highlight_commands:
                    full_command = f"<strong>{html.escape(full_command)}</strong>"
                else:
                    full_command = html.escape(full_command)

                intervening_items.append(
                    f"<li>{task_ref}: <code>{full_command}</code>{status_badge} &mdash; {ts_display}</li>"
                )

            intervening_html = f"""
                <p><strong>Operations between retries:</strong></p>
                <ul style="font-size: 0.9em;">{"".join(intervening_items)}</ul>
            """

        rows.append(f"""
        <tr>
            <td>{html.escape(cmd_name)}</td>
            <td>{attempt_count}</td>
            <td data-sort="{time_span}">{time_span:.1f}s</td>
            <td>{html.escape(final_status)}</td>
            <td>
                <details>
                    <summary>View attempts</summary>
                    {timestamp_details}
                    {arg_changes_html}
                    {intervening_html}
                </details>
            </td>
        </tr>
        """)

    table = f"""
    <div class="table-wrap">
    <table class="sortable">
        <thead>
            <tr>
                <th>Command</th>
                <th>Attempts</th>
                <th>Time Span</th>
                <th>Final Status</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
    </div>
    """

    return _collapsible_section("Command Retry Success", f"{summary_html}{table}")


def _render_task_context(task_id: int, outlier_context_map: dict, mythic_base_url: str = "") -> str:
    """Render task context for an outlier (preceding/following commands).

    Returns HTML string with context information, or empty string if no context available.
    """
    if not outlier_context_map or task_id not in outlier_context_map:
        return ""

    outlier = outlier_context_map[task_id]
    preceding_ctx = outlier.get("preceding_context", [])
    following_ctx = outlier.get("following_context", [])

    if not preceding_ctx and not following_ctx:
        return ""

    # Helper to format a context item
    def _fmt_ctx_item(c: dict) -> str:
        dur = f", {c['duration_seconds']:.2f}s" if c.get("duration_seconds") is not None else ""
        full_command = _format_full_command(
            c['command_name'],
            c.get('arguments_raw', ''),
            max_length=80,
            event=c,
        )
        return f"<code>{html.escape(full_command)}</code> ({_task_link(mythic_base_url, c['task_id'], c.get('display_id') or None)}{dur})"

    # Build context HTML
    context_parts = []

    # Show up to 3 preceding commands
    if preceding_ctx:
        ctx_limit = 3
        show_preceding = preceding_ctx[-ctx_limit:] if len(preceding_ctx) > ctx_limit else preceding_ctx
        preceding_items = "".join(f"<li>{_fmt_ctx_item(c)}</li>" for c in show_preceding)

        if len(preceding_ctx) > ctx_limit:
            hidden_count = len(preceding_ctx) - ctx_limit
            hidden_preceding = preceding_ctx[:-ctx_limit]
            hidden_items = "".join(f"<li>{_fmt_ctx_item(c)}</li>" for c in hidden_preceding)
            preceding_html = f"""
            <p><strong>Preceding:</strong></p>
            <ol reversed start="{len(preceding_ctx)}">{preceding_items}</ol>
            <details>
                <summary>+{hidden_count} earlier</summary>
                <ol reversed start="{len(hidden_preceding)}">{hidden_items}</ol>
            </details>
            """
        else:
            preceding_html = f'<p><strong>Preceding:</strong></p><ol reversed start="{len(preceding_ctx)}">{preceding_items}</ol>'
        context_parts.append(preceding_html)

    # Show up to 3 following commands
    if following_ctx:
        ctx_limit = 3
        show_following = following_ctx[:ctx_limit] if len(following_ctx) > ctx_limit else following_ctx
        following_items = "".join(f"<li>{_fmt_ctx_item(c)}</li>" for c in show_following)

        if len(following_ctx) > ctx_limit:
            hidden_count = len(following_ctx) - ctx_limit
            hidden_following = following_ctx[ctx_limit:]
            hidden_items = "".join(f"<li>{_fmt_ctx_item(c)}</li>" for c in hidden_following)
            following_html = f"""
            <p><strong>Following:</strong></p>
            <ol>{following_items}</ol>
            <details>
                <summary>+{hidden_count} later</summary>
                <ol start="{ctx_limit + 1}">{hidden_items}</ol>
            </details>
            """
        else:
            following_html = f'<p><strong>Following:</strong></p><ol>{following_items}</ol>'
        context_parts.append(following_html)

    # Build sequence signature
    sequence_sig = outlier.get("sequence_signature", "")
    if sequence_sig:
        # Truncate for display: 2 before + [outlier] + 2 after
        nearest_preceding = preceding_ctx[-2:] if len(preceding_ctx) > 2 else preceding_ctx
        nearest_following = following_ctx[:2] if len(following_ctx) > 2 else following_ctx
        truncate_left = len(preceding_ctx) > 2
        truncate_right = len(following_ctx) > 2

        sig_parts = []
        if truncate_left:
            sig_parts.append("...")
        sig_parts.extend(c["command_name"] for c in nearest_preceding)
        sig_parts.append(f"[{outlier['command_name']}]")
        sig_parts.extend(c["command_name"] for c in nearest_following)
        if truncate_right:
            sig_parts.append("...")
        signature_display = " -> ".join(sig_parts)
        context_parts.append(f'<p><strong>Sequence:</strong> <code>{html.escape(signature_display)}</code></p>')

    return '<div class="outlier-context">' + "".join(context_parts) + '</div>'


def _render_command_duration(data: dict, mythic_base_url: str = "", outlier_context_data: dict | None = None) -> str:
    """Render command duration statistics as HTML."""
    durations = data.get("durations", {})

    if not durations:
        return _collapsible_section("Command Duration", "<p>No duration data available.</p>")

    # Build outlier context map (task_id -> outlier data)
    outlier_context_map = {}
    aggregations_html = ""
    if outlier_context_data:
        outliers = outlier_context_data.get("outliers", [])
        for outlier in outliers:
            outlier_context_map[outlier["task_id"]] = outlier

        # Build aggregation summary if we have outliers
        aggregations = outlier_context_data.get("aggregations", {})
        if aggregations and outliers:
            preceding = aggregations.get("most_common_preceding_command", {})
            following = aggregations.get("most_common_following_command", {})
            chains = aggregations.get("most_common_3step_chains", {})

            top_preceding = max(preceding.items(), key=lambda x: x[1])[0] if preceding else "N/A"
            top_following = max(following.items(), key=lambda x: x[1])[0] if following else "N/A"
            top_chain = max(chains.items(), key=lambda x: x[1]) if chains else None
            top_chain_str = f"{html.escape(top_chain[0])} ({top_chain[1]}x)" if top_chain else "N/A"

            aggregations_html = f"""
            <div class="summary-stats">
                <p><strong>Outlier Context Patterns ({len(outliers)} outliers enriched):</strong></p>
                <ul>
                    <li>Most common preceding command: <code>{html.escape(top_preceding)}</code></li>
                    <li>Most common following command: <code>{html.escape(top_following)}</code></li>
                    <li>Top 3-step chain: <code>{top_chain_str}</code></li>
                </ul>
            </div>
            """

    # Sort by mean duration descending
    sorted_durations = sorted(
        durations.items(),
        key=lambda x: x[1]["mean_seconds"],
        reverse=True
    )

    rows = []
    for cmd_name, stats in sorted_durations:
        mean = stats["mean_seconds"]
        median = stats["median_seconds"]
        p95 = stats["p95_seconds"]
        max_sec = stats["max_seconds"]
        min_sec = stats["min_seconds"]
        exec_count = stats["execution_count"]
        outlier_count = stats.get("outlier_count", 0)

        # Build outlier details if present
        outlier_details = ""
        if outlier_count > 0:
            outlier_events = stats.get("outlier_events", [])
            outlier_items = []
            for evt in outlier_events:
                task_id = evt['task_id']
                duration = evt['duration_seconds']
                full_command = _format_duration_row_command(evt, evt.get("command_name", ""))

                # Add context if available
                context_html = _render_task_context(task_id, outlier_context_map, mythic_base_url)

                outlier_items.append(
                    f"<li>{_task_link(mythic_base_url, task_id, evt.get('display_id') or None)}: "
                    f"{duration:.2f}s - <code>{html.escape(full_command)}</code>"
                    f"{context_html}</li>"
                )

            outlier_list = "<ul>" + "".join(outlier_items) + "</ul>"
            outlier_details = f"""
            <details>
                <summary>{outlier_count} outliers</summary>
                {outlier_list}
            </details>
            """

        # Build max event details
        max_event = stats.get("max_event") or {}
        # Format full command with arguments (PTY synthetics nested under pty_in_session)
        full_command = _format_duration_row_command(max_event, cmd_name, max_length=150)
        task_id = max_event.get('task_id', 'N/A')
        display_id = max_event.get('display_id') or None
        duration_seconds = max_event.get('duration_seconds', 0)
        max_details = f"""
        <details>
            <summary>Max event</summary>
            <p><strong>Task ID:</strong> {_task_link(mythic_base_url, task_id, display_id)}</p>
            <p><strong>Duration:</strong> {duration_seconds:.2f}s</p>
            <p><strong>Command:</strong> <code>{html.escape(full_command)}</code></p>
        </details>
        """

        # Table "Command Name": show slowest nested shell line for PTY bucket (max duration row)
        name_cell = html.escape(cmd_name)
        if cmd_name == "pty_in_session" and max_event.get("pty_shell_command"):
            peak = _format_full_command(
                max_event["pty_shell_command"],
                max_event.get("arguments_raw", ""),
                max_length=100,
                event=max_event,
            )
            name_cell = (
                f"{html.escape(cmd_name)}<br>"
                f'<span class="text-muted" style="font-size:0.9em">slowest line: {html.escape(peak)}</span>'
            )

        rows.append(f"""
        <tr>
            <td>{name_cell}</td>
            <td>{exec_count}</td>
            <td class="col-extra" data-sort="{mean}">{mean:.2f}s</td>
            <td data-sort="{median}">{median:.2f}s</td>
            <td data-sort="{p95}">{p95:.2f}s</td>
            <td data-sort="{max_sec}">{max_sec:.2f}s</td>
            <td class="col-extra" data-sort="{min_sec}">{min_sec:.2f}s</td>
            <td class="col-extra" data-sort="{outlier_count}">{outlier_details or 'None'}</td>
            <td class="col-extra">{max_details}</td>
        </tr>
        """)

    table = f"""
    <button class="toggle-cols-btn" onclick="toggleExtraCols(this)">Show all columns</button>
    <div class="table-wrap">
    <table class="sortable">
        <thead>
            <tr>
                <th>Command Name</th>
                <th>Executions</th>
                <th class="col-extra">Mean</th>
                <th>Median</th>
                <th>P95</th>
                <th>Max</th>
                <th class="col-extra">Min</th>
                <th class="col-extra">Outliers</th>
                <th class="col-extra">Max Event</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
    </div>
    """

    content = f"<p>Commands sorted by mean duration (slowest first).</p>{aggregations_html}{table}"
    return _collapsible_section("Command Duration", content)


def _render_outlier_context(data: dict, mythic_base_url: str = "") -> str:
    """Render outlier context analysis as HTML."""
    outliers = data.get("outliers", [])
    aggregations = data.get("aggregations", {})

    # Build summary from aggregations
    preceding = aggregations.get("most_common_preceding_command", {})
    following = aggregations.get("most_common_following_command", {})
    chains = aggregations.get("most_common_3step_chains", {})

    top_preceding = max(preceding.items(), key=lambda x: x[1])[0] if preceding else "N/A"
    top_following = max(following.items(), key=lambda x: x[1])[0] if following else "N/A"
    top_chain = max(chains.items(), key=lambda x: x[1]) if chains else None
    top_chain_str = f"{html.escape(top_chain[0])} ({top_chain[1]}x)" if top_chain else "N/A"

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Outliers enriched:</strong> {len(outliers)}</p>
        <p><strong>Most common preceding command:</strong> {html.escape(top_preceding)}</p>
        <p><strong>Most common following command:</strong> {html.escape(top_following)}</p>
        <p><strong>Top 3-step chain:</strong> {top_chain_str}</p>
    </div>
    """

    if not outliers:
        return _collapsible_section("Outlier Context", f"{summary_html}<p>No outliers detected.</p>")

    rows = []
    for outlier in outliers:
        task_id = outlier["task_id"]
        display_id = outlier.get("display_id") or None
        cmd_name = outlier["command_name"]
        duration = outlier["duration_seconds"]
        preceding_ctx = outlier.get("preceding_context", [])
        following_ctx = outlier.get("following_context", [])

        # Truncate signature: 2 before + [outlier] + 2 after
        nearest_preceding = preceding_ctx[-2:] if len(preceding_ctx) > 2 else preceding_ctx
        nearest_following = following_ctx[:2] if len(following_ctx) > 2 else following_ctx
        truncate_left = len(preceding_ctx) > 2
        truncate_right = len(following_ctx) > 2

        sig_parts = []
        if truncate_left:
            sig_parts.append("...")
        sig_parts.extend(c["command_name"] for c in nearest_preceding)
        sig_parts.append(f"[{cmd_name}]")
        sig_parts.extend(c["command_name"] for c in nearest_following)
        if truncate_right:
            sig_parts.append("...")
        signature_display = " -> ".join(sig_parts) if sig_parts else html.escape(cmd_name)

        # Context: limit to 3 nearest each side, compact format, "show all" if more
        ctx_limit = 3
        show_preceding = preceding_ctx[-ctx_limit:] if len(preceding_ctx) > ctx_limit else preceding_ctx
        show_following = following_ctx[:ctx_limit] if len(following_ctx) > ctx_limit else following_ctx
        has_more_preceding = len(preceding_ctx) > ctx_limit
        has_more_following = len(following_ctx) > ctx_limit

        def _fmt_ctx_item(c: dict) -> str:
            dur = f", {c['duration_seconds']:.2f}s" if c.get("duration_seconds") is not None else ""
            full_command = _format_full_command(
                c['command_name'],
                c.get('arguments_raw', ''),
                max_length=80,
                event=c,
            )
            return f"<code>{html.escape(full_command)}</code> ({_task_link(mythic_base_url, c['task_id'], c.get('display_id') or None)}{dur})"

        preceding_items = "".join(
            f"<li>{_fmt_ctx_item(c)}</li>" for c in show_preceding
        )
        following_items = "".join(
            f"<li>{_fmt_ctx_item(c)}</li>" for c in show_following
        )

        context_html = ""
        if preceding_items:
            context_html += f"<p><strong>Preceding:</strong></p><ol>{preceding_items}</ol>"
        if following_items:
            context_html += f"<p><strong>Following:</strong></p><ol>{following_items}</ol>"

        extra_html = ""
        if has_more_preceding or has_more_following:
            hidden_preceding = preceding_ctx[: -ctx_limit] if has_more_preceding else []
            hidden_following = following_ctx[ctx_limit:] if has_more_following else []
            hidden_items = []
            for c in hidden_preceding:
                hidden_items.append(f"<li>{_fmt_ctx_item(c)}</li>")
            if hidden_items:
                extra_html += f"<p><strong>Earlier preceding:</strong></p><ol>{''.join(hidden_items)}</ol>"
            hidden_items = []
            for c in hidden_following:
                hidden_items.append(f"<li>{_fmt_ctx_item(c)}</li>")
            if hidden_items:
                extra_html += f"<p><strong>Later following:</strong></p><ol>{''.join(hidden_items)}</ol>"

        if extra_html:
            context_html += f"<details><summary>Show all ({len(preceding_ctx) + len(following_ctx)} tasks)</summary>{extra_html}</details>"

        rows.append(f"""
        <tr>
            <td>{_task_link(mythic_base_url, task_id, display_id)}</td>
            <td>{html.escape(cmd_name)}</td>
            <td>{duration:.2f}s</td>
            <td class="args-display">{html.escape(signature_display)}</td>
            <td>
                <details>
                    <summary>View context</summary>
                    {context_html}
                </details>
            </td>
        </tr>
        """)

    table = f"""
    <div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th>Task ID</th>
                <th>Command</th>
                <th>Duration</th>
                <th>Sequence Signature</th>
                <th>Context Window</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
    </div>
    """

    content = f"<p>Duration outliers enriched with surrounding command context (&plusmn;5 tasks).</p>{summary_html}{table}"
    return _collapsible_section("Outlier Context", content)


def _render_callback_health(data: dict, mythic_base_url: str = "") -> str:
    """Render callback health analysis as HTML."""
    callbacks = data.get("callbacks", {})
    summary = data.get("summary", {})

    consecutive_failures = summary.get('callbacks_with_consecutive_failures', 0)
    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Total callbacks:</strong> {summary.get('total_callbacks', 0)}</p>
        <p><strong>Callbacks with consecutive failures (3+):</strong> {consecutive_failures}</p>
    </div>
    """

    if not callbacks:
        return _collapsible_section("Callback Health", f"{summary_html}<p>No callback data available.</p>")

    # Sort by consecutive failures (descending), then by task count (descending)
    sorted_callbacks = sorted(
        callbacks.items(),
        key=lambda x: (
            -x[1].get("consecutive_failure_count", 0),
            -x[1].get("task_count", 0),
        ),
    )

    def _build_cb_row(cb_id: str, info: dict) -> str:
        has_consecutive = info.get("has_consecutive_failures", False)
        consecutive_count = info.get("consecutive_failure_count", 0)

        # Highlight callbacks with consecutive failures (yellow/orange, not red)
        if has_consecutive:
            row_class = "row-consecutive-failures"
        else:
            row_class = ""

        first_ts = info.get("first_task_timestamp", "")
        last_ts = info.get("last_task_timestamp", "")
        if first_ts and last_ts:
            duration_str = _format_duration_from_timestamps(first_ts, last_ts)
            tooltip = f"{first_ts} -> {last_ts}"
            active_period_html = (
                f'<abbr title="{html.escape(tooltip)}">{html.escape(duration_str)}</abbr>'
            )
        elif first_ts:
            active_period_html = f"<small>{_ts_html(first_ts)}</small>"
        else:
            active_period_html = "<em>N/A</em>"

        last_success = info.get("last_successful_task")
        trailing = info.get("trailing_failures", [])

        # Build trailing failures display (show count and expandable details)
        if trailing:
            warning_badge = ' <span class="consecutive-failure-warning">⚠</span>' if has_consecutive else ""
            inline_limit = 3
            shown = trailing[:inline_limit]
            trailing_items = []
            for tf in shown:
                full_command = _format_full_command(
                    tf.get("command_name", ""),
                    tf.get("arguments_raw", ""),
                    event=tf,
                )
                trailing_items.append(
                    f"<li>{_task_link(mythic_base_url, tf['task_id'], tf.get('display_id') or None)}: "
                    f"<code>{html.escape(full_command)}</code>"
                    f' <span class="status-{tf["status"]}">({tf["status"]})</span>'
                    f" &mdash; {_ts_html(tf.get('timestamp', ''))}</li>"
                )
            all_trailing_items = list(trailing_items)
            for tf in trailing[inline_limit:]:
                full_command = _format_full_command(
                    tf.get("command_name", ""),
                    tf.get("arguments_raw", ""),
                    event=tf,
                )
                all_trailing_items.append(
                    f"<li>{_task_link(mythic_base_url, tf['task_id'], tf.get('display_id') or None)}: "
                    f"<code>{html.escape(full_command)}</code>"
                    f' <span class="status-{tf["status"]}">({tf["status"]})</span>'
                    f" &mdash; {_ts_html(tf.get('timestamp', ''))}</li>"
                )
            trailing_html = (
                f"{consecutive_count}{warning_badge}"
                f"<details><summary>View failures</summary>"
                f"<ul>{''.join(all_trailing_items)}</ul>"
                f"</details>"
            )
        else:
            trailing_html = "0"

        # Build last success display
        if last_success:
            full_command = _format_full_command(
                last_success.get('command_name', ''),
                last_success.get('arguments_raw', ''),
                event=last_success,
            )
            last_success_html = (
                f"{_task_link(mythic_base_url, last_success['task_id'], last_success.get('display_id') or None)}: "
                f"<code>{html.escape(full_command)}</code>"
                f"<br><small>{_ts_html(last_success.get('timestamp', ''))}</small>"
            )
        else:
            last_success_html = "<em>None</em>"

        # Build visual completion rate bar
        completion_rate = info['completion_rate']
        completion_pct = f"{completion_rate:.1%}"
        bar_width_pct = int(completion_rate * 100)
        completion_bar = f"""
        <div style="display: flex; align-items: center; gap: 8px;">
            <span>{completion_pct}</span>
            <div style="flex: 1; min-width: 100px; height: 20px; background: #e0e0e0; border-radius: 4px; overflow: hidden;">
                <div style="width: {bar_width_pct}%; height: 100%; background: #05ce8b; transition: width 0.3s;"></div>
            </div>
        </div>
        """

        return f"""
        <tr class="{row_class}">
            <td>{_cb_link(mythic_base_url, str(cb_id), info.get('callback_display_id') or None)}<br>{active_period_html}</td>
            <td>{info['task_count']}</td>
            <td>{info['success_count']}</td>
            <td>{info['error_count']}</td>
            <td>{info['unknown_count']}</td>
            <td data-sort="{info['completion_rate']}">{completion_bar}</td>
            <td>{last_success_html}</td>
            <td data-sort="{consecutive_count}">{trailing_html}</td>
        </tr>
        """

    header_row = """
            <tr>
                <th>Callback ID / Active Period</th>
                <th>Tasks</th>
                <th>Success</th>
                <th>Error</th>
                <th>Unknown</th>
                <th>Completion Rate</th>
                <th>Last Successful Task</th>
                <th>Trailing Failures</th>
            </tr>"""

    all_rows = "".join(_build_cb_row(cid, info) for cid, info in sorted_callbacks)
    main_table = f"""
    <div class="table-wrap">
    <table class="sortable">
        <thead>{header_row}
        </thead>
        <tbody>
            {all_rows}
        </tbody>
    </table>
    </div>
    """

    content = f"""
        <p>Per-callback task execution statistics. Callbacks with 3+ consecutive failures may indicate crashes or hangs.</p>
        {summary_html}
        {main_table}
    """
    return _collapsible_section("Callback Health", content)


def _render_av_tracker(data: dict, mythic_base_url: str = "") -> str:
    """Render AV tracker detections as HTML."""
    summary = data.get("summary", {})
    vendors = data.get("vendors", {})
    detections = data.get("detections", [])
    registry = data.get("registry", {})

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>`ps` results scanned:</strong> {summary.get('ps_tasks_scanned', 0)}</p>
        <p><strong>Matching `ps` outputs:</strong> {summary.get('matching_ps_outputs', 0)}</p>
        <p><strong>Detections:</strong> {summary.get('detection_count', 0)}</p>
        <p><strong>Callbacks with detections:</strong> {summary.get('callbacks_with_detections', 0)}</p>
    </div>
    <p class="muted">Registry: {html.escape(str(registry.get('path', 'unknown')))} | Vendors loaded: {registry.get('vendor_count', 0)}</p>
    """

    vendor_rows = []
    for vendor_key, vendor in sorted(vendors.items()):
        if vendor.get("detection_count", 0) <= 0:
            continue
        matched_execs = [
            f"<code>{html.escape(exe_name)}</code> ({count})"
            for exe_name, count in sorted(vendor.get("executables", {}).items())
            if count > 0
        ]
        vendor_rows.append(
            "<tr>"
            f"<td>{html.escape(vendor.get('display_name', vendor_key))}</td>"
            f"<td>{vendor.get('detection_count', 0)}</td>"
            f"<td>{len(vendor.get('callbacks', []))}</td>"
            f"<td>{', '.join(matched_execs) if matched_execs else '<em>None</em>'}</td>"
            "</tr>"
        )

    if vendor_rows:
        vendor_table = f"""
        <div class="table-wrap">
        <table class="sortable">
            <thead>
                <tr>
                    <th>Vendor</th>
                    <th>Detections</th>
                    <th>Callbacks</th>
                    <th>Matched Executables</th>
                </tr>
            </thead>
            <tbody>
                {''.join(vendor_rows)}
            </tbody>
        </table>
        </div>
        """
    else:
        vendor_table = "<p>No AV detections found.</p>"

    detection_rows = []
    for detection in detections:
        detection_rows.append(
            "<tr>"
            f"<td>{html.escape(detection.get('vendor_name', ''))}</td>"
            f"<td>{', '.join(f'<code>{html.escape(name)}</code>' for name in detection.get('matched_executables', []))}</td>"
            f"<td>{detection.get('occurrence_count', 1)}</td>"
            f"<td>{_cb_link(mythic_base_url, detection.get('callback_id', 0), detection.get('callback_display_id') or None)}</td>"
            f"<td>{_task_link(mythic_base_url, detection.get('task_id', 0), detection.get('display_id') or None)}</td>"
            f"<td>{html.escape(detection.get('status', ''))}</td>"
            f"<td>{_ts_html(detection.get('timestamp', ''))}</td>"
            "</tr>"
        )

    if detection_rows:
        detection_table = f"""
        <div class="table-wrap">
        <table class="sortable">
            <thead>
                <tr>
                    <th>Vendor</th>
                    <th>Executables</th>
                    <th>Scans</th>
                    <th>Callback</th>
                    <th>Task</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {''.join(detection_rows)}
            </tbody>
        </table>
        </div>
        """
    else:
        detection_table = "<p class='muted'>No `ps` output matched the AV executable registry.</p>"

    content = f"""
        <p>Detects known AV executables in `ps` command output using a YAML-backed signature registry.</p>
        {summary_html}
        <h3>Vendors</h3>
        {vendor_table}
        <h3>Detections</h3>
        {detection_table}
    """
    return _collapsible_section("AV Tracker", content)


def _render_dwell_time(data: dict, mythic_base_url: str = "") -> str:
    """Render dwell-time workflow friction statistics as HTML."""
    meta = data.get("metadata", {})
    stats = data.get("global_statistics", {})

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Dwell measurements:</strong> {meta.get('dwell_count', 0)}</p>
        <p><strong>Events analyzed:</strong> {meta.get('events_analyzed', 0)}</p>
        <p><strong>Median dwell:</strong> {_fmt_duration(stats.get('median_seconds', 0))}</p>
        <p><strong>P95 dwell:</strong> {_fmt_duration(stats.get('p95_seconds', 0))}</p>
        <p><strong>Max dwell:</strong> {_fmt_duration(stats.get('max_seconds', 0))}</p>
    </div>
    """

    outliers = stats.get("outlier_events", [])
    if not outliers:
        return _collapsible_section("Dwell Time", f"{summary_html}<p>No dwell-time outliers detected.</p>")

    rows = []
    for outlier in outliers:
        from_cmd = _format_full_command(
            outlier.get("from_command", ""),
            outlier.get("from_arguments_raw", ""),
            max_length=120,
            event=outlier,
            prefix="from_",
        )
        to_cmd = _format_full_command(
            outlier.get("to_command", ""),
            outlier.get("to_arguments_raw", ""),
            max_length=120,
            event=outlier,
            prefix="to_",
        )
        rows.append(f"""
        <tr>
            <td>{_task_link(mythic_base_url, outlier.get('from_task_id', '?'), outlier.get('from_display_id') or None)}</td>
            <td><code>{html.escape(from_cmd)}</code><br><small>{_ts_html(outlier.get('from_timestamp', ''))}</small></td>
            <td>{_task_link(mythic_base_url, outlier.get('to_task_id', '?'), outlier.get('to_display_id') or None)}</td>
            <td><code>{html.escape(to_cmd)}</code><br><small>{_ts_html(outlier.get('to_timestamp', ''))}</small></td>
            <td data-sort="{outlier.get('dwell_seconds', 0)}">{_fmt_duration(outlier.get('dwell_seconds', 0))}</td>
        </tr>
        """)

    table = f"""
    <div class="table-wrap">
    <table class="sortable">
        <thead>
            <tr>
                <th>Earlier Task</th>
                <th>Earlier Command</th>
                <th>Later Task</th>
                <th>Later Command</th>
                <th>Dwell</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
    </div>
    """

    content = f"""
        <p>Measures the gap between consecutive operator commands to surface workflow friction and long pauses.</p>
        {summary_html}
        {table}
    """
    return _collapsible_section("Dwell Time", content)


def _render_parameter_entropy(data: dict, mythic_base_url: str = "") -> str:
    """Render parameter entropy and structural anomaly findings as HTML."""
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    repeated = data.get("repeated_high_entropy", [])

    type_counts = summary.get("by_type", {})
    type_list = "".join(
        f"<li><code>{html.escape(str(kind))}</code>: {count}</li>"
        for kind, count in sorted(type_counts.items())
    ) or "<li>No findings by type.</li>"

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Total findings:</strong> {summary.get('total_findings', 0)}</p>
        <p><strong>Tasks with findings:</strong> {summary.get('tasks_with_findings', 0)}</p>
        <p><strong>Repeated high-entropy tokens:</strong> {summary.get('repeated_high_entropy_tokens', 0)}</p>
        <ul>{type_list}</ul>
    </div>
    """

    repeated_html = ""
    if repeated:
        repeated_items = []
        for item in repeated:
            commands = ", ".join(html.escape(cmd) for cmd in item.get("commands", []))
            repeated_items.append(
                f"<li><code>{html.escape(item.get('token_prefix', ''))}...</code> "
                f"appears {item.get('occurrences', 0)} times"
                + (f" across <code>{commands}</code>" if commands else "")
                + "</li>"
            )
        repeated_html = f"""
        <details>
            <summary>Repeated high-entropy tokens</summary>
            <ul>{"".join(repeated_items)}</ul>
        </details>
        """

    if not findings:
        return _collapsible_section("Parameter Entropy", f"{summary_html}<p>No anomalous parameters detected.</p>")

    rows = []
    for finding in findings[:100]:
        task_ref = _task_link(mythic_base_url, finding.get("task_id", "?"), finding.get("display_id") or None)
        entropy = finding.get("token_entropy")
        entropy_display = f"{entropy:.2f}" if isinstance(entropy, (int, float)) else "<em>N/A</em>"
        rows.append(f"""
        <tr>
            <td>{task_ref}</td>
            <td class="wrap-cell">{_wrap_cell_text(finding.get('command_name', ''))}</td>
            <td><code>{html.escape(str(finding.get('finding_type', '')))}</code></td>
            <td>{entropy_display}</td>
            <td class="wrap-cell">{_wrap_cell_text(finding.get('detail', ''))}</td>
            <td>{_fmt_args_cell(finding.get('arguments_raw', ''), event=finding)}</td>
        </tr>
        """)

    overflow_note = ""
    if len(findings) > 100:
        overflow_note = f"<p><em>Showing first 100 findings of {len(findings)} total.</em></p>"

    table = f"""
    <div class="table-wrap">
    <table class="sortable wide-table">
        <thead>
            <tr>
                <th>Task</th>
                <th>Command</th>
                <th>Finding Type</th>
                <th>Entropy</th>
                <th>Detail</th>
                <th>Arguments</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
    </div>
    """

    content = f"""
        <p>Flags structurally anomalous arguments such as high-entropy blobs, wildcard-heavy paths, regex-like syntax, and oversized parameter lists.</p>
        {summary_html}
        {repeated_html}
        {overflow_note}
        {table}
    """
    return _collapsible_section("Parameter Entropy", content)


def _format_argument_profile_command_label(cmd_name: str) -> str:
    """Human-readable label for per_command keys (PTY synthetics use pty_in_session::shell)."""
    if cmd_name.startswith("pty_in_session::"):
        shell = cmd_name.split("::", 1)[1]
        return f"PTY ▸ {html.escape(shell)}"
    return html.escape(cmd_name)


def _render_argument_position_profile(data: dict, base_url: str = "") -> str:
    """Render argument position profiling and findings as HTML."""
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    depth_dist = data.get("depth_distribution", [])
    per_command = data.get("per_command", {})

    total_findings = summary.get("total_findings", 0)

    has_pty_shell_keys = any(str(k).startswith("pty_in_session::") for k in per_command.keys())
    pty_key_note = ""
    if has_pty_shell_keys:
        pty_key_note = (
            "<p><strong>PTY in-session:</strong> each typed shell command has its own profile "
            "(keys like <code>pty_in_session::cd</code>). This is separate from the "
            "<code>pty_in_session</code> roll-up used in duration metrics.</p>"
        )

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Commands profiled:</strong> {summary.get('commands_profiled', 0)}</p>
        <p><strong>Tasks with arguments:</strong> {summary.get('tasks_with_arguments', 0)} / {summary.get('total_tasks', 0)}</p>
        <p><strong>Max argument depth:</strong> {summary.get('max_depth_observed', 0)}</p>
        <p><strong>Mean argument depth:</strong> {summary.get('mean_argument_depth', 0)}</p>
        <p><strong>Positions profiled:</strong> {summary.get('positions_profiled', 0)}</p>
        <p><strong>Findings:</strong> {total_findings}</p>
        {pty_key_note}
    </div>
    """

    if not findings and not depth_dist and not per_command:
        return _collapsible_section(
            "Argument Position Profile",
            f"{summary_html}<p>No tasks with arguments found.</p>",
            open_by_default=False,
        )

    # --- Findings table ---
    # Build a concise detail string per finding type from structured fields
    def _finding_detail(f: dict) -> str:
        t = f.get("type")
        if t == "static_argument":
            expected = f.get("expected", False)
            label = (
                f"always <code>{html.escape(str(f.get('value', '')))}</code> &mdash; "
                f"{f.get('occurrences', 0)}/{f.get('tasks_at_position', 0)} tasks "
                f"({f.get('fraction', 0):.0%})"
            )
            if expected:
                label += ' <span class="expected-badge">expected</span>'
            return label
        if t == "unexpected_static_deviation":
            dev_values = f.get("deviating_values", [])
            dev_strs = ", ".join(
                f"<code>{html.escape(d['value'])}</code> ({d['count']}x)"
                for d in dev_values[:3]
            )
            result = (
                f"expected <code>{html.escape(str(f.get('expected_value', '')))}</code> but "
                f"{f.get('deviation_count', 0)}/{f.get('tasks_at_position', 0)} tasks deviate "
                f"({f.get('deviation_pct', 0)}%): {dev_strs}"
            )
            task_refs = f.get("task_refs", [])
            if task_refs:
                ref_links = []
                for ref in task_refs[:10]:
                    cb_id = ref.get("callback_id")
                    cb_display = ref.get("callback_display_id")
                    task_link = _task_link(base_url, ref["task_id"], ref.get("display_id"))
                    cb_part = ""
                    if cb_id:
                        cb_part = f" ({_cb_link(base_url, str(cb_id), cb_display)})"
                    ref_links.append(f"{task_link}{cb_part}")
                refs_html = ", ".join(ref_links)
                if len(task_refs) > 10:
                    refs_html += f" (+{len(task_refs) - 10} more)"
                result += f"<br><small>Tasks: {refs_html}</small>"
            return result
        if t == "high_diversity":
            return (
                f"{f.get('unique_values', 0)} unique values across "
                f"{f.get('tasks_at_position', 0)} tasks "
                f"({f.get('diversity_ratio', 0):.0%} diversity)"
            )
        if t == "depth_anomaly":
            return (
                f"depth {f.get('min_depth', 0)}–{f.get('max_depth', 0)}, "
                f"mean {f.get('mean_depth', 0)}, CV {f.get('cv', 0):.2f}"
            )
        if t == "sparse_trailing":
            return (
                f"{f.get('tasks_at_position', 0)}/{f.get('total_command_tasks', 0)} tasks "
                f"({f.get('reach_pct', 0)}%)"
            )
        return ""

    findings_html = ""
    if findings:
        type_labels = {
            "unexpected_static_deviation": "Deviation",
            "static_argument": "Static Arg",
            "high_diversity": "High Diversity",
            "depth_anomaly": "Depth Anomaly",
            "sparse_trailing": "Sparse Trailing",
        }
        finding_rows = []
        for f in findings[:30]:
            ftype = type_labels.get(f["type"], f["type"])
            cmd = _format_argument_profile_command_label(f.get("command_name", ""))
            pos = f.get("position", "&mdash;")
            detail = _finding_detail(f)
            finding_rows.append(f"""
            <tr>
                <td><code>{ftype}</code></td>
                <td><code>{cmd}</code></td>
                <td>{pos}</td>
                <td>{detail}</td>
            </tr>
            """)
        findings_html = f"""
        <h4>Findings ({total_findings})</h4>
        <div class="table-wrap">
        <table class="sortable">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Command</th>
                    <th>Position</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>
                {"".join(finding_rows)}
            </tbody>
        </table>
        </div>
        """

    # --- Per-command position breakdown ---
    # One collapsible per command showing volume, reach %, and value distribution
    per_command_blocks = []
    for cmd_name, cmd_data in per_command.items():
        task_count = cmd_data.get("task_count", 0)
        positions = cmd_data.get("positions", [])
        if not positions:
            continue
        pos_rows = []
        for p in positions:
            top_vals = " &nbsp;|&nbsp; ".join(
                f"<code>{html.escape(str(v['value']))}</code> {v['count']} ({v['pct']}%)"
                for v in p.get("top_values", [])[:3]
            ) or "&mdash;"
            pos_rows.append(f"""
            <tr>
                <td>#{p['position']}</td>
                <td>{p['tasks_reaching']}</td>
                <td>{p['reach_pct']}%</td>
                <td>{p['unique_values']}</td>
                <td>{top_vals}</td>
            </tr>
            """)
        if cmd_name.startswith("pty_in_session::"):
            title = _format_argument_profile_command_label(cmd_name)
            key_hint = f' <span class="text-muted">(<code>{html.escape(cmd_name)}</code>)</span>'
        else:
            title = f"<code>{html.escape(cmd_name)}</code>"
            key_hint = ""
        per_command_blocks.append(f"""
        <details>
            <summary>{title}{key_hint} &mdash; {task_count} tasks, {len(positions)} positions</summary>
            <div class="table-wrap">
            <table class="sortable">
                <thead>
                    <tr>
                        <th>Position</th>
                        <th>Tasks</th>
                        <th>Reach %</th>
                        <th>Unique Values</th>
                        <th>Top Values</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(pos_rows)}
                </tbody>
            </table>
            </div>
        </details>
        """)

    per_command_html = f"""
    <details>
        <summary>Per-Command Position Breakdown ({len(per_command)} commands)</summary>
        {"".join(per_command_blocks)}
    </details>
    """ if per_command_blocks else ""

    # --- Depth distribution table ---
    depth_rows = []
    for entry in depth_dist[:25]:
        cmd = _format_argument_profile_command_label(entry.get("command_name", ""))
        depth_rows.append(f"""
        <tr>
            <td><code>{cmd}</code></td>
            <td>{entry.get('task_count', 0)}</td>
            <td>{entry.get('min_depth', 0)}</td>
            <td>{entry.get('max_depth', 0)}</td>
            <td>{entry.get('mean_depth', 0)}</td>
            <td>{entry.get('median_depth', 0)}</td>
            <td>{entry.get('stdev_depth', 0)}</td>
        </tr>
        """)

    depth_html = f"""
    <details>
        <summary>Depth Distribution by Command ({len(depth_dist)} commands)</summary>
        <div class="table-wrap">
        <table class="sortable">
            <thead>
                <tr>
                    <th>Command</th>
                    <th>Tasks</th>
                    <th>Min Depth</th>
                    <th>Max Depth</th>
                    <th>Mean</th>
                    <th>Median</th>
                    <th>Stdev</th>
                </tr>
            </thead>
            <tbody>
                {"".join(depth_rows)}
            </tbody>
        </table>
        </div>
    </details>
    """

    content = f"""
    {summary_html}
    <p>Profiles argument structure across all positions and commands. Detects static arguments
    (automation candidates), high-diversity positions (operator improvisation), depth anomalies
    (inconsistent usage), and sparse trailing arguments.</p>
    {findings_html}
    {per_command_html}
    {depth_html}
    """
    return _collapsible_section("Argument Position Profile", content, open_by_default=False)


def _render_tool_dump(data: dict, base_url: str = "") -> str:
    """Render registry-driven task dumps as HTML."""
    summary = data.get("summary", {})
    groups = data.get("groups", [])
    registry = data.get("registry", {})

    summary_html = f"""
    <div class="summary-stats">
        <p><strong>Groups defined:</strong> {summary.get('groups_defined', 0)}</p>
        <p><strong>Groups with matches:</strong> {summary.get('groups_with_matches', 0)}</p>
        <p><strong>Total matches:</strong> {summary.get('total_matches', 0)}</p>
        <p><strong>Registry:</strong> <code>{html.escape(str(registry.get('path', '')))}</code></p>
    </div>
    """

    if not groups:
        return _collapsible_section("Tool Dump", f"{summary_html}<p>No dump groups configured.</p>")

    group_rows = []
    match_rows = []

    for group in groups:
        group_rows.append(f"""
        <tr>
            <td class="wrap-cell">{_wrap_cell_text(group.get('name', ''), use_code=True)}</td>
            <td class="wrap-cell">{_wrap_cell_text(group.get('description', ''))}</td>
            <td>{group.get('match_count', 0)}</td>
            <td>{group.get('unique_command_count', 0)}</td>
            <td class="wrap-cell">{_wrap_cell_text(group.get('dump_path', ''), use_code=True)}</td>
        </tr>
        """)

        for entry in group.get("entries", [])[:25]:
            task_ref = _task_link(base_url, entry.get("task_id", "?"), entry.get("display_id") or None)
            match_rows.append(f"""
            <tr>
                <td class="wrap-cell">{_wrap_cell_text(group.get('name', ''), use_code=True)}</td>
                <td>{task_ref}</td>
                <td class="wrap-cell">{_wrap_cell_text(entry.get('source', ''))}</td>
                <td class="wrap-cell">{_wrap_cell_text(entry.get('tool_name', ''))}</td>
                <td class="wrap-cell">{_wrap_cell_text(entry.get('command_name', ''))}</td>
                <td>{_fmt_args_cell(entry.get('arguments_raw', ''), event=entry)}</td>
            </tr>
            """)

    group_table = f"""
    <div class="table-wrap">
    <table class="sortable wide-table">
        <thead>
            <tr>
                <th>Group</th>
                <th>Description</th>
                <th>Matches</th>
                <th>Unique Commands</th>
                <th>Dump Path</th>
            </tr>
        </thead>
        <tbody>
            {"".join(group_rows)}
        </tbody>
    </table>
    </div>
    """

    matches_html = "<p>No matching tasks found.</p>"
    if match_rows:
        matches_html = f"""
        <div class="table-wrap">
        <table class="sortable wide-table">
            <thead>
                <tr>
                    <th>Group</th>
                    <th>Task</th>
                    <th>Source</th>
                    <th>Tool</th>
                    <th>Command</th>
                    <th>Arguments</th>
                </tr>
            </thead>
            <tbody>
                {"".join(match_rows)}
            </tbody>
        </table>
        </div>
        """

    content = f"""
        <p>Dumps registry-defined command subsets into plain-text files for external tooling and dataset workflows.</p>
        {summary_html}
        {group_table}
        {matches_html}
    """
    return _collapsible_section("Tool Dump", content)


def _get_html_template(report_overview_html: str, body_content: str) -> str:
    """Generate complete HTML document with embedded CSS."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'; object-src 'none'; frame-ancestors 'none'">
    <title>Janus Analysis Report</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
        }}

        h1 {{
            color: #0D0A30;
            border-bottom: 3px solid #05CE8B;
            padding-bottom: 10px;
        }}

        .report-overview-title {{
            margin-top: 0;
            margin-bottom: 16px;
        }}

        .report-overview-title .report-generated-sub {{
            font-size: 0.48em;
            font-weight: 500;
            color: #4a4570;
            white-space: nowrap;
        }}

        @media (max-width: 640px) {{
            .report-overview-title .report-generated-sub {{
                white-space: normal;
                display: block;
                margin-top: 6px;
                font-size: 0.55em;
            }}
        }}

        h2 {{
            color: #2a2550;
            border-bottom: 2px solid #ddd;
            padding-bottom: 8px;
            margin-top: 24px;
        }}

        h3 {{
            color: #2a2550;
            margin: 18px 0 8px;
            font-size: 1.1em;
        }}

        code {{
            background-color: #f0f0f0;
            padding: 1px 5px;
            border-radius: 3px;
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.88em;
            color: #0D0A30;
        }}

        .section-panel {{
            background-color: white;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section-panel > summary {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2a2550;
            padding: 14px 20px;
            cursor: pointer;
            list-style: none;
            display: flex;
            align-items: center;
            border-bottom: 2px solid transparent;
        }}

        .section-panel > summary::-webkit-details-marker {{
            display: none;
        }}

        .section-panel > summary::before {{
            content: '-';
            margin-right: 10px;
            flex-shrink: 0;
        }}

        .section-panel > summary:hover {{
            background-color: #fafafa;
            border-radius: 5px 5px 0 0;
        }}

        .section-panel[open] > summary {{
            border-bottom-color: #eee;
        }}

        .section-body {{
            padding: 4px 20px 20px;
        }}

        .section-static.analyzer-group-summary {{
            background-color: #ffffff;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border: 1px solid #e8e8ed;
        }}

        .analyzer-group-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2a2550;
            padding: 14px 20px 10px;
            margin: 0;
            border-bottom: 2px solid #eee;
        }}

        .section-static.analyzer-group-summary > .section-body {{
            padding: 4px 20px 20px;
        }}

        .analyzer-group.section-panel {{
            background-color: #f0f0f4;
            border: 1px solid #dcdce3;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }}

        .analyzer-group.section-panel > summary {{
            background-color: #e8e8ee;
            border-radius: 5px 5px 0 0;
        }}

        .analyzer-group.section-panel[open] > summary {{
            border-bottom: 2px solid #d5d5dd;
        }}

        .analyzer-group > .section-body {{
            background-color: #f0f0f4;
            padding: 16px 16px 20px;
            border-radius: 0 0 5px 5px;
        }}

        .analyzer-group > .section-body > .section-panel {{
            margin-bottom: 12px;
            background-color: #ffffff;
            border: 1px solid #e0e0e6;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        }}

        .report-header {{
            border-left: 4px solid #05CE8B;
        }}

        .report-header.has-issues {{
            border-left-color: #FF6B35;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 6px 16px;
            margin: 12px 0 16px;
        }}

        .meta-grid dt {{
            font-weight: 600;
            color: #2a2550;
        }}

        .meta-grid dd {{
            margin: 0;
        }}

        .summary-viz-grid {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 24px;
            align-items: start;
        }}

        @media (max-width: 700px) {{
            .summary-viz-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .summary-viz-pie h3,
        .summary-viz-timeline h3 {{
            margin-top: 0;
        }}

        .expected-badge {{
            display: inline-block;
            background: #e8f9f4;
            color: #05ce8b;
            font-size: 0.75em;
            font-weight: 600;
            padding: 1px 6px;
            border-radius: 3px;
            vertical-align: middle;
        }}

        .findings-list {{
            margin: 8px 0;
            padding-left: 20px;
        }}

        .findings-list li {{
            margin: 6px 0;
            line-height: 1.5;
        }}

        .findings-issues li {{
            color: #0D0A30;
        }}

        .findings-clean {{
            color: #05ce8b;
            font-weight: 500;
        }}

        .findings-limited {{
            color: #8d6e63;
            font-weight: 500;
        }}

        .quality-warning {{
            background-color: #fff9f5;
            border-left: 4px solid #FF6B35;
            padding: 12px 16px;
            margin: 12px 0;
        }}

        .quality-warning p,
        .quality-warning ul {{
            margin: 6px 0;
        }}

        .privacy-notice {{
            background-color: #f0f4ff;
            border-left: 4px solid #5b7fc7;
            padding: 12px 16px;
            margin: 12px 0;
        }}

        .privacy-notice p,
        .privacy-notice ul {{
            margin: 6px 0;
        }}

        .privacy-filtered {{
            color: #888;
            font-style: italic;
        }}

        .operations-list {{
            margin: 12px 0;
            padding-left: 20px;
            list-style: disc;
        }}

        .operations-list li {{
            margin: 6px 0;
            line-height: 1.5;
        }}

        .table-wrap {{
            overflow-x: auto;
            margin: 16px 0;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            background-color: white;
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 8px 10px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background-color: #f2f2f2;
            font-weight: bold;
            color: #0D0A30;
            white-space: nowrap;
        }}

        /* Sortable table styles */
        table.sortable th {{
            cursor: pointer;
            position: relative;
            padding-right: 20px;
            user-select: none;
        }}

        table.sortable th:hover {{
            background-color: #e0e0e0;
        }}

        table.sortable th::after {{
            content: '';
            position: absolute;
            right: 6px;
            top: 50%;
            transform: translateY(-50%);
            opacity: 0.3;
            width: 0;
            height: 0;
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-top: 5px solid #4a4570;
        }}

        table.sortable th.sort-asc::after {{
            opacity: 1;
            border-top: 5px solid #05CE8B;
        }}

        table.sortable th.sort-desc::after {{
            opacity: 1;
            border-top: none;
            border-bottom: 5px solid #05CE8B;
        }}

        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}

        tr:hover {{
            background-color: #f5f5f5;
        }}

        tr.row-high-failure {{
            background-color: #ffeeed !important;
        }}

        tr.row-high-failure:hover {{
            background-color: #ffdddc !important;
        }}

        tr.row-medium-failure {{
            background-color: #fff7f3 !important;
        }}

        tr.row-medium-failure:hover {{
            background-color: #ffdfcb !important;
        }}

        tr.row-consecutive-failures {{
            background-color: #fffbf6 !important;  /* Light yellow/orange */
        }}

        tr.row-consecutive-failures:hover {{
            background-color: #ffe5ce !important;
        }}

        .high-failure {{
            color: #EA1412;
            font-weight: bold;
        }}

        .medium-failure {{
            color: #FF6B35;
            font-weight: bold;
        }}

        .low-failure {{
            color: #05ce8b;
        }}

        .error {{
            color: #EA1412;
            font-style: italic;
        }}

        .summary-stats {{
            background-color: #f0effc;
            padding: 12px 16px;
            border-left: 4px solid #05CE8B;
            margin: 12px 0;
        }}

        .summary-stats p {{
            margin: 4px 0;
        }}

        details {{
            cursor: pointer;
        }}

        summary {{
            cursor: pointer;
            font-weight: bold;
            color: #05CE8B;
            padding: 2px 0;
        }}

        summary:hover {{
            text-decoration: underline;
        }}

        details ul, details ol {{
            margin: 4px 0;
            padding-left: 18px;
        }}

        details li {{
            margin: 2px 0;
            font-size: 0.92em;
            line-height: 1.4;
        }}

        details p {{
            margin: 3px 0;
        }}

        .status-success {{
            color: #05ce8b;
            font-weight: bold;
        }}

        .status-error {{
            color: #EA1412;
            font-weight: bold;
        }}

        .status-unknown {{
            color: #4a4570;
        }}

        .consecutive-failure-warning {{
            color: #FF6B35;
            font-weight: bold;
            font-size: 1.1em;
        }}

        a.mythic-link, table a {{
            color: inherit;
            text-decoration: none;
            border-bottom: 1px dotted currentColor;
        }}

        a.mythic-link:hover, table a:hover {{
            color: #05CE8B;
            border-bottom-style: solid;
        }}

        td details {{
            margin: 0;
        }}

        td details p {{
            margin: 2px 0;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}

        td details ul, td details ol {{
            margin: 4px 0;
            padding-left: 16px;
        }}

        td details li {{
            margin: 2px 0;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}

        table.wide-table {{
            width: 100%;
        }}

        table.wide-table td.wrap-cell {{
            max-width: 340px;
            white-space: normal;
        }}

        table.wide-table td.wrap-cell .wrap-cell-text {{
            display: inline-block;
            max-width: 100%;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        table.wide-table td.wrap-cell code.wrap-cell-text {{
            padding: 1px 4px;
        }}

        .args-display {{
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            word-break: break-all;
            max-width: 300px;
        }}

        .col-extra {{
            display: none;
        }}

        .show-all-cols .col-extra {{
            display: table-cell;
        }}

        .toggle-cols-btn {{
            background: none;
            border: 1px solid #ccc;
            border-radius: 4px;
            padding: 4px 10px;
            font-size: 0.88em;
            color: #05CE8B;
            cursor: pointer;
            margin-bottom: 8px;
        }}

        .toggle-cols-btn:hover {{
            background-color: #f0f0f0;
            border-color: #05CE8B;
        }}

        .outlier-context {{
            margin-top: 8px;
            padding: 8px;
            background-color: #f9f9f9;
            border-left: 3px solid #05CE8B;
            font-size: 0.9em;
        }}

        .outlier-context p {{
            margin: 4px 0;
        }}

        .outlier-context ol {{
            margin: 4px 0;
            padding-left: 20px;
        }}

        .outlier-context li {{
            margin: 2px 0;
        }}

        .outlier-context code {{
            font-size: 0.85em;
        }}

        @media (max-width: 768px) {{
            body {{
                padding: 10px;
            }}

            .container {{
                padding: 0 8px;
            }}

            section {{
                padding: 12px;
            }}

            table {{
                font-size: 13px;
            }}

            th, td {{
                padding: 6px 8px;
            }}
        }}

        /* Git-like diff visualization styles */
        .diff-list {{
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.9em;
            margin: 8px 0;
            padding-left: 20px;
            list-style: none;
        }}

        .diff-list li {{
            margin: 4px 0;
            line-height: 1.5;
            padding: 2px 0;
        }}

        .diff-removed {{
            color: #EA1412;
        }}

        .diff-added {{
            color: #05ce8b;
        }}

        .diff-modified {{
            color: #FF6B35;
        }}

        .diff-path {{
            font-weight: bold;
            margin-right: 0.5em;
        }}

        .diff-marker {{
            margin: 0 0.5em;
            font-weight: bold;
        }}

        .diff-list code {{
            background-color: #f9f9f9;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.95em;
        }}

        .diff-transition {{
            margin: 6px 0 10px;
        }}

        .diff-transition-label {{
            font-size: 0.8em;
            font-weight: bold;
            color: #4a4570;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            display: block;
            margin-bottom: 2px;
        }}

        .diff-hint {{
            font-size: 0.82em;
            color: #6b6890;
            font-style: italic;
            margin-left: 0.3em;
        }}

        /* Search bar */
        .search-bar-wrap {{
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 6px;
            margin: 20px 0 20px;
        }}

        .search-label {{
            font-size: 0.9em;
            font-weight: 600;
            color: #0D0A30;
        }}

        .search-hint {{
            font-size: 0.86em;
            color: #4a4570;
            font-weight: normal;
            margin-left: 6px;
        }}

        .search-controls {{
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
        }}

        #report-search {{
            flex: 1;
            max-width: 480px;
            padding: 7px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 0.95em;
            outline: none;
            transition: border-color 0.15s;
        }}

        #report-search:focus {{
            border-color: #05CE8B;
            box-shadow: 0 0 0 2px rgba(5,206,139,0.15);
        }}

        #search-match-count {{
            font-size: 0.88em;
            color: #4a4570;
            white-space: nowrap;
        }}

        tr.search-hidden {{
            display: none;
        }}

        tr.search-nav-current {{
            outline: 2px solid #05CE8B;
            outline-offset: -2px;
        }}

        /* Error output styling */
        .error-output {{
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.88em;
            color: #EA1412;
            background: #ffeeed;
            border-left: 3px solid #EA1412;
            padding: 0.5em 0.75em;
            margin: 0.4em 0;
            line-height: 1.4;
            max-width: 100%;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        .error-output-full {{
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.85em;
            color: #0D0A30;
            background: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 0.75em;
            margin: 0.5em 0;
            line-height: 1.5;
            max-height: 20em;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        .error-output em,
        .error-output-full em {{
            color: #4a4570;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
    {report_overview_html}

    <div class="search-bar-wrap">
        <label class="search-label" for="report-search">
            Search table rows
            <span class="search-hint" id="report-search-hint">Table filter updates after you pause typing (no auto-scroll). Press / to focus. Enter / Shift+Enter jump between visible rows.</span>
        </label>
        <div class="search-controls">
            <input type="search" id="report-search" placeholder="Search table rows..." autocomplete="off" aria-describedby="report-search-hint search-match-count">
            <span id="search-match-count" aria-live="polite" aria-atomic="true"></span>
        </div>
    </div>

    {body_content}

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #4a4570; text-align: center;">
        <p>Generated by Janus - Red Team Operational Log Intelligence</p>
    </footer>
    </div>
    <script>
    function toggleExtraCols(btn) {{
        var wrap = btn.nextElementSibling;
        var expanded = wrap.classList.toggle('show-all-cols');
        btn.textContent = expanded ? 'Hide extra columns' : 'Show all columns';
    }}

    // Sortable table functionality
    (function() {{
        function getCellValue(row, idx) {{
            var cell = row.children[idx];
            // Check for data-sort attribute first
            if (cell.hasAttribute('data-sort')) {{
                return cell.getAttribute('data-sort');
            }}
            return cell.innerText || cell.textContent;
        }}

        function comparer(idx, asc) {{
            return function(a, b) {{
                var v1 = getCellValue(asc ? a : b, idx);
                var v2 = getCellValue(asc ? b : a, idx);

                // Try numeric comparison first
                var n1 = parseFloat(v1.replace(/[^0-9.-]/g, ''));
                var n2 = parseFloat(v2.replace(/[^0-9.-]/g, ''));

                if (!isNaN(n1) && !isNaN(n2)) {{
                    return n1 - n2;
                }}

                // Fall back to string comparison
                return v1.toString().localeCompare(v2);
            }};
        }}

        // Search / filter functionality
        (function() {{
            var searchInput = document.getElementById('report-search');
            var matchCount = document.getElementById('search-match-count');
            var debounceTimer = null;
            var matchedRows = [];
            var activeMatchIndex = -1;
            var detailsSnapshot = null;
            var previousQuery = '';
            var runToken = 0;
            var CHUNK_ROW_THRESHOLD = 2000;
            var FILTER_CHUNK_SIZE = 250;
            var SEARCH_DEBOUNCE_MS = 480;

            function clearCurrentNavigationRow() {{
                document.querySelectorAll('tr.search-nav-current').forEach(function(row) {{
                    row.classList.remove('search-nav-current');
                    row.removeAttribute('tabindex');
                }});
            }}

            function setCurrentNavigationRow(row) {{
                clearCurrentNavigationRow();
                row.classList.add('search-nav-current');
                row.setAttribute('tabindex', '-1');
                row.scrollIntoView({{ block: 'nearest', behavior: 'smooth' }});
                try {{
                    row.focus({{ preventScroll: true }});
                }} catch (e) {{
                    // Older browsers may not support focus options.
                    row.focus();
                }}
            }}

            function captureDetailsState() {{
                detailsSnapshot = Array.from(document.querySelectorAll('details')).map(function(panel) {{
                    return {{ element: panel, wasOpen: panel.open }};
                }});
            }}

            function resetDetailsToSnapshot() {{
                if (!detailsSnapshot) {{
                    return;
                }}
                detailsSnapshot.forEach(function(item) {{
                    if (item.wasOpen) {{
                        item.element.setAttribute('open', '');
                    }} else {{
                        item.element.removeAttribute('open');
                    }}
                }});
            }}

            function restoreDetailsState() {{
                resetDetailsToSnapshot();
                detailsSnapshot = null;
            }}

            function expandAncestorDetailsForVisibleRows() {{
                document.querySelectorAll('table tbody tr:not(.search-hidden)').forEach(function(tr) {{
                    var el = tr;
                    while (el) {{
                        if (el.tagName === 'DETAILS') {{
                            el.setAttribute('open', '');
                        }}
                        el = el.parentElement;
                    }}
                }});
            }}

            function updateMatchCount(query, shown) {{
                if (!query) {{
                    matchCount.textContent = '';
                    return;
                }}
                if (shown === 0) {{
                    matchCount.textContent = 'No matching rows';
                    return;
                }}
                matchCount.textContent = shown + ' row' + (shown === 1 ? '' : 's') + ' matched';
            }}

            function navigateMatches(step) {{
                if (!matchedRows.length) {{
                    return;
                }}
                activeMatchIndex = (activeMatchIndex + step + matchedRows.length) % matchedRows.length;
                setCurrentNavigationRow(matchedRows[activeMatchIndex]);
            }}

            function finalizeSearch(runId, query, shown) {{
                if (runId !== runToken) {{
                    return;
                }}

                if (query) {{
                    resetDetailsToSnapshot();
                    expandAncestorDetailsForVisibleRows();
                }}
                updateMatchCount(query, shown);
                previousQuery = query;
            }}

            function runSearchNow() {{
                var query = searchInput.value.trim().toLowerCase();
                var rows = Array.from(document.querySelectorAll('table tbody tr'));
                var runId = ++runToken;
                var shown = 0;

                if (!previousQuery && query && !detailsSnapshot) {{
                    captureDetailsState();
                }} else if (previousQuery && !query) {{
                    restoreDetailsState();
                }}

                clearCurrentNavigationRow();
                activeMatchIndex = -1;
                matchedRows = [];

                function applyRowRange(start, end) {{
                    for (var i = start; i < end; i++) {{
                        var row = rows[i];
                        if (!query || row.textContent.toLowerCase().includes(query)) {{
                            row.classList.remove('search-hidden');
                            shown++;
                            if (query) {{
                                matchedRows.push(row);
                            }}
                        }} else {{
                            row.classList.add('search-hidden');
                        }}
                    }}
                }}

                if (rows.length > CHUNK_ROW_THRESHOLD) {{
                    var idx = 0;
                    function processChunk() {{
                        if (runId !== runToken) {{
                            return;
                        }}
                        var end = Math.min(idx + FILTER_CHUNK_SIZE, rows.length);
                        applyRowRange(idx, end);
                        idx = end;
                        if (idx < rows.length) {{
                            requestAnimationFrame(processChunk);
                            return;
                        }}
                        finalizeSearch(runId, query, shown);
                    }}
                    requestAnimationFrame(processChunk);
                }} else {{
                    applyRowRange(0, rows.length);
                    finalizeSearch(runId, query, shown);
                }}
            }}

            function scheduleSearch() {{
                if (debounceTimer) {{
                    clearTimeout(debounceTimer);
                }}
                debounceTimer = setTimeout(function() {{
                    debounceTimer = null;
                    runSearchNow();
                }}, SEARCH_DEBOUNCE_MS);
            }}

            function flushSearchIfPending() {{
                if (!debounceTimer) {{
                    return;
                }}
                clearTimeout(debounceTimer);
                debounceTimer = null;
                runSearchNow();
            }}

            searchInput.addEventListener('input', scheduleSearch);
            searchInput.addEventListener('blur', flushSearchIfPending);
            searchInput.addEventListener('keydown', function(event) {{
                if (event.key === 'Escape') {{
                    event.preventDefault();
                    if (debounceTimer) {{
                        clearTimeout(debounceTimer);
                        debounceTimer = null;
                    }}
                    searchInput.value = '';
                    runSearchNow();
                    return;
                }}
                if (event.key === 'Enter') {{
                    event.preventDefault();
                    if (debounceTimer) {{
                        clearTimeout(debounceTimer);
                        debounceTimer = null;
                    }}
                    runSearchNow();
                    if (!matchedRows.length) {{
                        return;
                    }}
                    navigateMatches(event.shiftKey ? -1 : 1);
                }}
            }});

            document.addEventListener('keydown', function(event) {{
                if (event.key !== '/') {{
                    return;
                }}
                if (event.metaKey || event.ctrlKey || event.altKey) {{
                    return;
                }}
                var active = document.activeElement;
                if (active === searchInput) {{
                    return;
                }}
                if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.tagName === 'SELECT' || active.isContentEditable)) {{
                    return;
                }}
                event.preventDefault();
                searchInput.focus();
            }});
        }})();

        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('table.sortable thead th').forEach(function(th) {{
                th.addEventListener('click', function() {{
                    var table = th.closest('table');
                    var tbody = table.querySelector('tbody');
                    var thIndex = Array.from(th.parentNode.children).indexOf(th);

                    // Remove sort classes from other headers
                    Array.from(th.parentNode.children).forEach(function(otherTh) {{
                        if (otherTh !== th) {{
                            otherTh.classList.remove('sort-asc', 'sort-desc');
                        }}
                    }});

                    // Toggle sort direction
                    var asc = !th.classList.contains('sort-asc');
                    th.classList.remove('sort-asc', 'sort-desc');
                    th.classList.add(asc ? 'sort-asc' : 'sort-desc');

                    // Sort rows
                    Array.from(tbody.querySelectorAll('tr'))
                        .sort(comparer(thIndex, asc))
                        .forEach(function(tr) {{ tbody.appendChild(tr); }});
                }});
            }});
        }});
    }})();
    </script>
</body>
</html>
"""
