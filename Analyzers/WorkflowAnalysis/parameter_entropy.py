"""
ParameterEntropy — Detects structurally anomalous arguments in TaskEvents.

Examines arguments_raw across all tasks and flags arguments that look
anomalous by structural and statistical properties — not by content —
preserving OPSEC-safe output.

Detection dimensions:
  - High Shannon entropy tokens (keys, tokens, encrypted blobs)
  - Wildcard-heavy paths
  - Large IN (...) list expansions
  - Embedded regex-like syntax
  - Repeated high-entropy tokens across tasks (possible hardcoded credential)

Entropy baseline logic:
  Some commands are EXPECTED to carry high-entropy arguments by design
  (e.g. /ptt always takes a Kerberos ticket blob; upload/inject take
  shellcode or PE bytes).  For these commands, the analyzer uses a
  per-command expected entropy range rather than a global threshold, so
  a /ptt call with a suspiciously SHORT or LOW-entropy ticket is flagged
  as an anomaly (likely to fail) while a normal-length ticket is not.

  TODO: Tune per-command entropy baselines from real engagement data.
        Priority commands to baseline first:
          - /ptt         — Kerberos ticket blob; short/low-entropy → will fail
          - upload       — PE/shellcode bytes; always high-entropy, never flag
          - inject       — shellcode blob; same as upload
          - execute-assembly — .NET PE; always high-entropy, never flag
          - make_token   — credentials; medium entropy, flag extremes
          - mimikatz     — sub-command args vary; baseline by sub-command
        The goal is to surface "this /ptt argument looks too short to be a
        real ticket" rather than "this /ptt argument looks high-entropy"
        (which is always true and never interesting).

Output: parameter_entropy.json with per-finding details, repeated-token
        summary, and aggregate counts by finding type.
"""

import json
import math
import re
import statistics
from collections import Counter
from typing import Any

from Core.analyzer_behavior_registry import build_analyzer_context

# ---------------------------------------------------------------------------
# Thresholds — can be overridden via config in the future
# ---------------------------------------------------------------------------

ENTROPY_THRESHOLD: float = 4.5
"""Bits/char above which a token is considered high-entropy.
English prose ~4.0; base64 ~6.0; hex strings ~3.8-4.0.
"""

MIN_TOKEN_LENGTH: int = 16
"""Ignore tokens shorter than this even if they score high entropy."""

WILDCARD_THRESHOLD: int = 3
"""Number of wildcard characters (*  ?) before flagging a path."""

IN_LIST_THRESHOLD: int = 20
"""Number of items in an IN (...) list before flagging."""

REPEATED_ENTROPY_MIN_COUNT: int = 3
"""Same high-entropy token prefix seen this many times → notable."""

LOW_ENTROPY_SHORT_PAYLOAD_MAX_LEN: int = 96
"""Only flag expected-high-entropy payloads as suspicious when they are short."""

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Tokenizer: keep quoted strings whole, then split on whitespace/delimiters
_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')

# SQL-style IN list
_IN_LIST_RE = re.compile(r'\bIN\s*\(([^)]+)\)', re.IGNORECASE)

# Unambiguous regex indicators: always flag regardless of argument shape.
# These constructs have no plausible meaning outside a regex context.
_REGEX_STRONG_RE = re.compile(r'(?:\(\?[imsxIL]\)|[\[\]]{3,}|\+\?|\*\?|\(\?:)')

# Backslash metachar combos (\d \w \s \D \W \S).  These look like regex but
# are also produced by Windows file paths (e.g. \desktop → \d).  Only flag
# when the argument is not a Windows-style path.
_REGEX_BACKSLASH_META_RE = re.compile(r'\\[dwsWDS]')

# Matches Windows UNC paths (\\server\share) and drive paths (C:\...)
_WINDOWS_PATH_RE = re.compile(r'(?:\\\\[^\\]|[A-Za-z]:\\)')


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _safe_truncate(token: str, max_len: int = 32) -> str:
    """Truncate a token for output — avoids logging full secrets."""
    if len(token) <= max_len:
        return token
    return token[:max_len] + f"…[+{len(token) - max_len}]"


def _overall_entropy(raw: str) -> float:
    """Entropy of the entire arguments_raw string (used for command-level checks)."""
    return _shannon_entropy(raw)


def _longest_token(raw: str) -> str:
    """Return the longest token-like segment from arguments_raw."""
    longest = ""
    for match in _TOKEN_RE.finditer(raw):
        token = match.group().strip('"\'')
        if len(token) > len(longest):
            longest = token
    return longest


def _is_structured_json_payload(raw: str) -> bool:
    """Return True when arguments_raw is a JSON object/list, not a path-like token."""
    stripped = raw.strip()
    if not stripped or stripped[0] not in "[{":
        return False
    try:
        parsed = json.loads(stripped)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return isinstance(parsed, (dict, list))


# ---------------------------------------------------------------------------
# Per-task analysis
# ---------------------------------------------------------------------------

def _analyze_task(task: dict, context: dict[str, Any]) -> tuple[list[dict], dict[str, int]]:
    """Return a list of finding dicts for a single task event."""
    raw: str = task.get("arguments_raw") or ""
    command_name: str = task.get("command_name", "")
    findings: list[dict] = []
    adjustments = {
        "registry_adjusted_tasks": 0,
        "suppressed_high_entropy_findings": 0,
        "converted_low_entropy_findings": 0,
    }
    registry = context["behavior_registry"]
    behavior = registry.resolve(task)

    base = {
        "task_id":       task.get("task_id"),
        "display_id":    task.get("display_id"),
        "operation_id":  task.get("operation_id"),
        "timestamp":     task.get("timestamp"),
        "tool_name":     task.get("tool_name"),
        "command_name":  command_name,
        "arguments_raw": raw,
    }

    if not raw:
        return findings, adjustments

    # ------------------------------------------------------------------
    # 1. Per-command expected-entropy check (known high-entropy commands)
    #    Check BEFORE the global token scan so we can skip global flagging
    #    for these commands.
    # ------------------------------------------------------------------
    if behavior.has_class("expected_high_entropy"):
        adjustments["registry_adjusted_tasks"] += 1
        expected = behavior.parameter_entropy
        overall_ent = _overall_entropy(raw)
        longest_token = _longest_token(raw)
        longest_token_ent = _shannon_entropy(longest_token) if longest_token else 0.0
        min_expected = expected.get("min_expected")
        # Long payload commands often include fixed headers, JSON wrappers, or
        # repeated padding that lower whole-string entropy without making the
        # argument suspicious. Only flag likely truncation/placeholders when the
        # payload is both short and below the expected entropy floor.
        if (
            min_expected is not None
            and overall_ent < min_expected
            and len(longest_token) < LOW_ENTROPY_SHORT_PAYLOAD_MAX_LEN
            and longest_token_ent < min_expected
        ):
            findings.append({
                **base,
                "finding_type":   "low_entropy_for_expected_high_entropy_command",
                "detail": (
                    f"'{command_name}' argument entropy {overall_ent:.2f} bits/char is below "
                    f"expected minimum {min_expected:.2f} on a short payload — argument may be "
                    f"truncated, malformed, or a placeholder (likely to fail)"
                ),
                "token":          _safe_truncate(raw, 64),
                "token_entropy":  round(overall_ent, 3),
                "token_length":   len(raw),
            })
            adjustments["converted_low_entropy_findings"] += 1
        # Do NOT run the global high-entropy token scan for these commands —
        # high entropy is expected and would only generate noise.
        # Still run wildcard, IN-list, and regex checks below.
        skip_global_entropy = True
    else:
        skip_global_entropy = False

    # ------------------------------------------------------------------
    # 2. Global high-entropy token scan
    #    Skip when arguments_raw is a structured JSON object/array — Mythic
    #    commands routinely send JSON like {"host":"X","full_path":"..."} which
    #    scores high entropy due to mixed punctuation, not because the content
    #    is a key or blob.
    # ------------------------------------------------------------------
    if not skip_global_entropy and _is_structured_json_payload(raw):
        skip_global_entropy = True
        adjustments["suppressed_high_entropy_findings"] += 1

    if not skip_global_entropy:
        for match in _TOKEN_RE.finditer(raw):
            token = match.group().strip('"\'')
            if len(token) < MIN_TOKEN_LENGTH:
                continue
            ent = _shannon_entropy(token)
            if ent >= ENTROPY_THRESHOLD:
                findings.append({
                    **base,
                    "finding_type":  "high_entropy_token",
                    "detail": (
                        f"Token entropy {ent:.2f} bits/char (len={len(token)}) — "
                        f"may be a key, token, or encrypted blob"
                    ),
                    "token":         _safe_truncate(token),
                    "token_entropy": round(ent, 3),
                    "token_length":  len(token),
                })
    else:
        for match in _TOKEN_RE.finditer(raw):
            token = match.group().strip('"\'')
            if len(token) < MIN_TOKEN_LENGTH:
                continue
            ent = _shannon_entropy(token)
            if ent >= ENTROPY_THRESHOLD:
                adjustments["suppressed_high_entropy_findings"] += 1

    # ------------------------------------------------------------------
    # 3. Wildcard-heavy paths
    # ------------------------------------------------------------------
    wildcard_count = raw.count('*') + raw.count('?')
    bracket_count = 0 if _is_structured_json_payload(raw) else len(re.findall(r'\[.+?\]', raw))
    if wildcard_count >= WILDCARD_THRESHOLD or bracket_count >= 2:
        findings.append({
            **base,
            "finding_type": "wildcard_path",
            "detail": (
                f"{wildcard_count} wildcard char(s), {bracket_count} bracket group(s) — "
                f"may indicate a guessed or overly broad path"
            ),
            "token":         _safe_truncate(raw, 64),
            "token_entropy": None,
            "token_length":  len(raw),
        })

    # ------------------------------------------------------------------
    # 4. Large IN (...) lists
    # ------------------------------------------------------------------
    for m in _IN_LIST_RE.finditer(raw):
        items = [i.strip() for i in m.group(1).split(',')]
        if len(items) >= IN_LIST_THRESHOLD:
            findings.append({
                **base,
                "finding_type": "large_in_list",
                "detail": (
                    f"IN list with {len(items)} items — "
                    f"consider scripting this enumeration"
                ),
                "token":         _safe_truncate(m.group(), 64),
                "token_entropy": None,
                "token_length":  len(m.group()),
            })

    # ------------------------------------------------------------------
    # 5. Embedded regex syntax
    #    Skip entirely for structured JSON payloads (normal Mythic arg format).
    #    For plain strings, split detection: unambiguous regex constructs are
    #    always flagged; backslash metachar combos (\d \w etc.) are only flagged
    #    when the argument does not look like a Windows file/UNC path, because
    #    paths like C:\desktop.ini or \\SERVER\D$ produce \d and \D naturally.
    # ------------------------------------------------------------------
    is_json_payload = _is_structured_json_payload(raw)
    if not is_json_payload:
        is_winpath = bool(_WINDOWS_PATH_RE.search(raw))
        has_strong = bool(_REGEX_STRONG_RE.search(raw))
        has_meta = (not is_winpath) and bool(_REGEX_BACKSLASH_META_RE.search(raw))
        if has_strong or has_meta:
            findings.append({
                **base,
                "finding_type": "regex_syntax",
                "detail": "Argument contains embedded regex-like syntax",
                "token":         _safe_truncate(raw, 64),
                "token_entropy": None,
                "token_length":  len(raw),
            })

    return findings, adjustments


# ---------------------------------------------------------------------------
# Cross-task repeated-entropy detection
# ---------------------------------------------------------------------------

def _detect_repeated_tokens(all_findings: list[dict]) -> list[dict]:
    """Find high-entropy tokens that appear in 3+ tasks (possible hardcoded secret)."""
    # key: first 8 chars of token (prefix fingerprint) → list of occurrences
    prefix_map: dict[str, list[dict]] = {}
    for f in all_findings:
        if f["finding_type"] == "high_entropy_token" and f.get("token_entropy"):
            prefix = f["token"][:8]
            prefix_map.setdefault(prefix, []).append(f)

    repeated = []
    for prefix, occurrences in prefix_map.items():
        if len(occurrences) < REPEATED_ENTROPY_MIN_COUNT:
            continue
        entropies = [o["token_entropy"] for o in occurrences if o.get("token_entropy")]
        repeated.append({
            "token_prefix":  prefix,
            "entropy_mean":  round(statistics.mean(entropies), 3) if entropies else None,
            "occurrences":   len(occurrences),
            "task_ids":      [o["task_id"] for o in occurrences],
            "commands":      sorted({o["command_name"] for o in occurrences}),
            "detail": (
                f"Same high-entropy token prefix '{prefix}…' appears in "
                f"{len(occurrences)} tasks — may be a reused/hardcoded credential or key"
            ),
        })

    return sorted(repeated, key=lambda r: r["occurrences"], reverse=True)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def analyze(task_events: list[dict], result_events: list[dict], context: dict[str, Any] | None = None) -> dict:
    """Analyze argument entropy and structural anomalies across all task events.

    Args:
        task_events:   List of normalized task event dicts.
        result_events: List of normalized result event dicts (unused but
                       required for interface consistency).

    Returns:
        Dict with analyzer name, metadata, per-finding list, repeated-token
        summary, and aggregate counts by finding type.
    """
    if context is None:
        context = build_analyzer_context()

    all_findings: list[dict] = []
    registry_adjustments = {
        "registry_adjusted_tasks": 0,
        "suppressed_high_entropy_findings": 0,
        "converted_low_entropy_findings": 0,
    }

    for task in task_events:
        findings, adjustments = _analyze_task(task, context)
        all_findings.extend(findings)
        for key, value in adjustments.items():
            registry_adjustments[key] += value

    repeated = _detect_repeated_tokens(all_findings)

    type_counts = dict(Counter(f["finding_type"] for f in all_findings))
    registry = context["behavior_registry"]
    unreliable_sources = sorted({
        str(task.get("source", ""))
        for task in task_events
        if registry.resolve(task).has_class("result_status_unreliable")
    })

    return {
        "analyzer": "parameter_entropy",
        "metadata": {
            "events_analyzed": len(task_events),
            "thresholds": {
                "entropy_threshold":         ENTROPY_THRESHOLD,
                "min_token_length":          MIN_TOKEN_LENGTH,
                "wildcard_threshold":        WILDCARD_THRESHOLD,
                "in_list_threshold":         IN_LIST_THRESHOLD,
                "repeated_entropy_min_count": REPEATED_ENTROPY_MIN_COUNT,
            },
            "known_high_entropy_commands": registry.commands_with_behavior_class("expected_high_entropy"),
            "behavior_registry": context["behavior_registry_metadata"],
            "registry_adjustments": registry_adjustments,
            "sources_with_unreliable_status": unreliable_sources,
        },
        "summary": {
            "total_findings":                len(all_findings),
            "by_type":                       type_counts,
            "tasks_with_findings":           len({f["task_id"] for f in all_findings}),
            "repeated_high_entropy_tokens":  len(repeated),
        },
        "findings":               all_findings,
        "repeated_high_entropy":  repeated,
    }
