"""
Retention policy for how much content is persisted to events.ndjson.

Controls two independent axes:
  output_rule     — how much result output_text is kept
  arguments_rule  — how much task arguments_raw is kept

Both are resolved from config (top-level keys) with CLI overrides taking
precedence.  The resolved policy is recorded in bundle.json so downstream
consumers know exactly what was applied.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass

from Core.models import ResultEvent, TaskEvent

# ---------------------------------------------------------------------------
# output_rule constants
# ---------------------------------------------------------------------------

OUTPUT_RULE_ALL = "all"
OUTPUT_RULE_ERRORS_ONLY = "errors_only"
OUTPUT_RULE_NONE = "none"
RETENTION_RULE_MIXED = "mixed"

_VALID_OUTPUT_RULES = (OUTPUT_RULE_ALL, OUTPUT_RULE_ERRORS_ONLY, OUTPUT_RULE_NONE)

# ---------------------------------------------------------------------------
# arguments_rule constants
# ---------------------------------------------------------------------------

ARGUMENTS_RULE_ALL = "all"
ARGUMENTS_RULE_DROP = "drop"
ARGUMENTS_RULE_HASH = "hash"
ARGUMENTS_RULE_FEATURES_ONLY = "features_only"

_VALID_ARGUMENTS_RULES = (
    ARGUMENTS_RULE_ALL,
    ARGUMENTS_RULE_DROP,
    ARGUMENTS_RULE_HASH,
    ARGUMENTS_RULE_FEATURES_ONLY,
)

# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------


def normalize_output_rule(value: str | None) -> str:
    """Normalize a user or config string to a canonical output_rule id."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return OUTPUT_RULE_ALL
    raw = str(value).strip().lower().replace("-", "_")
    if raw == "all":
        return OUTPUT_RULE_ALL
    if raw in ("errors_only", "errorsonly"):
        return OUTPUT_RULE_ERRORS_ONLY
    if raw == "none":
        return OUTPUT_RULE_NONE
    raise ValueError(
        f"invalid output_rule {value!r}; expected one of {_VALID_OUTPUT_RULES!r}"
    )


def normalize_arguments_rule(value: str | None) -> str:
    """Normalize a user or config string to a canonical arguments_rule id."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return ARGUMENTS_RULE_ALL
    raw = str(value).strip().lower().replace("-", "_")
    if raw == "all":
        return ARGUMENTS_RULE_ALL
    if raw == "drop":
        return ARGUMENTS_RULE_DROP
    if raw == "hash":
        return ARGUMENTS_RULE_HASH
    if raw in ("features_only", "featuresonly", "features"):
        return ARGUMENTS_RULE_FEATURES_ONLY
    raise ValueError(
        f"invalid arguments_rule {value!r}; expected one of {_VALID_ARGUMENTS_RULES!r}"
    )


# ---------------------------------------------------------------------------
# Resolvers  (CLI wins over config; default is "all")
# ---------------------------------------------------------------------------


def resolve_output_rule(config: dict, cli_value: str | None) -> str:
    """CLI wins over top-level config key; default is all."""
    if cli_value is not None:
        return normalize_output_rule(cli_value)
    cfg_val = config.get("output_rule")
    if cfg_val is None:
        return OUTPUT_RULE_ALL
    return normalize_output_rule(str(cfg_val))


def resolve_arguments_rule(config: dict, cli_value: str | None) -> str:
    """CLI wins over top-level config key; default is all."""
    if cli_value is not None:
        return normalize_arguments_rule(cli_value)
    cfg_val = config.get("arguments_rule")
    if cfg_val is None:
        return ARGUMENTS_RULE_ALL
    return normalize_arguments_rule(str(cfg_val))


# ---------------------------------------------------------------------------
# Resolved policy container
# ---------------------------------------------------------------------------


@dataclass
class RetentionPolicy:
    """Immutable snapshot of resolved retention settings for a run."""

    output_rule: str = OUTPUT_RULE_ALL
    arguments_rule: str = ARGUMENTS_RULE_ALL

    def to_dict(self) -> dict:
        return {
            "output_rule": self.output_rule,
            "arguments_rule": self.arguments_rule,
        }

    @property
    def is_default(self) -> bool:
        return (
            self.output_rule == OUTPUT_RULE_ALL
            and self.arguments_rule == ARGUMENTS_RULE_ALL
        )


def resolve_retention_policy(
    config: dict,
    output_rule_cli: str | None = None,
    arguments_rule_cli: str | None = None,
) -> RetentionPolicy:
    """Build a RetentionPolicy from config + CLI overrides."""
    return RetentionPolicy(
        output_rule=resolve_output_rule(config, output_rule_cli),
        arguments_rule=resolve_arguments_rule(config, arguments_rule_cli),
    )


# ---------------------------------------------------------------------------
# Feature extraction helpers (for features_only mode)
# ---------------------------------------------------------------------------

_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\|^\\\\")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _detect_arguments_shape(raw: str) -> str:
    stripped = raw.strip()
    if not stripped:
        return "empty"
    if stripped[0] == "{":
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return "json_object"
        except (json.JSONDecodeError, ValueError):
            pass
    if stripped[0] == "[":
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return "json_array"
        except (json.JSONDecodeError, ValueError):
            pass
    if stripped.startswith("/") or _WINDOWS_PATH_RE.match(stripped):
        return "path_like"
    return "plain_text"


def compute_arguments_features(raw: str) -> dict:
    """Compute privacy-safe derived features from arguments_raw."""
    if not raw:
        return {"arguments_present": False, "arguments_length": 0}
    return {
        "arguments_present": True,
        "arguments_length": len(raw),
        "arguments_token_count": len(raw.split()),
        "arguments_shape": _detect_arguments_shape(raw),
        "arguments_entropy": round(_shannon_entropy(raw), 3),
    }


def compute_arguments_digest(raw: str) -> str:
    """SHA-256 hex digest of the raw argument string."""
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_output_features(text: str) -> dict:
    """Compute privacy-safe derived features from output_text."""
    if not text:
        return {"output_present": False, "output_length": 0}
    return {
        "output_present": True,
        "output_length": len(text),
        "output_line_count": text.count("\n") + 1,
    }


_ARGUMENTS_RETENTION_FIELDS = (
    "arguments_retained",
    "arguments_digest",
    "arguments_present",
    "arguments_length",
    "arguments_token_count",
    "arguments_shape",
    "arguments_entropy",
)

_OUTPUT_RETENTION_FIELDS = (
    "output_retained",
    "output_present",
    "output_length",
    "output_line_count",
)


def _copy_prefixed_fields(
    event: dict,
    fields: tuple[str, ...],
    *,
    source_prefix: str = "",
    dest_prefix: str = "",
) -> dict:
    """Return selected retention fields with optional source/destination prefixes."""
    copied: dict = {}
    for field in fields:
        src_key = f"{source_prefix}{field}"
        if src_key in event:
            copied[f"{dest_prefix}{field}"] = event[src_key]
    return copied


def copy_task_retention_fields(
    task: dict,
    *,
    source_prefix: str = "",
    dest_prefix: str = "",
) -> dict:
    """Copy argument-retention metadata from a task-shaped event dict."""
    return _copy_prefixed_fields(
        task,
        _ARGUMENTS_RETENTION_FIELDS,
        source_prefix=source_prefix,
        dest_prefix=dest_prefix,
    )


def copy_result_retention_fields(
    result: dict,
    *,
    source_prefix: str = "",
    dest_prefix: str = "",
) -> dict:
    """Copy output-retention metadata from a result-shaped event dict."""
    return _copy_prefixed_fields(
        result,
        _OUTPUT_RETENTION_FIELDS,
        source_prefix=source_prefix,
        dest_prefix=dest_prefix,
    )


# ---------------------------------------------------------------------------
# Application helpers  — mutate event lists in place
# ---------------------------------------------------------------------------


def apply_output_rule_to_results(results: list[ResultEvent], rule: str) -> None:
    """Mutate result events in place according to the output retention policy."""
    r = normalize_output_rule(rule)
    if r == OUTPUT_RULE_ALL:
        return
    for res in results:
        if r == OUTPUT_RULE_NONE:
            res.retention_meta["output_retained"] = OUTPUT_RULE_NONE
            res.retention_meta.update(compute_output_features(res.output_text))
            res.output_text = ""
            res.pty_output_preface = ""
        elif r == OUTPUT_RULE_ERRORS_ONLY:
            res.retention_meta["output_retained"] = OUTPUT_RULE_ERRORS_ONLY
            if res.status == "success":
                res.retention_meta.update(compute_output_features(res.output_text))
                res.output_text = ""
                res.pty_output_preface = ""


def apply_arguments_rule_to_tasks(
    tasks: list[TaskEvent], rule: str
) -> None:
    """Mutate task events in place according to the arguments retention policy."""
    r = normalize_arguments_rule(rule)
    if r == ARGUMENTS_RULE_ALL:
        return
    for task in tasks:
        raw = task.arguments_raw
        if r == ARGUMENTS_RULE_DROP:
            task.retention_meta["arguments_retained"] = ARGUMENTS_RULE_DROP
            task.retention_meta["arguments_length"] = len(raw)
            task.arguments_raw = ""
            task.pty_input_raw = ""
        elif r == ARGUMENTS_RULE_HASH:
            task.retention_meta["arguments_retained"] = ARGUMENTS_RULE_HASH
            if raw:
                task.retention_meta["arguments_digest"] = compute_arguments_digest(raw)
            task.retention_meta["arguments_length"] = len(raw)
            task.arguments_raw = ""
            task.pty_input_raw = ""
        elif r == ARGUMENTS_RULE_FEATURES_ONLY:
            task.retention_meta["arguments_retained"] = ARGUMENTS_RULE_FEATURES_ONLY
            task.retention_meta.update(compute_arguments_features(raw))
            task.arguments_raw = ""
            task.pty_input_raw = ""


def apply_retention_policy(
    task_events: list[TaskEvent],
    result_events: list[ResultEvent],
    policy: RetentionPolicy,
) -> None:
    """Apply the full retention policy to both event lists in place."""
    apply_arguments_rule_to_tasks(task_events, policy.arguments_rule)
    apply_output_rule_to_results(result_events, policy.output_rule)


# ---------------------------------------------------------------------------
# Post-hoc detection from loaded event dicts (for analyzer-time awareness)
# ---------------------------------------------------------------------------

_ARGUMENTS_DEPENDENT_ANALYZERS = frozenset({
    "parameter-entropy",
    "argument-position-profile",
    "tool-dump",
    "command-retry-success",
    "dwell-time",
    "callback-health",
    "command-duration",
    "command-failure-summary",
})

_OUTPUT_DEPENDENT_ANALYZERS = frozenset({
    "av-tracker",
    "command-failure-summary",
})


def _normalize_bundle_output_rule(value: str | None) -> str | None:
    """Normalize output_rule values found in bundle metadata."""
    if value is None:
        return None
    raw = str(value).strip().lower().replace("-", "_")
    if not raw:
        return None
    if raw == RETENTION_RULE_MIXED:
        return RETENTION_RULE_MIXED
    return normalize_output_rule(raw)


def _normalize_bundle_arguments_rule(value: str | None) -> str | None:
    """Normalize arguments_rule values found in bundle metadata."""
    if value is None:
        return None
    raw = str(value).strip().lower().replace("-", "_")
    if not raw:
        return None
    if raw == RETENTION_RULE_MIXED:
        return RETENTION_RULE_MIXED
    return normalize_arguments_rule(raw)


def _normalized_rules_from_metadata(
    value: object,
    normalizer,
) -> set[str]:
    """Normalize a metadata field containing zero, one, or many rule ids."""
    normalized: set[str] = set()
    if value is None:
        return normalized
    values = value if isinstance(value, list) else [value]
    for raw in values:
        try:
            rule = normalizer(raw)
        except ValueError:
            continue
        if rule:
            normalized.add(rule)
    return normalized


def _canonical_rule(observed: set[str], default_rule: str) -> str:
    """Collapse observed rules into a canonical state."""
    if not observed:
        return default_rule
    if RETENTION_RULE_MIXED in observed or len(observed) > 1:
        return RETENTION_RULE_MIXED
    return next(iter(observed))


def _build_privacy_limitations(args_rule: str, out_rule: str) -> list[str]:
    limitations: list[str] = []
    if args_rule != ARGUMENTS_RULE_ALL:
        if args_rule == RETENTION_RULE_MIXED:
            limitations.append(
                "arguments_raw was filtered under multiple policies across the dataset; "
                "analyzers that depend on raw arguments may produce reduced, partial, or inconsistent output"
            )
        else:
            limitations.append(
                f"arguments_raw was filtered (policy: {args_rule}); "
                "analyzers that depend on raw arguments may produce reduced or empty output"
            )
    if out_rule != OUTPUT_RULE_ALL:
        if out_rule == RETENTION_RULE_MIXED:
            limitations.append(
                "output_text was filtered under multiple policies across the dataset; "
                "analyzers that depend on result output may produce reduced, partial, or inconsistent output"
            )
        else:
            limitations.append(
                f"output_text was filtered (policy: {out_rule}); "
                "analyzers that depend on result output may produce reduced or empty output"
            )
    return limitations


def detect_retention_from_events(
    task_events: list[dict],
    result_events: list[dict],
    bundle_metadata: dict | None = None,
) -> dict:
    """Inspect loaded event dicts for retention metadata.

    Returns a dict suitable for merging into analyzer metadata:
      - arguments_retained: detected policy, "all", or "mixed"
      - output_retained: detected policy, "all", or "mixed"
      - observed_arguments_rules: exact observed rule ids
      - observed_output_rules: exact observed rule ids
      - privacy_limited: list of human-readable limitation descriptions
    """
    args_retained = set()
    output_retained = set()

    for t in task_events:
        ar = t.get("arguments_retained")
        if ar:
            args_retained.add(ar)
    for r in result_events:
        or_ = r.get("output_retained")
        if or_:
            output_retained.add(or_)

    if bundle_metadata:
        args_retained.update(
            _normalized_rules_from_metadata(
                bundle_metadata.get("observed_arguments_rules"),
                _normalize_bundle_arguments_rule,
            )
        )
        output_retained.update(
            _normalized_rules_from_metadata(
                bundle_metadata.get("observed_output_rules"),
                _normalize_bundle_output_rule,
            )
        )

        try:
            bundle_args_rule = _normalize_bundle_arguments_rule(
                bundle_metadata.get("arguments_rule")
            )
        except ValueError:
            bundle_args_rule = None
        try:
            bundle_output_rule = _normalize_bundle_output_rule(
                bundle_metadata.get("output_rule")
            )
        except ValueError:
            bundle_output_rule = None

        if bundle_args_rule:
            if bundle_args_rule == RETENTION_RULE_MIXED:
                args_retained.update(
                    _normalized_rules_from_metadata(
                        bundle_metadata.get("observed_arguments_rules"),
                        _normalize_bundle_arguments_rule,
                    )
                )
            else:
                args_retained = {bundle_args_rule}
        if bundle_output_rule:
            if bundle_output_rule == RETENTION_RULE_MIXED:
                output_retained.update(
                    _normalized_rules_from_metadata(
                        bundle_metadata.get("observed_output_rules"),
                        _normalize_bundle_output_rule,
                    )
                )
            else:
                output_retained = {bundle_output_rule}

    args_rule = _canonical_rule(args_retained, ARGUMENTS_RULE_ALL)
    out_rule = _canonical_rule(output_retained, OUTPUT_RULE_ALL)
    limitations = _build_privacy_limitations(args_rule, out_rule)

    return {
        "arguments_retained": args_rule,
        "output_retained": out_rule,
        "observed_arguments_rules": (
            sorted(args_retained) if args_retained else [ARGUMENTS_RULE_ALL]
        ),
        "observed_output_rules": (
            sorted(output_retained) if output_retained else [OUTPUT_RULE_ALL]
        ),
        "privacy_limited": limitations if limitations else None,
    }


def privacy_warnings_for_analyzer(
    analyzer_name: str,
    retention_info: dict,
) -> list[str]:
    """Return specific warnings for a given analyzer based on detected retention state."""
    warnings: list[str] = []
    args_rule = retention_info.get("arguments_retained", "all")
    out_rule = retention_info.get("output_retained", "all")
    args_label = (
        "multiple argument-retention policies"
        if args_rule == RETENTION_RULE_MIXED
        else f"arguments_rule={args_rule}"
    )
    out_label = (
        "multiple output-retention policies"
        if out_rule == RETENTION_RULE_MIXED
        else f"output_rule={out_rule}"
    )

    if args_rule != "all" and analyzer_name in _ARGUMENTS_DEPENDENT_ANALYZERS:
        if analyzer_name == "parameter-entropy":
            warnings.append(
                "parameter-entropy requires raw arguments_raw to detect structural anomalies; "
                f"results are empty or severely limited under {args_label}"
            )
        elif analyzer_name == "argument-position-profile":
            warnings.append(
                "argument-position-profile requires raw arguments_raw for positional analysis; "
                f"results are empty or severely limited under {args_label}"
            )
        elif analyzer_name == "tool-dump":
            warnings.append(
                "tool-dump uses arguments_raw for substring matching and full-command dumps; "
                f"match accuracy and dump content are degraded under {args_label}"
            )
        elif analyzer_name == "command-retry-success":
            warnings.append(
                "command-retry-success compares arguments_raw between attempts to detect tuning; "
                f"argument diff detection is unavailable under {args_label}"
            )
        else:
            warnings.append(
                f"{analyzer_name} may include arguments_raw in detail rows; "
                f"those fields are empty under {args_label}"
            )

    if out_rule != "all" and analyzer_name in _OUTPUT_DEPENDENT_ANALYZERS:
        if analyzer_name == "av-tracker":
            warnings.append(
                "av-tracker scans successful ps output_text for AV/EDR executables; "
                f"detections are unavailable or incomplete under {out_label}"
            )
        else:
            warnings.append(
                f"{analyzer_name} uses output_text for error message analysis; "
                f"detail may be limited under {out_label}"
            )

    return warnings
