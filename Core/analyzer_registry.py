"""
Shared analyzer registry for Janus entry points.

Loads analyzer names and output filenames from Config/analyzers.yml when
available, with hardcoded fallback so Python code works even without the
YAML file (e.g. inside the Docker container before Config is mounted).
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Hardcoded fallback (keeps Python working without the YAML file)
# ---------------------------------------------------------------------------

_FALLBACK_OUTPUTS = {
    "summary-visualization": "summary_visualization.json",
    "command-failure-summary": "command_failure_summary.json",
    "command-retry-success": "command_retry_success.json",
    "command-duration": "command_duration.json",
    "outlier-context": "outlier_context_analysis.json",
    "callback-health": "callback_health.json",
    "av-tracker": "av_tracker.json",
    "dwell-time": "dwell_time.json",
    "parameter-entropy": "parameter_entropy.json",
    "argument-position-profile": "argument_position_profile.json",
    "tool-dump": "tool_dump.json",
}

_FALLBACK_PARTIAL = [
    "summary-visualization",
    "command-failure-summary",
    "command-retry-success",
    "command-duration",
    "outlier-context",
    "av-tracker",
    "parameter-entropy",
    "argument-position-profile",
    "tool-dump",
]

_FALLBACK_MULTI = [
    "summary-visualization",
    "command-failure-summary",
    "command-retry-success",
    "command-duration",
    "outlier-context",
    "callback-health",
    "av-tracker",
    "parameter-entropy",
    "argument-position-profile",
    "tool-dump",
]

# ---------------------------------------------------------------------------
# YAML loader (stdlib only — avoids PyYAML dependency on host)
# ---------------------------------------------------------------------------


def _find_analyzers_yml() -> Path | None:
    """Locate analyzers.yml: Config/analyzers.yml (host) or /config/analyzers.yml (container)."""
    candidates = [
        Path(__file__).resolve().parent.parent / "Config" / "analyzers.yml",
        Path("/config/analyzers.yml"),
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def _parse_analyzers_yml(path: Path) -> tuple[dict[str, str], list[str], list[str]]:
    """Minimal YAML parser for the analyzers.yml structure."""
    outputs: dict[str, str] = {}
    partial: list[str] = []
    multi: list[str] = []

    section = None  # "analyzers" | "partial_load" | "multi_analyze"

    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip()
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(stripped)

            # Top-level keys
            if indent == 0:
                if stripped.startswith("analyzers:"):
                    section = "analyzers"
                elif stripped.startswith("partial_load:"):
                    section = "partial_load"
                elif stripped.startswith("multi_analyze:"):
                    section = "multi_analyze"
                else:
                    section = None
                continue

            # Indented content
            if section == "analyzers" and ":" in stripped:
                key, _, val = stripped.partition(":")
                outputs[key.strip()] = val.strip()
            elif section == "partial_load" and stripped.startswith("- "):
                partial.append(stripped[2:].strip())
            elif section == "multi_analyze" and stripped.startswith("- "):
                multi.append(stripped[2:].strip())

    return outputs, partial, multi


def _load() -> tuple[dict[str, str], list[str], list[str]]:
    yml = _find_analyzers_yml()
    if yml is not None:
        try:
            return _parse_analyzers_yml(yml)
        except Exception:
            pass
    return _FALLBACK_OUTPUTS, _FALLBACK_PARTIAL, _FALLBACK_MULTI


ANALYZER_OUTPUTS, PARTIAL_LOAD_ANALYZERS, MULTI_ANALYZE_ANALYZERS = _load()
ALL_ANALYZERS = list(ANALYZER_OUTPUTS.keys())
