"""Load completed Janus run artifacts for run-to-run diffing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Core.analyzer_registry import ANALYZER_OUTPUTS
from Core.data_quality import build_data_quality


@dataclass(frozen=True)
class RunArtifacts:
    path: Path
    bundle: dict[str, Any]
    analyzers: dict[str, dict[str, Any]]
    task_events: list[dict[str, Any]]
    result_events: list[dict[str, Any]]
    data_quality: list[dict[str, Any]]


def load_run_artifacts(run_dir: Path) -> RunArtifacts:
    """Load bundle, analyzer JSON, and events for a completed Janus output dir."""
    run_dir = run_dir.resolve()
    if not run_dir.exists() or not run_dir.is_dir():
        raise FileNotFoundError(f"run directory not found: {run_dir}")

    bundle = _load_json(run_dir / "bundle.json")
    analyzers: dict[str, dict[str, Any]] = {}
    for analyzer_name, filename in sorted(ANALYZER_OUTPUTS.items()):
        payload = _load_json(run_dir / filename)
        if payload:
            analyzers[analyzer_name] = payload

    task_events, result_events = _load_events(run_dir / "events.ndjson")
    data_quality = build_data_quality(bundle, task_events, result_events)

    return RunArtifacts(
        path=run_dir,
        bundle=bundle,
        analyzers=analyzers,
        task_events=task_events,
        result_events=result_events,
        data_quality=data_quality,
    )


def run_identity(artifacts: RunArtifacts) -> dict[str, Any]:
    """Return stable, user-facing run metadata for diff.json."""
    bundle = artifacts.bundle
    sources = sorted(_sources(artifacts))
    return {
        "path": str(artifacts.path),
        "run_id": str(
            bundle.get("operation_slug")
            or bundle.get("operation_name")
            or bundle.get("analysis_version")
            or artifacts.path.name
        ),
        "operation_id": bundle.get("operation_id"),
        "operation_name": bundle.get("operation_name"),
        "operation_slug": bundle.get("operation_slug"),
        "analysis_version": bundle.get("analysis_version"),
        "analysis_timestamp": bundle.get("analysis_timestamp"),
        "sources": sources,
        "total_tasks": len(artifacts.task_events) or _safe_int(bundle.get("task_count")),
    }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8-sig") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_events(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tasks: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    if not path.exists():
        return tasks, results

    with path.open(encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("event_type") == "task":
                tasks.append(event)
            elif event.get("event_type") == "result":
                results.append(event)
    return tasks, results


def _sources(artifacts: RunArtifacts) -> set[str]:
    sources = {
        str(event.get("source") or "")
        for event in [*artifacts.task_events, *artifacts.result_events]
        if str(event.get("source") or "").strip()
    }
    for entry in artifacts.data_quality:
        source = str(entry.get("source") or "").strip()
        if source:
            sources.add(source)
    bundle_source = str(artifacts.bundle.get("source") or "").strip()
    if bundle_source:
        sources.add(bundle_source)
    return sources or {"unknown"}


def _safe_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed >= 0 else 0
