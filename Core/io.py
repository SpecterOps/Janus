"""
Output writers for Janus.

Writes normalized events to NDJSON and bundle metadata to JSON.
"""

import json
import os
import platform
import tomllib
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path


class EventValidationError(Exception):
    """Raised when an event fails schema validation."""


REQUIRED_TASK_FIELDS = ("task_id", "command_name", "timestamp")
REQUIRED_RESULT_FIELDS = ("task_id", "status", "timestamp", "output_text")


def validate_events(events: list[dict]) -> None:
    """Assert all events have required fields. Fail fast on schema drift."""
    for i, event in enumerate(events):
        etype = event.get("event_type")
        if etype == "task":
            required = REQUIRED_TASK_FIELDS
        elif etype == "result":
            required = REQUIRED_RESULT_FIELDS
        else:
            raise EventValidationError(
                f"Event {i}: unknown event_type {etype!r}"
            )
        for field in required:
            if field not in event or event[field] is None:
                raise EventValidationError(
                    f"Event {i} ({etype}): missing or null field '{field}'"
                )


def get_janus_version() -> str:
    """Return the Janus package version from installed metadata or source."""
    try:
        return metadata.version("janus")
    except metadata.PackageNotFoundError:
        pass

    try:
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        return data.get("project", {}).get("version", "unknown")
    except Exception:
        return "unknown"


def get_versioned_output_dir(
    base_dir: Path, operation_slug: str, timestamp: datetime | None = None
) -> Path:
    """
    Generate versioned output directory path like: out/my-operation_20260213_143022/

    ``operation_slug`` is a filesystem-safe slug (see
    ``Parsers.Mythic.mythic_pull.slugify``).  Legacy callers that still
    pass an int will be coerced via ``str()``.

    If timestamp is None, use current UTC time.
    If directory exists, add UUID suffix to avoid collisions.
    """
    if isinstance(operation_slug, int):
        operation_slug = f"op-{operation_slug}"

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    version_str = timestamp.strftime("%Y%m%d_%H%M%S")
    dir_name = f"{operation_slug}_{version_str}"
    versioned_dir = base_dir / dir_name

    # Handle clock skew / multiple runs per second
    if versioned_dir.exists():
        unique_suffix = str(uuid.uuid4())[:8]
        dir_name = f"{operation_slug}_{version_str}_{unique_suffix}"
        versioned_dir = base_dir / dir_name

    return versioned_dir


def create_latest_symlink(base_dir: Path, versioned_dir: Path) -> None:
    """
    Create/update 'latest' symlink to point to versioned_dir.
    On Windows or if symlink fails, use marker file fallback.
    """
    latest_link = base_dir / "latest"
    is_windows = platform.system() == "Windows"

    # Try symlink approach first (Unix/Linux/Mac)
    if not is_windows:
        try:
            # Remove existing symlink if present
            if latest_link.is_symlink():
                latest_link.unlink()
            elif latest_link.exists():
                # If it's a file/dir, remove it
                if latest_link.is_dir():
                    latest_link.rmdir()
                else:
                    latest_link.unlink()

            # Create new symlink (relative path for portability)
            latest_link.symlink_to(versioned_dir.name, target_is_directory=True)
            return
        except (OSError, NotImplementedError):
            pass  # Fall through to marker file approach

    # Fallback: marker file approach (Windows or symlink failed)
    marker_file = base_dir / "latest.txt"
    marker_file.write_text(versioned_dir.name, encoding="utf-8")


def write_ndjson(events: list[dict], path: Path) -> None:
    """Write events as one JSON object per line, sorted by timestamp."""
    validate_events(events)
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
    with path.open("w", encoding="utf-8") as f:
        for event in sorted_events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def write_bundle(
    metadata: dict, path: Path, analysis_timestamp: datetime | None = None
) -> None:
    """
    Write bundle metadata JSON with versioning fields.

    If analysis_timestamp is provided, enrich metadata with:
    - analysis_version (YYYYMMDD_HHMMSS)
    - analysis_timestamp (ISO 8601 UTC)
    - janus_version
    """
    if analysis_timestamp is not None:
        version_str = analysis_timestamp.strftime("%Y%m%d_%H%M%S")
        timestamp_iso = analysis_timestamp.isoformat().replace("+00:00", "Z")

        metadata["analysis_version"] = version_str
        metadata["analysis_timestamp"] = timestamp_iso
        metadata["janus_version"] = get_janus_version()

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
