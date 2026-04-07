"""
ToolDump - Export registry-driven command/task subsets for downstream datasets.

This analyzer matches normalized task events against a dedicated YAML registry
and writes per-group plain-text dumps of the matching commands. The JSON output
stays inside the normal Janus analyzer flow while the text dumps make it easy to
build external corpora around specific tools or command families.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from Core.output_rule import copy_task_retention_fields


REGISTRY_VERSION = 1


def default_registry_path() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "Config" / "tool_dump_registry.yml"


@dataclass(frozen=True)
class ToolDumpRule:
    name: str
    description: str
    match: dict[str, Any]


class ToolDumpRegistry:
    def __init__(self, *, version: int, groups: list[ToolDumpRule], source_path: Path) -> None:
        self.version = version
        self.groups = groups
        self.source_path = source_path

    @classmethod
    def from_path(cls, path: Path | None = None) -> "ToolDumpRegistry":
        registry_path = path or default_registry_path()
        with registry_path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return cls.from_dict(raw, source_path=registry_path)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, source_path: Path) -> "ToolDumpRegistry":
        version = int(raw.get("version", 0))
        if version != REGISTRY_VERSION:
            raise ValueError(f"tool dump registry version must be {REGISTRY_VERSION}, got {version}")

        groups_raw = raw.get("groups", [])
        if not isinstance(groups_raw, list):
            raise ValueError("groups must be a list")

        groups: list[ToolDumpRule] = []
        seen_names: set[str] = set()

        for idx, item in enumerate(groups_raw):
            if not isinstance(item, dict):
                raise ValueError(f"groups[{idx}] must be a mapping")

            name = str(item.get("name", "")).strip()
            if not name:
                raise ValueError(f"groups[{idx}].name is required")
            if name in seen_names:
                raise ValueError(f"duplicate tool dump group name: {name}")
            seen_names.add(name)

            match = item.get("match")
            if not isinstance(match, dict):
                raise ValueError(f"groups[{idx}].match must be a mapping")

            groups.append(
                ToolDumpRule(
                    name=name,
                    description=str(item.get("description", "")).strip(),
                    match=_normalize_match(match, location=f"groups[{idx}].match"),
                )
            )

        return cls(version=version, groups=groups, source_path=source_path)

    def metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "path": str(self.source_path),
            "group_count": len(self.groups),
        }


def _normalize_match(match: dict[str, Any], *, location: str) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    allowed_scalar = {"source", "tool_name", "command_name", "issued_command_name", "arguments_contains"}
    allowed_list = {"sources", "tool_names", "command_names", "issued_command_names", "arguments_contains_any"}
    allowed_keys = allowed_scalar | allowed_list

    unknown = sorted(set(match.keys()) - allowed_keys)
    if unknown:
        raise ValueError(f"{location} contains unsupported keys: {', '.join(unknown)}")

    for key in allowed_scalar:
        if key in match:
            value = match[key]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{location}.{key} must be a non-empty string")
            normalized[key] = value.strip().lower()

    for key in allowed_list:
        if key in match:
            value = match[key]
            if not isinstance(value, list) or not value:
                raise ValueError(f"{location}.{key} must be a non-empty list")
            normalized[key] = [str(item).strip().lower() for item in value if str(item).strip()]
            if not normalized[key]:
                raise ValueError(f"{location}.{key} must contain at least one non-empty value")

    if not normalized:
        raise ValueError(f"{location} must contain at least one matcher")
    return normalized


def _event_matches(task: dict[str, Any], match: dict[str, Any]) -> bool:
    source = str(task.get("source", "") or "").lower()
    tool_name = str(task.get("tool_name", "") or "").lower()
    command_name = str(task.get("command_name", "") or "").lower()
    issued_command_name = str(task.get("issued_command_name", "") or "").lower()
    arguments_raw = str(task.get("arguments_raw", "") or "")
    arguments_lower = arguments_raw.lower()

    if "source" in match and source != match["source"]:
        return False
    if "sources" in match and source not in match["sources"]:
        return False
    if "tool_name" in match and tool_name != match["tool_name"]:
        return False
    if "tool_names" in match and tool_name not in match["tool_names"]:
        return False
    if "command_name" in match and command_name != match["command_name"]:
        return False
    if "command_names" in match and command_name not in match["command_names"]:
        return False
    if "issued_command_name" in match and issued_command_name != match["issued_command_name"]:
        return False
    if "issued_command_names" in match and issued_command_name not in match["issued_command_names"]:
        return False
    if "arguments_contains" in match and match["arguments_contains"] not in arguments_lower:
        return False
    if "arguments_contains_any" in match and not any(token in arguments_lower for token in match["arguments_contains_any"]):
        return False
    return True


def _full_command(task: dict[str, Any]) -> str:
    command_name = str(task.get("command_name", "") or "").strip()
    arguments_raw = str(task.get("arguments_raw", "") or "").strip()
    if command_name and arguments_raw:
        return f"{command_name} {arguments_raw}"
    retained = str(task.get("arguments_retained", "") or "")
    if command_name and retained == "drop":
        return f"{command_name} [arguments redacted]"
    if command_name and retained == "hash":
        digest = str(task.get("arguments_digest", "") or "")
        short = digest[:20] + "..." if len(digest) > 20 else digest
        return f"{command_name} [args hash: {short or 'unavailable'}]"
    if command_name and retained == "features_only":
        shape = str(task.get("arguments_shape", "") or "")
        length = task.get("arguments_length", 0)
        summary = f"{shape}, {length} chars" if shape else f"{length} chars"
        return f"{command_name} [args features: {summary}]"
    return command_name or arguments_raw


def _write_text_dump(output_dir: Path, group_name: str, lines: list[str]) -> str:
    dump_dir = output_dir / "tool_dumps"
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = dump_dir / f"{group_name}.txt"
    content = "\n".join(lines)
    if content:
        content += "\n"
    dump_path.write_text(content, encoding="utf-8")
    return str(dump_path)


def analyze(
    task_events: list[dict],
    result_events: list[dict],
    context: dict | None = None,
) -> dict:
    """Match task events against registry-defined dump groups."""
    del result_events

    ctx = context or {}
    registry_path = ctx.get("tool_dump_registry_path")
    registry = ToolDumpRegistry.from_path(Path(registry_path) if registry_path else None)

    output_dir_value = ctx.get("output_dir")
    output_dir = Path(output_dir_value) if output_dir_value else None

    groups_output = []
    total_matches = 0

    for group in registry.groups:
        matches = []
        dump_lines = []
        unique_commands: set[str] = set()
        unique_tools: set[str] = set()

        for task in task_events:
            if not _event_matches(task, group.match):
                continue

            full_command = _full_command(task)
            entry = {
                "task_id": task.get("task_id"),
                "display_id": task.get("display_id"),
                "callback_id": task.get("callback_id"),
                "callback_display_id": task.get("callback_display_id"),
                "operation_id": task.get("operation_id"),
                "timestamp": task.get("timestamp"),
                "source": task.get("source"),
                "tool_name": task.get("tool_name"),
                "command_name": task.get("command_name"),
                "issued_command_name": task.get("issued_command_name", ""),
                "arguments_raw": task.get("arguments_raw", ""),
                "full_command": full_command,
                **copy_task_retention_fields(task),
            }
            matches.append(entry)
            dump_lines.append(full_command)
            if entry["command_name"]:
                unique_commands.add(str(entry["command_name"]))
            if entry["tool_name"]:
                unique_tools.add(str(entry["tool_name"]))

        dump_path = ""
        if output_dir is not None and dump_lines:
            dump_path = _write_text_dump(output_dir, group.name, dump_lines)

        total_matches += len(matches)
        groups_output.append(
            {
                "name": group.name,
                "description": group.description,
                "match": group.match,
                "match_count": len(matches),
                "unique_command_count": len(unique_commands),
                "unique_tool_count": len(unique_tools),
                "dump_path": dump_path,
                "entries": matches,
            }
        )

    populated_groups = sum(1 for group in groups_output if group["match_count"] > 0)
    return {
        "summary": {
            "total_tasks": len(task_events),
            "groups_defined": len(groups_output),
            "groups_with_matches": populated_groups,
            "total_matches": total_matches,
        },
        "groups": groups_output,
        "registry": registry.metadata(),
    }
