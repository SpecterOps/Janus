"""
YAML-backed registry for friction-score recommendation policy.

This is intentionally separate from analyzer_registry.yml: it controls how
friction findings should be actioned, not which analyzers exist or how core
behavior heuristics are resolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


REGISTRY_VERSION = 1
ALLOWED_ACTIONS = {"repair", "document", "automate", "retire", "investigate"}


def default_registry_path() -> Path:
    candidates = [
        Path("/config/friction_score_registry.yml"),
        Path(__file__).resolve().parent.parent / "Config" / "friction_score_registry.yml",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[-1]


@dataclass(frozen=True)
class FrictionScoreRule:
    name: str
    description: str
    match: dict[str, Any]
    suppress_actions: tuple[str, ...]
    fallback_action: str
    reason: str


class FrictionScoreRegistry:
    def __init__(self, *, version: int, rules: list[FrictionScoreRule], source_path: Path) -> None:
        self.version = version
        self.rules = rules
        self.source_path = source_path

    @classmethod
    def from_path(cls, path: Path | None = None) -> "FrictionScoreRegistry":
        registry_path = path or default_registry_path()
        with registry_path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return cls.from_dict(raw, source_path=registry_path)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, source_path: Path) -> "FrictionScoreRegistry":
        version = int(raw.get("version", 0))
        if version != REGISTRY_VERSION:
            raise ValueError(f"friction score registry version must be {REGISTRY_VERSION}, got {version}")

        rules_raw = raw.get("recommendation_rules", [])
        if not isinstance(rules_raw, list):
            raise ValueError("recommendation_rules must be a list")

        rules: list[FrictionScoreRule] = []
        seen_names: set[str] = set()
        for idx, item in enumerate(rules_raw):
            if not isinstance(item, dict):
                raise ValueError(f"recommendation_rules[{idx}] must be a mapping")
            name = str(item.get("name", "")).strip()
            if not name:
                raise ValueError(f"recommendation_rules[{idx}].name is required")
            if name in seen_names:
                raise ValueError(f"duplicate friction score rule name: {name}")
            seen_names.add(name)

            match = _normalize_match(item.get("match"), location=f"recommendation_rules[{idx}].match")
            suppress_actions = _normalize_actions(
                item.get("suppress_actions", []),
                location=f"recommendation_rules[{idx}].suppress_actions",
            )
            fallback_action = str(item.get("fallback_action", "investigate")).strip()
            if fallback_action not in ALLOWED_ACTIONS:
                raise ValueError(
                    f"recommendation_rules[{idx}].fallback_action must be one of {sorted(ALLOWED_ACTIONS)}"
                )
            reason = str(item.get("reason", "")).strip()
            if not reason:
                raise ValueError(f"recommendation_rules[{idx}].reason is required")

            rules.append(
                FrictionScoreRule(
                    name=name,
                    description=str(item.get("description", "")).strip(),
                    match=match,
                    suppress_actions=suppress_actions,
                    fallback_action=fallback_action,
                    reason=reason,
                )
            )

        return cls(version=version, rules=rules, source_path=source_path)

    def first_match(self, *, command_name: str, tool_names: list[str], sources: list[str]) -> FrictionScoreRule | None:
        for rule in self.rules:
            if _matches(rule.match, command_name=command_name, tool_names=tool_names, sources=sources):
                return rule
        return None

    def metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "path": str(self.source_path),
            "rule_count": len(self.rules),
        }


def _normalize_actions(value: Any, *, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{location} must be a non-empty list")
    actions = []
    for item in value:
        action = str(item).strip()
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"{location} contains unsupported action '{action}'")
        actions.append(action)
    return tuple(dict.fromkeys(actions))


def _normalize_match(value: Any, *, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be a mapping")
    allowed_scalar = {"command_name", "tool_name", "source"}
    allowed_list = {"command_names", "tool_names", "sources"}
    unknown = sorted(set(value.keys()) - allowed_scalar - allowed_list)
    if unknown:
        raise ValueError(f"{location} contains unsupported keys: {', '.join(unknown)}")

    normalized: dict[str, Any] = {}
    for key in allowed_scalar:
        if key in value:
            text = str(value[key]).strip().lower()
            if not text:
                raise ValueError(f"{location}.{key} must be non-empty")
            normalized[key] = text
    for key in allowed_list:
        if key in value:
            items = [str(item).strip().lower() for item in value[key] if str(item).strip()]
            if not items:
                raise ValueError(f"{location}.{key} must contain at least one value")
            normalized[key] = sorted(set(items))
    if not normalized:
        raise ValueError(f"{location} must contain at least one match condition")
    return normalized


def _matches(match: dict[str, Any], *, command_name: str, tool_names: list[str], sources: list[str]) -> bool:
    command = command_name.lower()
    tools = {tool.lower() for tool in tool_names}
    source_set = {source.lower() for source in sources}

    if "command_name" in match and match["command_name"] != command:
        return False
    if "command_names" in match and command not in match["command_names"]:
        return False
    if "tool_name" in match and match["tool_name"] not in tools:
        return False
    if "tool_names" in match and not tools.intersection(match["tool_names"]):
        return False
    if "source" in match and match["source"] not in source_set:
        return False
    if "sources" in match and not source_set.intersection(match["sources"]):
        return False
    return True
