"""
Shared behavior registry for analyzer heuristics.

This registry is separate from ``Core/analyzer_registry.py`` which only maps
analyzer names to output filenames. Here we store source-aware, command-aware
behavior hints that analyzers can consult before applying global heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


REGISTRY_VERSION = 1
ALLOWED_BEHAVIOR_CLASSES = {
    "expected_high_entropy",
    "expected_sleep_or_delay",
    "expected_large_structured_args",
    "result_status_unreliable",
}
ALLOWED_DURATION_MODES = {"exclude_from_friction"}


def default_registry_path() -> Path:
    return Path(__file__).resolve().parent.parent / "Config" / "analyzer_registry.yml"


@dataclass(frozen=True)
class BehaviorRule:
    match: dict[str, str]
    behavior_classes: tuple[str, ...]
    command_duration: dict[str, Any]
    parameter_entropy: dict[str, Any]
    argument_position_profile: dict[str, Any]


@dataclass(frozen=True)
class ResolvedBehavior:
    behavior_classes: tuple[str, ...]
    command_duration: dict[str, Any]
    parameter_entropy: dict[str, Any]
    argument_position_profile: dict[str, Any]
    matched_rule: dict[str, str] | None

    def has_class(self, class_name: str) -> bool:
        return class_name in self.behavior_classes


class AnalyzerBehaviorRegistry:
    def __init__(
        self,
        *,
        version: int,
        defaults: dict[str, Any],
        friction_score: dict[str, Any],
        source_defaults: dict[str, dict[str, Any]],
        command_rules: list[BehaviorRule],
        source_path: Path,
    ) -> None:
        self.version = version
        self.defaults = defaults
        self.friction_score = friction_score
        self.source_defaults = source_defaults
        self.command_rules = command_rules
        self.source_path = source_path

    @classmethod
    def from_path(cls, path: Path | None = None) -> "AnalyzerBehaviorRegistry":
        registry_path = path or default_registry_path()
        with registry_path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return cls.from_dict(raw, source_path=registry_path)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, source_path: Path | None = None) -> "AnalyzerBehaviorRegistry":
        version = int(raw.get("version", 0))
        if version != REGISTRY_VERSION:
            raise ValueError(f"analyzer registry version must be {REGISTRY_VERSION}, got {version}")

        defaults = _normalize_behavior_block(raw.get("defaults", {}), location="defaults")
        friction_score = _normalize_friction_score_block(raw.get("friction_score", {}))

        raw_source_defaults = raw.get("source_defaults", {})
        if not isinstance(raw_source_defaults, dict):
            raise ValueError("source_defaults must be a mapping")
        source_defaults = {
            str(source): _normalize_behavior_block(block, location=f"source_defaults.{source}")
            for source, block in raw_source_defaults.items()
        }

        raw_rules = raw.get("commands", [])
        if not isinstance(raw_rules, list):
            raise ValueError("commands must be a list")

        command_rules: list[BehaviorRule] = []
        for idx, item in enumerate(raw_rules):
            if not isinstance(item, dict):
                raise ValueError(f"commands[{idx}] must be a mapping")
            match = item.get("match")
            if not isinstance(match, dict):
                raise ValueError(f"commands[{idx}].match must be a mapping")
            if "command_name" not in match:
                raise ValueError(f"commands[{idx}].match.command_name is required")
            if "tool_name" in match and "source" not in match:
                raise ValueError(f"commands[{idx}] tool_name matching requires source")

            normalized = _normalize_behavior_block(item, location=f"commands[{idx}]")
            command_rules.append(
                BehaviorRule(
                    match={k: str(v) for k, v in match.items()},
                    behavior_classes=tuple(normalized["behavior_classes"]),
                    command_duration=normalized["command_duration"],
                    parameter_entropy=normalized["parameter_entropy"],
                    argument_position_profile=normalized["argument_position_profile"],
                )
            )

        return cls(
            version=version,
            defaults=defaults,
            friction_score=friction_score,
            source_defaults=source_defaults,
            command_rules=command_rules,
            source_path=source_path or default_registry_path(),
        )

    def resolve(self, event: dict[str, Any]) -> ResolvedBehavior:
        source = str(event.get("source", "") or "")
        tool_name = str(event.get("tool_name", "") or "")
        command_name = str(event.get("command_name", "") or "")

        merged = _copy_behavior_block(self.defaults)
        if source in self.source_defaults:
            merged = _merge_behavior_blocks(merged, self.source_defaults[source])

        exact_source_tool_command: BehaviorRule | None = None
        exact_source_command: BehaviorRule | None = None
        exact_command: BehaviorRule | None = None

        for rule in self.command_rules:
            match = rule.match
            if match.get("command_name") != command_name:
                continue
            if "source" in match and match["source"] != source:
                continue
            if "tool_name" in match and match["tool_name"] != tool_name:
                continue

            if "source" in match and "tool_name" in match:
                exact_source_tool_command = rule
                break
            if "source" in match:
                exact_source_command = rule
                continue
            exact_command = rule

        matched_rule = exact_source_tool_command or exact_source_command or exact_command
        for rule in (exact_command, exact_source_command, exact_source_tool_command):
            if not rule:
                continue
            merged = _merge_behavior_blocks(
                merged,
                {
                    "behavior_classes": list(rule.behavior_classes),
                    "command_duration": dict(rule.command_duration),
                    "parameter_entropy": dict(rule.parameter_entropy),
                    "argument_position_profile": dict(rule.argument_position_profile),
                },
            )

        return ResolvedBehavior(
            behavior_classes=tuple(merged["behavior_classes"]),
            command_duration=merged["command_duration"],
            parameter_entropy=merged["parameter_entropy"],
            argument_position_profile=merged["argument_position_profile"],
            matched_rule=matched_rule.match if matched_rule else None,
        )

    def commands_with_behavior_class(self, class_name: str) -> list[str]:
        commands = []
        for rule in self.command_rules:
            if class_name in rule.behavior_classes and rule.match.get("command_name"):
                commands.append(rule.match["command_name"])
        return sorted(set(commands))

    def metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "path": str(self.source_path),
        }


def _normalize_friction_score_block(block: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(block, dict):
        raise ValueError("friction_score must be a mapping")

    default_weights = {
        "failure_rate": 30.0,
        "retry_density": 20.0,
        "retry_to_success_rate": 15.0,
        "p95_duration": 15.0,
        "median_duration": 10.0,
        "callback_health_penalty": 5.0,
        "argument_anomaly_rate": 5.0,
    }
    weights = dict(default_weights)
    raw_weights = block.get("weights", {})
    if raw_weights is not None:
        if not isinstance(raw_weights, dict):
            raise ValueError("friction_score.weights must be a mapping")
        for key, value in raw_weights.items():
            if key not in default_weights:
                raise ValueError(f"friction_score.weights contains unsupported key '{key}'")
            if not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"friction_score.weights.{key} must be a non-negative number")
            weights[key] = float(value)

    sample_thresholds = {
        "high": 10,
        "medium": 5,
    }
    raw_thresholds = block.get("sample_confidence_thresholds", {})
    if raw_thresholds is not None:
        if not isinstance(raw_thresholds, dict):
            raise ValueError("friction_score.sample_confidence_thresholds must be a mapping")
        for key in ("high", "medium"):
            if key in raw_thresholds:
                value = raw_thresholds[key]
                if not isinstance(value, int) or value < 1:
                    raise ValueError(f"friction_score.sample_confidence_thresholds.{key} must be a positive integer")
                sample_thresholds[key] = value
    if sample_thresholds["high"] < sample_thresholds["medium"]:
        raise ValueError("friction_score.sample_confidence_thresholds.high must be >= medium")

    duration_caps = {
        "median_seconds": 300.0,
        "p95_seconds": 900.0,
    }
    raw_caps = block.get("duration_caps", {})
    if raw_caps is not None:
        if not isinstance(raw_caps, dict):
            raise ValueError("friction_score.duration_caps must be a mapping")
        for key in ("median_seconds", "p95_seconds"):
            if key in raw_caps:
                value = raw_caps[key]
                if not isinstance(value, (int, float)) or value <= 0:
                    raise ValueError(f"friction_score.duration_caps.{key} must be a positive number")
                duration_caps[key] = float(value)

    return {
        "weights": weights,
        "sample_confidence_thresholds": sample_thresholds,
        "duration_caps": duration_caps,
    }


def _normalize_behavior_block(block: dict[str, Any], *, location: str) -> dict[str, Any]:
    if not isinstance(block, dict):
        raise ValueError(f"{location} must be a mapping")

    behavior_classes = block.get("behavior_classes", [])
    if not isinstance(behavior_classes, list):
        raise ValueError(f"{location}.behavior_classes must be a list")
    for class_name in behavior_classes:
        if class_name not in ALLOWED_BEHAVIOR_CLASSES:
            raise ValueError(f"{location}.behavior_classes contains unsupported class '{class_name}'")

    command_duration = block.get("command_duration", {})
    if not isinstance(command_duration, dict):
        raise ValueError(f"{location}.command_duration must be a mapping")
    mode = command_duration.get("mode")
    if mode is not None and mode not in ALLOWED_DURATION_MODES:
        raise ValueError(f"{location}.command_duration.mode must be one of {sorted(ALLOWED_DURATION_MODES)}")

    parameter_entropy = block.get("parameter_entropy", {})
    if not isinstance(parameter_entropy, dict):
        raise ValueError(f"{location}.parameter_entropy must be a mapping")
    for field in ("min_expected", "max_expected"):
        if field in parameter_entropy:
            value = parameter_entropy[field]
            if not isinstance(value, (int, float)):
                raise ValueError(f"{location}.parameter_entropy.{field} must be numeric")

    argument_position_profile = block.get("argument_position_profile", {})
    if not isinstance(argument_position_profile, dict):
        raise ValueError(f"{location}.argument_position_profile must be a mapping")
    expected_static = argument_position_profile.get("expected_static", [])
    if not isinstance(expected_static, list):
        raise ValueError(f"{location}.argument_position_profile.expected_static must be a list")
    for idx, entry in enumerate(expected_static):
        if not isinstance(entry, dict):
            raise ValueError(f"{location}.argument_position_profile.expected_static[{idx}] must be a mapping")
        if "position" not in entry or "value" not in entry:
            raise ValueError(f"{location}.argument_position_profile.expected_static[{idx}] requires position and value")

    return {
        "behavior_classes": list(dict.fromkeys(str(c) for c in behavior_classes)),
        "command_duration": dict(command_duration),
        "parameter_entropy": dict(parameter_entropy),
        "argument_position_profile": dict(argument_position_profile),
    }


def _copy_behavior_block(block: dict[str, Any]) -> dict[str, Any]:
    return {
        "behavior_classes": list(block.get("behavior_classes", [])),
        "command_duration": dict(block.get("command_duration", {})),
        "parameter_entropy": dict(block.get("parameter_entropy", {})),
        "argument_position_profile": dict(block.get("argument_position_profile", {})),
    }


def _merge_behavior_blocks(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = _copy_behavior_block(base)
    merged["behavior_classes"] = list(
        dict.fromkeys(merged["behavior_classes"] + list(override.get("behavior_classes", [])))
    )
    merged["command_duration"].update(override.get("command_duration", {}))
    merged["parameter_entropy"].update(override.get("parameter_entropy", {}))
    # For argument_position_profile, merge expected_static lists
    override_app = override.get("argument_position_profile", {})
    if override_app:
        base_static = list(merged["argument_position_profile"].get("expected_static", []))
        override_static = override_app.get("expected_static", [])
        if override_static:
            base_static.extend(override_static)
        merged["argument_position_profile"]["expected_static"] = base_static
    return merged


def build_analyzer_context(path: Path | None = None) -> dict[str, Any]:
    registry = AnalyzerBehaviorRegistry.from_path(path)
    return {
        "behavior_registry": registry,
        "behavior_registry_metadata": registry.metadata(),
        "friction_score": registry.friction_score,
    }
