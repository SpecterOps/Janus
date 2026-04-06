"""
YAML-backed registry of AV process signatures for the av-tracker analyzer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


REGISTRY_VERSION = 1


def default_registry_path() -> Path:
    return Path(__file__).resolve().parent.parent / "Config" / "av_signature_registry.yml"


@dataclass(frozen=True)
class VendorSignature:
    vendor_key: str
    display_name: str
    executables: tuple[str, ...]


@dataclass(frozen=True)
class AVSignatureRegistry:
    version: int
    vendors: dict[str, VendorSignature]
    source_path: Path

    @classmethod
    def from_path(cls, path: Path | None = None) -> "AVSignatureRegistry":
        registry_path = path or default_registry_path()
        with registry_path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return cls.from_dict(raw, source_path=registry_path)

    @classmethod
    def from_dict(cls, raw: dict, *, source_path: Path | None = None) -> "AVSignatureRegistry":
        version = int(raw.get("version", 0))
        if version != REGISTRY_VERSION:
            raise ValueError(f"AV signature registry version must be {REGISTRY_VERSION}, got {version}")

        raw_vendors = raw.get("vendors", {})
        if not isinstance(raw_vendors, dict) or not raw_vendors:
            raise ValueError("vendors must be a non-empty mapping")

        vendors: dict[str, VendorSignature] = {}
        for vendor_key, raw_vendor in raw_vendors.items():
            if not isinstance(raw_vendor, dict):
                raise ValueError(f"vendors.{vendor_key} must be a mapping")

            display_name = str(raw_vendor.get("display_name") or "").strip()
            if not display_name:
                raise ValueError(f"vendors.{vendor_key}.display_name is required")

            raw_executables = raw_vendor.get("executables", [])
            if not isinstance(raw_executables, list) or not raw_executables:
                raise ValueError(f"vendors.{vendor_key}.executables must be a non-empty list")

            executables = []
            seen_lower = set()
            for idx, entry in enumerate(raw_executables):
                exe_name = str(entry or "").strip()
                if not exe_name:
                    raise ValueError(f"vendors.{vendor_key}.executables[{idx}] must be non-empty")
                exe_lower = exe_name.lower()
                if exe_lower in seen_lower:
                    continue
                seen_lower.add(exe_lower)
                executables.append(exe_name)

            vendors[str(vendor_key)] = VendorSignature(
                vendor_key=str(vendor_key),
                display_name=display_name,
                executables=tuple(executables),
            )

        return cls(
            version=version,
            vendors=vendors,
            source_path=source_path or default_registry_path(),
        )

    def metadata(self) -> dict:
        return {
            "version": self.version,
            "path": str(self.source_path),
            "vendor_count": len(self.vendors),
        }
