"""
Ghostwriter raw exporter and normalizer.
"""

import json
import re
import zlib
from datetime import datetime
from pathlib import Path

from Core.io import write_bundle, write_ndjson
from Core.models import ResultEvent, TaskEvent, normalize_timestamp
from Core.output_rule import (
    ARGUMENTS_RULE_ALL,
    OUTPUT_RULE_ALL,
    apply_arguments_rule_to_tasks,
    apply_output_rule_to_results,
    normalize_arguments_rule,
    normalize_output_rule,
)
from Parsers.Ghostwriter.client import GhostwriterClient
from Parsers.Ghostwriter.models import GhostwriterExportMetadata


_CALLBACK_RE = re.compile(r"\bCallback:\s*(\d+)\b", re.IGNORECASE)


def slugify(name: str) -> str:
    """Convert a name to a filesystem-safe slug."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "unnamed"


class GhostwriterPullParser:
    """Export raw Ghostwriter oplog data to local JSON."""

    def __init__(
        self,
        endpoint: str,
        api_token: str,
        verify_tls: bool = True,
        debug: bool = False,
        client: GhostwriterClient | None = None,
    ):
        self.client = client or GhostwriterClient(
            endpoint=endpoint,
            api_token=api_token,
            verify_tls=verify_tls,
            debug=debug,
        )
        self.endpoint = endpoint.rstrip("/")
        self.api_token = api_token
        self.verify_tls = verify_tls
        self.debug = debug

    @classmethod
    def from_credentials(
        cls,
        endpoint: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        debug: bool = False,
    ) -> "GhostwriterPullParser":
        token, _expires = GhostwriterClient.login(
            endpoint=endpoint,
            username=username,
            password=password,
            verify_tls=verify_tls,
            debug=debug,
        )
        return cls(
            endpoint=endpoint,
            api_token=token,
            verify_tls=verify_tls,
            debug=debug,
        )

    def schema_probe(self) -> dict:
        return self.client.probe_schema().to_dict()

    def require_oplog_access(self) -> dict:
        return self.client.require_oplog_access().to_dict()

    def fetch_oplog_name(self, oplog_id: int) -> str:
        rows = self.client.fetch_oplog(oplog_id)
        if not rows:
            return f"oplog-{oplog_id}"
        row = rows[0]
        project = row.get("project") or {}
        return project.get("codename") or row.get("name") or f"oplog-{oplog_id}"

    def export(self, oplog_id: int) -> dict:
        probe = self.client.require_oplog_access()
        oplog_rows = self.client.fetch_oplog(oplog_id)
        oplog = oplog_rows[0] if oplog_rows else None
        oplog_name = self.fetch_oplog_name(oplog_id)
        entries = self.client.fetch_oplog_entries(oplog_id)
        return {
            "source": "ghostwriter",
            "export_format": "ghostwriter_raw",
            "oplog_id": oplog_id,
            "oplog_name": oplog_name,
            "schema_probe": probe.to_dict(),
            "oplog": oplog,
            "entries": entries,
        }

    @classmethod
    def normalize_export(
        cls,
        raw_export: dict,
        oplog_id: int | None = None,
    ) -> tuple[list[TaskEvent], list[ResultEvent], dict]:
        """Normalize Ghostwriter oplog entries into Janus task/result events.

        Ghostwriter oplog exports preserve command chronology well, but do not expose
        reliable execution-status fields like Mythic. Result events are therefore
        emitted with conservative ``unknown`` status unless future schema fields
        provide stronger evidence.
        """
        oplog_id = oplog_id or int(raw_export.get("oplog_id") or 0)
        task_events: list[TaskEvent] = []
        result_events: list[ResultEvent] = []
        skipped_entries = 0
        invalid_timestamp_count = 0
        fallback_task_id_count = 0

        for index, entry in enumerate(raw_export["entries"], start=1):
            start_ts = entry.get("startDate")
            if not start_ts:
                skipped_entries += 1
                continue

            start_ts_normalized = cls._try_normalize_timestamp(start_ts)
            if start_ts_normalized is None:
                skipped_entries += 1
                invalid_timestamp_count += 1
                continue

            task_id, used_fallback = cls._coerce_task_id(
                raw_id=entry.get("id"),
                entry_identifier=(entry.get("entryIdentifier") or "").strip(),
                fallback_index=index,
            )
            if used_fallback:
                fallback_task_id_count += 1
            command_text = (entry.get("command") or "").strip()
            command_name, arguments_raw = cls._split_command(command_text)
            callback_id = cls._parse_callback_id(entry.get("description") or "")
            tool_name = (entry.get("tool") or "ghostwriter").strip().lower() or "ghostwriter"

            task_events.append(
                TaskEvent(
                    source="ghostwriter",
                    operation_id=oplog_id,
                    callback_id=callback_id,
                    callback_display_id=callback_id,
                    task_id=task_id,
                    timestamp=start_ts_normalized,
                    tool_name=tool_name,
                    command_name=command_name,
                    arguments_raw=arguments_raw,
                    c2_task_id=(entry.get("entryIdentifier") or "").strip(),
                )
            )

            result_ts = entry.get("endDate") or start_ts
            result_ts_normalized = cls._try_normalize_timestamp(result_ts) or start_ts_normalized
            result_events.append(
                ResultEvent(
                    source="ghostwriter",
                    operation_id=oplog_id,
                    task_id=task_id,
                    timestamp=result_ts_normalized,
                    status=cls._infer_status(entry),
                    output_text=entry.get("output") or "",
                )
            )

        return task_events, result_events, {
            "raw_export": raw_export,
            "skipped_entries": skipped_entries,
            "invalid_timestamp_count": invalid_timestamp_count,
            "fallback_task_id_count": fallback_task_id_count,
        }

    def normalize(self, oplog_id: int) -> tuple[list[TaskEvent], list[ResultEvent], dict]:
        raw_export = self.export(oplog_id)
        return self.normalize_export(raw_export, oplog_id=oplog_id)

    @staticmethod
    def _split_command(command_text: str) -> tuple[str, str]:
        if not command_text:
            return "unknown", ""
        parts = command_text.split(None, 1)
        command_name = parts[0].strip() or "unknown"
        arguments_raw = parts[1].strip() if len(parts) > 1 else ""
        return command_name, arguments_raw

    @staticmethod
    def _parse_callback_id(description: str) -> int:
        match = _CALLBACK_RE.search(description or "")
        return int(match.group(1)) if match else 0

    @staticmethod
    def _infer_status(entry: dict) -> str:
        """Ghostwriter oplog rows do not currently expose reliable success/error state."""
        _ = entry
        return "unknown"

    @staticmethod
    def _try_normalize_timestamp(raw: str | int | float | None) -> str | None:
        if raw is None:
            return None
        try:
            return normalize_timestamp(raw)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_task_id(raw_id, entry_identifier: str, fallback_index: int) -> tuple[int, bool]:
        """Best-effort task_id coercion with deterministic fallback for non-integer IDs."""
        try:
            task_id = int(raw_id)
            if task_id > 0:
                return task_id, False
        except (TypeError, ValueError):
            pass

        if entry_identifier:
            hashed = zlib.crc32(entry_identifier.encode("utf-8")) & 0x7FFFFFFF
            return hashed or fallback_index, True

        return fallback_index, True

    def run(
        self,
        oplog_id: int,
        out_dir: Path | None = None,
        analysis_timestamp: datetime | None = None,
        oplog_name: str | None = None,
        output_rule: str = OUTPUT_RULE_ALL,
        arguments_rule: str = ARGUMENTS_RULE_ALL,
    ) -> dict:
        out_dir = out_dir or Path("out")
        out_dir.mkdir(parents=True, exist_ok=True)
        task_events, result_events, normalized = self.normalize(oplog_id)
        raw_export = normalized["raw_export"]
        if oplog_name is None:
            oplog_name = raw_export["oplog_name"]

        raw_export_path = out_dir / "raw_export.json"
        with raw_export_path.open("w", encoding="utf-8") as f:
            json.dump(raw_export, f, indent=2, ensure_ascii=False)

        apply_arguments_rule_to_tasks(task_events, arguments_rule)
        apply_output_rule_to_results(result_events, output_rule)
        rule_applied = normalize_output_rule(output_rule)
        args_rule_applied = normalize_arguments_rule(arguments_rule)

        events_ndjson_path = out_dir / "events.ndjson"
        all_events = [e.to_dict() for e in task_events] + [e.to_dict() for e in result_events]
        write_ndjson(all_events, events_ndjson_path)

        status_counts: dict[str, int] = {"success": 0, "error": 0, "unknown": 0}
        for e in result_events:
            status_counts[e.status] += 1

        metadata = GhostwriterExportMetadata(
            source="ghostwriter",
            operation_id=oplog_id,
            operation_name=oplog_name,
            operation_slug=slugify(oplog_name),
            ghostwriter_endpoint=self.client.graphql_url(),
            task_count=len(task_events),
            result_count=len(result_events),
            status_counts=status_counts,
            entry_count=len(raw_export["entries"]),
            skipped_entry_count=normalized["skipped_entries"],
            schema_probe=raw_export["schema_probe"],
        ).to_dict()
        metadata["invalid_timestamp_count"] = normalized["invalid_timestamp_count"]
        metadata["fallback_task_id_count"] = normalized["fallback_task_id_count"]
        metadata["raw_export_path"] = raw_export_path.name
        metadata["events_path"] = events_ndjson_path.name
        metadata["output_rule"] = rule_applied
        metadata["arguments_rule"] = args_rule_applied

        write_bundle(metadata, out_dir / "bundle.json", analysis_timestamp)
        return metadata
