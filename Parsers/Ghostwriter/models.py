"""
Models for Ghostwriter raw export metadata.
"""

from dataclasses import dataclass, field


@dataclass
class GhostwriterSchemaProbe:
    """Capture the live GraphQL surface exposed to the current token."""

    query_fields: list[str] = field(default_factory=list)
    mutation_fields: list[str] = field(default_factory=list)
    expected_query_fields: list[str] = field(default_factory=lambda: ["oplog", "oplogEntry"])

    @property
    def missing_query_fields(self) -> list[str]:
        return [name for name in self.expected_query_fields if name not in self.query_fields]

    @property
    def oplog_access_ok(self) -> bool:
        return not self.missing_query_fields

    def to_dict(self) -> dict:
        return {
            "query_fields": self.query_fields,
            "mutation_fields": self.mutation_fields,
            "expected_query_fields": self.expected_query_fields,
            "missing_query_fields": self.missing_query_fields,
            "oplog_access_ok": self.oplog_access_ok,
        }


@dataclass
class GhostwriterExportMetadata:
    """Metadata written alongside the raw Ghostwriter export."""

    source: str
    operation_id: int
    operation_name: str
    operation_slug: str
    ghostwriter_endpoint: str
    export_format: str = "ghostwriter_raw"
    task_count: int = 0
    result_count: int = 0
    status_counts: dict = field(default_factory=dict)
    entry_count: int = 0
    skipped_entry_count: int = 0
    schema_probe: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "operation_id": self.operation_id,
            "operation_name": self.operation_name,
            "operation_slug": self.operation_slug,
            "ghostwriter_endpoint": self.ghostwriter_endpoint,
            "export_format": self.export_format,
            "task_count": self.task_count,
            "result_count": self.result_count,
            "status_counts": self.status_counts,
            "entry_count": self.entry_count,
            "skipped_entry_count": self.skipped_entry_count,
            "schema_probe": self.schema_probe,
        }
