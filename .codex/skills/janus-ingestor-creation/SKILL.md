---
name: janus-ingestor-creation
description: Use this skill for Janus requests to design, add, or adjust source ingestors/parsers for live APIs or local files, including Mythic, Ghostwriter, Cobalt Strike REST, Outflank implant logs, new C2 telemetry sources, parser normalization, pull/load CLI wiring, source metadata, retention policy handling, and Docker janus-cli integration.
---

# Janus Ingestor Creation

## Overview

Use this skill when Janus needs to ingest a new telemetry source or change how an existing source is pulled, loaded, normalized, or wired into the CLI.

Start from Janus's existing ingest pipeline. Do not create a parallel pipeline unless the user explicitly asks for one.

## Workflow

1. State the source and mode in one sentence:
   - live API pull
   - local file/directory load
   - hybrid pull plus local normalization
2. Read the core ingest path first:
   - `janus.py`
   - `Core/models.py`
   - `Core/io.py`
   - `Core/output_rule.py`
   - `Config/janus.example.yml`
   - `docs/architecture.md`
3. If `janus-cli` should expose the ingestor, also read:
   - `cmd/janus-cli/config.go`
   - `cmd/janus-cli/main.go`
   - `cmd/janus-cli/status.go`
   - `cmd/janus-cli/docker.go`
4. Read the closest existing source implementation:
   - Mythic live API: `Parsers/Mythic/mythic_pull.py`
   - Partial/local Mythic: `Parsers/Mythic/partial_data_adapter.py`
   - Ghostwriter live/export: `Parsers/Ghostwriter/ghostwriter_pull.py`, `Parsers/Ghostwriter/main.py`
   - Cobalt Strike REST live API: `Parsers/CobaltStrike/cobalt_strike_rest.py`
   - Outflank local logs: `Parsers/Outflank/outflank_log.py`
5. Inspect the provided sample data, client, schema, or API docs before asking the user. Ask only for missing product intent or an undiscoverable endpoint/schema detail.
6. Implement the smallest source-specific parser that preserves the canonical Janus event model.

For the detailed implementation checklist and source-mode guidance, read `references/ingestor-patterns.md`.

## Event Model Rules

- Normalize all sources into `TaskEvent` and `ResultEvent`.
- Join task/result events by `(operation_id, task_id)`.
- Use `normalize_timestamp()` for all timestamps.
- Keep parser-specific quirks in the parser module, not in analyzers.
- For string source IDs, derive stable positive integer IDs, and preserve the raw source task ID in `c2_task_id` when available.
- Emit conservative `status` values:
  - Use `success` / `error` only when the source provides reliable status or a narrowly documented inference.
  - Use `unknown` when status fidelity is weak.
- Apply `arguments_rule` and `output_rule` before writing `events.ndjson`.
- Record parser quality counters in `bundle.json`: row counts, skipped counts, invalid timestamps, fallback IDs, status counts, and source provenance.

## Integration Rules

- Put new parser code under `Parsers/<Source>/`; do not overwrite or repurpose existing ingestors.
- Keep source identifiers stable and lowercase, such as `mythic`, `ghostwriter`, `cobaltstrike-rest`, or `outflank`.
- Add explicit Python CLI support for the new source or loader in `janus.py`.
- Add Go wrapper support when the source should work through `janus-cli pull` or `janus-cli run`.
- Update config examples, status/config output, README usage, and architecture/FAQ docs when behavior is user-facing.
- For live APIs, add auth/preflight behavior and TLS defaults consistent with existing sources.
- For local files, document Docker mount assumptions; `janus-cli` normally exposes `./out` and `./Config` to the container.

## Validation

Always run at least one real CLI/container path after implementation:

- Parser-level import or focused unit test.
- Source load/pull into `events.ndjson` and `bundle.json`.
- `analyze --all` against the generated events.
- `html` report generation.
- `go test` for `cmd/janus-cli` when Go wrapper code changed.

Report source fidelity limits in the final answer, especially for status inference and partial/local datasets.

