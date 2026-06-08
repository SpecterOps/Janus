Use this command for Janus requests to design, add, or adjust source ingestors/parsers for live APIs or local files, including Mythic, Ghostwriter, Cobalt Strike REST, Outflank implant logs, new C2 telemetry sources, parser normalization, pull/load CLI wiring, source metadata, retention policy handling, and Docker janus-cli integration.

## Overview

Use this when Janus needs to ingest a new telemetry source or change how an existing source is pulled, loaded, normalized, or wired into the CLI.

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
5. Inspect provided sample data, client code, schema, or API docs before asking the user. Ask only for missing product intent or an undiscoverable endpoint/schema detail.
6. Implement the smallest source-specific parser that preserves the canonical Janus event model.

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

## Source Mode Guidance

### Live API Pull

Use when Janus can authenticate to a service and fetch structured source records directly. Follow the Cobalt Strike REST, Mythic, or Ghostwriter pattern.

- Resolve endpoint/auth from CLI, environment, and config in a documented precedence order.
- Add preflight that proves connectivity, auth, and minimum schema availability before writing output.
- Handle pagination or large-response limits intentionally.
- Keep TLS verification enabled by default; expose `--insecure` or config `verify_tls: false` only as an explicit lab escape hatch.
- Avoid persisting secrets in bundles, logs, or analyzer output.
- Record endpoint provenance in bundle metadata when it is not sensitive.
- Add Docker loopback hints when host-local endpoints commonly fail from inside the container.

### Local File Or Directory Load

Use when telemetry is already exported or lives on disk. Follow partial Mythic or Outflank patterns.

- Support a single file when that is the source-native unit.
- Support a directory when operators naturally collect multiple files for one run.
- Treat malformed records intentionally: skip with counters or fail early with clear errors.
- Record source path(s), file counts, parsed/skipped counts, invalid timestamp counts, and fallback ID counts.
- For `janus-cli`, ensure input paths are visible inside Docker. Existing wrapper mounts `./out` as `/data/out` and `./Config` as `/config`.

### Hybrid Pull Plus Normalization

Use when an API client fetches or exports raw source data, then a local normalizer converts the raw payload.

- Keep fetch/export separate from normalization.
- Let tests exercise normalization without a live service.
- Record raw export format and source provenance in the bundle.

## Parser Shape

Prefer this structure:

- Source constants: `SOURCE`, `TOOL_NAME`
- Small helpers for slugging, timestamp coercion, ID coercion, and status inference
- A parser class with `normalize()` returning `(task_events, result_events, metadata)`
- A `run_*_ingest()` function that writes `events.ndjson` and `bundle.json`

Keep raw-source parsing separate from artifact writing so tests can exercise normalization without filesystem side effects.

## CLI And Config Checklist

Python `janus.py`:

- Import the parser.
- Add source or loader arguments.
- Add a dispatch branch.
- Pass retention rules into ingest.
- Create/update latest markers when versioning is enabled.

Go `janus-cli`:

- Add config struct fields.
- Update source resolution.
- Add source-specific flag handling.
- Map host paths to container paths safely.
- Update `status` and `config` output.

Docs/config:

- Update `Config/janus.example.yml`.
- Update README usage.
- Update architecture source coverage and event caveats.
- Add FAQ notes for source-specific operator pitfalls.

## Metadata Checklist

Every new ingestor should include:

- `source`
- `tool_name`
- `operation_id`
- `operation_name`
- `operation_slug`
- `task_count`
- `result_count`
- `status_counts`
- `output_rule`
- `arguments_rule`
- source-specific provenance such as endpoint, log path, project/oplog ID, or export format
- parser quality counters relevant to the source

## Status Fidelity

Prefer honest degradation:

- Mythic supports strong status semantics.
- Ghostwriter currently has weak execution status and should default to `unknown`.
- Cobalt Strike REST can map task status, result, and error fields when present.
- Outflank local logs can infer obvious response-text errors, but should not pretend to have full execution-state fidelity.

Document any source-specific inference in `docs/architecture.md` and final user output.

## Validation

Always run at least one real CLI/container path after implementation:

- Parser-level import or focused unit test.
- Source load/pull into `events.ndjson` and `bundle.json`.
- `analyze --all` against the generated events.
- `html` report generation.
- `go test` for `cmd/janus-cli` when Go wrapper code changed.

Report source fidelity limits in the final answer, especially for status inference and partial/local datasets.

