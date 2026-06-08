# Janus Ingestor Patterns

## Source Mode Decision

- **Live API pull**: Use when Janus can authenticate to a service and fetch structured source records directly. Follow the Cobalt Strike REST, Mythic, or Ghostwriter pattern.
- **Local file/directory load**: Use when telemetry is already exported or lives on disk. Follow partial Mythic or Outflank patterns.
- **Hybrid**: Use when an API client fetches or exports raw source data, then a local normalizer converts the raw payload. Keep fetch/export separate from normalization.

## Parser Shape

Prefer this structure:

- Source constants: `SOURCE`, `TOOL_NAME`.
- Small helpers for slugging, timestamp coercion, ID coercion, and status inference.
- A parser class with `normalize()` returning `(task_events, result_events, metadata)`.
- A `run_*_ingest()` function that writes `events.ndjson` and `bundle.json`.

Keep raw-source parsing separate from artifact writing so tests can exercise normalization without filesystem side effects.

## Live API Checklist

- Resolve endpoint/auth from CLI, environment, and config in a documented precedence order.
- Add preflight that proves connectivity, auth, and minimum schema availability before writing output.
- Handle pagination or large-response limits intentionally.
- Keep TLS verification enabled by default; expose `--insecure` or config `verify_tls: false` only as an explicit lab escape hatch.
- Avoid persisting secrets in bundles, logs, or analyzer output.
- Record endpoint provenance in bundle metadata when it is not sensitive.
- Add Docker loopback hints when host-local endpoints commonly fail from inside the container.

## Local File Checklist

- Support a single file when that is the source-native unit.
- Support a directory when operators naturally collect multiple files for one run.
- Treat malformed records intentionally: skip with counters or fail early with clear errors.
- Record source path(s), file counts, parsed/skipped counts, invalid timestamp counts, and any fallback ID counts.
- For `janus-cli`, ensure input paths are visible inside Docker. Existing wrapper mounts `./out` as `/data/out` and `./Config` as `/config`.

## CLI And Config Checklist

- Python `janus.py`:
  - import the parser
  - add source or loader arguments
  - add dispatch branch
  - pass retention rules into ingest
  - create/update latest markers when versioning is enabled
- Go `janus-cli`:
  - add config struct fields
  - update source resolution
  - add source-specific flag handling
  - map host paths to container paths safely
  - update `status` and `config` output
- Docs/config:
  - update `Config/janus.example.yml`
  - update README usage
  - update architecture source coverage and event caveats
  - add FAQ notes for source-specific operator pitfalls

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

