# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-04-24

### Added

- **Configurable Mythic response pagination**: Added `--response-page-size` for Mythic `pull` / `run` workflows and `mythic.response_page_size` in config so large `response_text` rows can be pulled with smaller GraphQL pages. Pull metadata now records the resolved `responses_page_size`.

## [1.0.3] - 2026-04-23

### Changed

- **Mythic response pagination hardening**: Janus now fetches Mythic `response` rows in smaller GraphQL pages (`response.id` cursor, ascending order, 500 rows per request) instead of issuing one unbounded operation-wide response query. This reduces the chance of Hasura/Postgres out-of-memory failures when pulling long engagements with large command output while preserving the existing normalized output and CLI behavior.

## [1.0.2] — 2026-04-22

### Added

- **Mythic PTY provenance fields**: PTY session, transport, and synthetic shell-line events now emit first-class schema fields instead of hiding PTY metadata in retention dictionaries. New task fields include `pty_session`, `pty_transport_event`, `pty_parent_task_id`, `pty_input_task_id`, `pty_sequence`, `pty_input_raw`, `pty_input_message_ids`, `pty_child_count`, and `pty_interactive_message_count`. New result fields include `pty_sequence`, `pty_output_message_ids`, `pty_output_preface`, `pty_exit_observed`, `pty_exit_timestamp`, and `pty_exit_code`.
- **Interactive PTY message attribution**: Synthetic PTY task/result pairs now preserve source interactive message IDs for input and output rows, use per-session sequence numbers, and timestamp synthetic results from observed output or exit messages when available.
- **PTY exit capture**: Mythic interactive stream parsing now records observed PTY exit messages, exit timestamps, and integer exit codes when the exit payload parses cleanly.

### Changed

- **PTY retention handling**: `arguments_rule` now clears `pty_input_raw` alongside `arguments_raw`; `output_rule` now clears `pty_output_preface` alongside `output_text`, preserving privacy expectations for PTY-specific content.
- **PTY architecture docs**: The normalized event model now documents PTY-specific task and result fields so downstream consumers can rely on the emitted schema.

## [1.0.1] — 2026-04-20

### Added

- **Mythic PTY-aware ingest**: Interactive PTY sessions keep the parent `pty` launch task; in-session commands are normalized as synthetic task/result pairs (negative `task_id`, metadata such as `pty_synthetic`, `pty_parent_task_id`, `pty_input_task_id`). Optional GraphQL query for Hasura `interactive` rows when exposed; otherwise child `pty` UI task rows are parsed from `original_params`. Bundle metadata includes `pty_interactive_query_available`.
- **PTY nested command grouping for analyzers**: Tasks with `pty_synthetic` roll up under the logical bucket **`pty_in_session`** (not under bare `cd` / `pwd` / `ls`, etc.) so session-scaled timings do not skew standalone command stats. Duration rows and HTML can carry **`pty_shell_command`** for the real shell line. Registry adds Mythic **`pty_in_session`** with `command_duration.mode: exclude_from_friction` alongside **`pty`**.
- **Argument position profile**: PTY in-session lines use per-shell keys **`pty_in_session::<shell>`** (e.g. `pty_in_session::cd`) so the per-command breakdown is interpretable; HTML labels them as **PTY ▸ (shell)** with an explanatory note when present.
- **Analyzer registry**: Mythic `pty` uses `command_duration.mode: exclude_from_friction` so session lifetime is not treated as operator friction.
- **Tests**: `Tests/test_mythic_pty_ingest.py` and fixtures under `Tests/fixtures/mythic_pty/`.

### Changed

- **`command_duration` analyzer**: Registry exclusion for friction metrics now applies whenever `command_duration.mode` is `exclude_from_friction` (not only when paired with `expected_sleep_or_delay`), so registry-only rules such as Mythic `pty` / `pty_in_session` take effect. PTY synthetics bucket separately; **`pty_shell_command`** is preserved on **`max_event`** and outlier rows for JSON and HTML.
- **Other analyzers**: `command_failure_summary`, `argument_position_profile`, `parameter_entropy`, `command_retry_success` (PTY groups use operation + shell command), `dwell_time`, and `outlier_context` use the same PTY grouping rules where they key by command name.
- **HTML report**: Duration max/outlier command text shows nested PTY lines as `pty_in_session → …` via `_format_duration_row_command`; the duration table’s **pty_in_session** row can show **slowest line: …** from the max event.

### Repository

- **`.gitignore`**: Ignore common testing/coverage artifacts (e.g. `.pytest_cache/`, `.coverage`, `htmlcov/`), local `.venv/`, and build metadata (`*.egg-info/`, `build/`).

### Mythic — refreshing data after an upgrade

Older `events.ndjson` / bundles do not gain PTY normalization retroactively. To ingest with the new parser and analyzers:

1. Use this Janus tree (or rebuild/install your CLI from it).
2. In **Config/janus.yml**, set **`mythic.endpoint`**, **`mythic.api_token`**, and **`mythic.operation_id`** (numeric ID of the operation in Mythic). Adjust **`mythic.verify_tls`** if you use self-signed HTTPS.
3. Run a **full pull** for that operation, e.g. `./janus-cli run --source mythic --operation-id <id>` (or rely on `mythic.operation_id` in config if your CLI supports it). This rewrites `out/.../events.ndjson`, `bundle.json`, and analyzer outputs.
4. In **`bundle.json`**, check **`pty_interactive_query_available`**: `true` means Hasura exposed the `interactive` query; `false` is OK — ingest still uses PTY child tasks and parent `stdout`/`stderr` where present.

## [1.0.0] — 2026-04-18

Initial tracked release (project version in `pyproject.toml`). Earlier history was not recorded in this file.

<!-- Release links: add compare URLs here when the public repo is fixed. -->
