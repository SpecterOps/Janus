# Architecture

Janus follows this pipeline: ingest source data, normalize it into a shared event stream, run analyzers, and write a versioned analysis bundle.

## System Shape

The live entrypoint is `janus.py`. In the normal operator workflow, `janus-cli` prepares Docker mounts and invokes the Python CLI inside the container; the Python runtime is not usually executed directly on the host.

The main boundaries are:

- `./Config` mounted read-only as `/config`
- `./out` mounted read/write as `/data/out`
- CLI path inputs for `--events`, `merge`, and `multi-analyze` must resolve under `out/`
- TLS verification enabled by default; `verify_tls: false` or `--insecure` are explicit escape hatches

## Docker wrapper networking

`janus-cli` does not run Python on the host by default: it builds a standard `docker run` with bind mounts (`./out` → `/data/out`, `./Config` → `/config`) and passes the Janus subcommand (`run`, `pull`, `analyze`, and so on) to the image entrypoint.

**Loopback in config is container loopback.** Any URL in `Config/janus.yml` that uses `127.0.0.1`, `localhost`, or `::1` resolves inside the **Janus container**. If the real service binds on the **host** (typical for lab teamservers, local Ghostwriter, or Mythic), connections fail with **connection refused** unless you change networking or the URL.

**Controls** (applied to `docker run` before volume mounts):

| Mechanism | Purpose |
| --- | --- |
| `janus-cli --docker-network <mode>` | Global (before subcommand) or per-command flag; maps to `docker run --network`. |
| `janus-cli --docker-add-host <host:ip>` | Appends `--add-host` (e.g. `host.docker.internal:host-gateway` on Linux bridge). |
| `docker.network_mode` / `docker.run_extra` in `janus.yml` | Persistent operator settings for “weird enclaves”; see [Config/janus.example.yml](../Config/janus.example.yml). |
| `JANUS_DOCKER_RUN_EXTRA` | Space-separated extra `docker run` tokens; lowest precedence for `--network` versus CLI/config. |

**Precedence for `--network`:** CLI `--docker-network` beats `docker.network_mode`, which replaces any `--network` coming from `JANUS_DOCKER_RUN_EXTRA` when `network_mode` is set.

**Platforms:** On Linux Engine, `network_mode: host` makes container loopback match the host (useful with unchanged `https://127.0.0.1:...` endpoints). On Docker Desktop for macOS/Windows, prefer `host.docker.internal` (or similar) in the API URL instead of relying on host networking.

The Cobalt Strike REST client may print a short **stderr hint** when a connection error targets loopback and the process appears to run inside a container. Operator playbook and caveats: [FAQ — Cobalt Strike REST and janus-cli + Docker](FAQ.md#cobalt-strike-rest-and-janus-cli--docker).

## Pipeline

Janus has two execution modes:

- Ingest mode: pull or load source telemetry, normalize it, and write a run directory
- Analysis mode: read an existing normalized dataset and produce analyzer JSON plus optional HTML

The pipeline is:

1. Ingest source telemetry
2. Normalize source-specific records into `task` and `result` events
3. Persist `events.ndjson` plus `bundle.json`
4. Run analyzers over the normalized events
5. Generate a self-contained HTML report from analyzer output

This separation matters operationally:

- Parsers own extraction and source quirks
- The event stream is the analysis contract
- Analyzers are mostly source-agnostic and rely on the normalized stream plus optional behavior-registry hints
- `merge` and `multi-analyze` operate on persisted normalized datasets, not on raw source exports

## Execution Responsibilities

| Command | What `janus-cli` does | What `janus` does |
| --- | --- | --- |
| `pull` | Resolve source, config, and target ID; invoke the matching pull workflow | Fetch telemetry and write the initial run directory |
| `pull --source cobaltstrike` | Resolve Cobalt Strike REST endpoint and auth from flags/config; invoke the Cobalt Strike REST ingest path in the container | Log in to the teamserver REST API, list/fetch tasks, normalize into `out/complete` |
| `run --source cobaltstrike` | Reuse the Cobalt Strike REST ingest path, then run analyzers and HTML generation | End-to-end Cobalt Strike workflow with the same pull ergonomics as other sources |
| `pull --source outflank` | Resolve a local Outflank implant log path from flags/config; invoke the Outflank loader in the container | Normalize copied per-beacon log files into `out/complete` |
| `analyze` | Resolve the latest run or user-specified events file | Run one analyzer or the full set against normalized events |
| `report` | Resolve the latest analysis directory | Generate HTML from analyzer output |
| `run` | Chain source pull, analyze, and report | Execute the full pipeline |
| `merge` / `multi-analyze` | Expand input paths or patterns | Merge normalized runs, then optionally run the multi-op analyzer set and report |
| `diff` | Resolve two completed run directories under `out/` | Compare baseline and candidate outputs, then write `diff.json` and optional `report.html` |
| `status` / `config` / `version` | Inspect local state | n/a |

## Source Coverage

| Source family | Current normalized `source` values | What it provides | Janus strength |
| --- | --- | --- | --- |
| Mythic | `mythic`, `mythic-partial` | Commands, responses, callback metadata, lifecycle state | Best fidelity for failure, retry, duration, and callback-health analysis |
| Ghostwriter | `ghostwriter` | Oplog chronology, command text, output, project/reporting context | Strong for workflow and timing analysis; weaker for failure-centric analysis |
| Cobalt Strike REST | `cobaltstrike-rest` | Teamserver REST API tasks (`/api/v1/tasks`, task detail, auth) — see [Cobalt Strike REST API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html) | Supported Cobalt Strike path: task + output in one API, suitable for automation without SSH file surgery |
| Outflank implant logs | `outflank` | Local per-beacon line-oriented JSON logs with task request/response records | Good for command chronology and output review; result status is inferred from response text |

**Cobalt Strike automation note:** The teamserver REST API is the practical way to pull structured tasks and beacon output for Janus. Alternatives such as SSH access to the teamserver host and copying fragmented on-disk artifacts are operationally heavier and do not match Janus’s normalized task/result model as directly.

Janus normalizes every source to the same two event types, but not every source can populate the same fields with the same fidelity.

## Persisted Contract

The real cross-component contract is the on-disk bundle:

- `events.ndjson`: normalized events, sorted by timestamp
- `bundle.json`: run metadata and provenance
- analyzer JSON files: per-analyzer output
- `report.html`: optional self-contained report

`write_ndjson()` validates each event before writing. `write_bundle()` adds run metadata such as:

- `analysis_version`
- `analysis_timestamp`
- `janus_version`
- `data_quality`

That means the persisted contract is slightly stricter than the in-memory dataclasses, but narrower than the old documentation implied.

### Data Quality Metadata

Every new `bundle.json` includes a `data_quality` array summarizing parser/source fidelity for the run. Each entry records the source name, parsed event count, skipped entries, invalid timestamps, fallback/generated task IDs, parser-specific malformed counts when available, status distribution, unknown-status percentage, retention modes, and factual interpretation warnings.

The HTML report renders the same entries in a **Data Quality** section. Treat these warnings as confidence guidance, not as analyzer invalidation. For example, a Ghostwriter run with all results marked `unknown` can still support chronology and argument-shape review, but failure-rate and retry-success findings are low-confidence because the source did not provide reliable success/error state.

Current warning rules:

- `unknown` result statuses at 80% or higher reduce confidence in failure-rate and retry-success analysis
- invalid timestamps may affect timeline and dwell-time analysis
- fallback/generated task IDs may make task correlation incomplete
- `arguments_rule: drop` or `features_only` limits argument-level analysis
- `output_rule: none` limits output and error-signature analysis
- `output_rule: errors_only` means success-output analysis is unavailable or limited

## Event Model

The event model should be read in three layers:

- Schema-required: fields enforced before NDJSON is written
- Common parser-populated: fields emitted by current first-party parsers, but not hard-validated
- Source-specific optional: enrichments only some parsers can provide

Many analyzers join events by `(operation_id, task_id)`, not by `task_id` alone.

### Task Event

Represents operator intent.

#### Schema-required

| Field | Meaning |
| --- | --- |
| `task_id` | Task identifier within the operation |
| `command_name` | Normalized command name |
| `timestamp` | ISO 8601 submit time |

#### Common parser-populated

These are emitted by current first-party parsers and should be treated as the practical shared shape, even though `validate_events()` does not currently enforce them.

| Field | Typical status | Meaning |
| --- | --- | --- |
| `event_type` | always present | Always `task` |
| `source` | always present | Parser/source identifier such as `mythic`, `ghostwriter`, `mythic-partial`, `cobaltstrike-rest`, or `outflank` |
| `operation_id` | always present today | Operation or project identifier; may be remapped during merge |
| `callback_id` | always present today | Callback/session identifier; may be synthetic or `0` when unavailable |
| `callback_display_id` | usually present | Human-facing callback label; may be copied from `callback_id` or defaulted |
| `display_id` | parser-dependent | Human-facing task label; Mythic-native in Mythic, synthetic/defaulted elsewhere |
| `tool_name` | always present today | Tool or source-side module name |
| `arguments_raw` | always present today | Raw argument payload, possibly empty |

#### Source-specific optional enrichments

| Field | Emitted by | Meaning |
| --- | --- | --- |
| `processing_timestamp` | Mythic, synthesized in partial Mythic | When the agent picked up the task |
| `callback_sleep_info` | Mythic, Cobalt Strike REST | Callback sleep interval used for duration heuristics |
| `issued_command_name` | Mythic | Actual executed command when attribution rewrites `command_name` |
| `parent_task_id` | Mythic | Parent task for subtask lineage |
| `orphaned_subtask` | Mythic | True when `parent_task_id` could not be resolved |
| `c2_task_id` | Ghostwriter, Cobalt Strike REST | Source-side cross-link identifier today; CS REST stores the string `taskId` here for traceability |
| `pty_synthetic` | Mythic PTY | True for a synthetic shell line inside an interactive PTY session |
| `pty_session` | Mythic PTY | True for the long-lived parent `pty` launch task |
| `pty_transport_event` | Mythic PTY | True for raw PTY child transport task rows when they are retained |
| `pty_parent_task_id` | Mythic PTY | Mythic task id of the parent PTY session |
| `pty_input_task_id` | Mythic PTY | Mythic child task id used as the fallback source for a synthetic shell line |
| `pty_sequence` | Mythic PTY | Per-session sequence number used to derive the negative synthetic `task_id` |
| `pty_input_raw` | Mythic PTY | Full PTY input line; treated as argument-sensitive content by retention rules |
| `pty_input_message_ids` | Mythic PTY | Interactive table message ids that supplied the PTY input line |
| `pty_child_count` | Mythic PTY | Count of PTY child task rows under the parent session |
| `pty_interactive_message_count` | Mythic PTY | Count of interactive rows associated with the parent session |

Important caveats:

- Ghostwriter does not populate `display_id`, `processing_timestamp`, `callback_sleep_info`, `issued_command_name`, `parent_task_id`, or `orphaned_subtask`
- Partial Mythic synthesizes some timing fields to preserve analyzer compatibility, so those values are less trustworthy than full Mythic pull data
- Cobalt Strike REST hashes string `taskId` to an int `task_id`, sets `callback_id` from `bid`, and may populate `callback_sleep_info` from beacon metadata when the REST API exposes sleep settings
- Outflank hashes string `task.uid` and `implant.uid` values to Janus integer IDs, stores the raw task UID in `c2_task_id`, and may populate `callback_sleep_info` from the implant `delay` field

### Result Event

Represents tool output or task outcome.

#### Schema-required

| Field | Meaning |
| --- | --- |
| `task_id` | Task the result belongs to |
| `status` | `success`, `error`, or `unknown` |
| `timestamp` | Completion, last-response, or fallback time |
| `output_text` | Concatenated output text; may be empty |

#### Common parser-populated

| Field | Typical status | Meaning |
| --- | --- | --- |
| `event_type` | always present | Always `result` |
| `source` | always present | Parser/source identifier |
| `operation_id` | always present today | Operation or project identifier |

#### Source-specific optional enrichments

| Field | Emitted by | Meaning |
| --- | --- | --- |
| `dispatch_failed` | Mythic, partial Mythic | Task failed before reaching the agent |
| `terminal_inferred_error` | Mythic | Janus promoted a terminal `unknown` to `error` |
| `pty_synthetic` | Mythic PTY | True for a synthetic result paired with a PTY shell-line task |
| `pty_parent_task_id` | Mythic PTY | Mythic task id of the parent PTY session |
| `pty_sequence` | Mythic PTY | Per-session sequence number paired with the synthetic task |
| `pty_output_message_ids` | Mythic PTY | Interactive table message ids that contributed output/error text |
| `pty_output_preface` | Mythic PTY | PTY output seen before the first input line; treated as output-sensitive content |
| `pty_exit_observed` | Mythic PTY | True when an interactive exit message was observed for the session |
| `pty_exit_timestamp` | Mythic PTY | Timestamp of the interactive exit message |
| `pty_exit_code` | Mythic PTY | Integer exit code when the exit payload cleanly parses as an integer |

Important caveats:

- Ghostwriter currently emits `status: unknown` for all results because the source does not expose a reliable success/error signal
- Cobalt Strike REST maps API `taskStatus` and `error`/`result` payloads to `success` / `error` / `unknown`; operator and acknowledgement text are merged into `output_text`
- Outflank local logs infer `error` only from clear response text markers such as `Err:`; non-empty non-error responses are `success`, and empty responses are `unknown`
- `output_text` is required by validation, but may be intentionally empty after `output_rule=errors_only`

### Retention controls and NDJSON content

Janus applies two independent retention controls after normalization and before writing `events.ndjson`. Both are set in `Config/janus.yml` (top-level keys) or overridden with CLI flags. CLI always takes precedence over config; default for both is `all`.

#### `output_rule` — result output retention

| Value | Behavior |
| --- | --- |
| `all` | Keep all `output_text` verbatim (default) |
| `errors_only` | Clear `output_text` on `success` results; `error` and `unknown` output kept |
| `none` | Clear `output_text` on all results regardless of status |

When output is cleared, the affected event retains an `output_retained` field recording the policy and derived features (`output_present`, `output_length`, `output_line_count`) so downstream consumers can distinguish missing output from genuinely empty output. This marker is written even if the original `output_text` was already empty.

Analyzers that rely on successful output, especially `av-tracker` on `ps`, need `output_rule: all`.

#### `arguments_rule` — task argument retention

| Value | Behavior |
| --- | --- |
| `all` | Keep `arguments_raw` verbatim (default) |
| `drop` | Clear `arguments_raw`; only `command_name` and metadata are retained |
| `hash` | Replace `arguments_raw` with a SHA-256 digest (`arguments_digest`) for correlation without content recovery |
| `features_only` | Replace `arguments_raw` with derived features: `arguments_length`, `arguments_token_count`, `arguments_shape`, and `arguments_entropy` |

When arguments are filtered, the affected event retains an `arguments_retained` field recording the applied policy. `drop` and `hash` also preserve `arguments_length`; `features_only` preserves derived fields such as `arguments_present`, `arguments_length`, `arguments_shape`, and `arguments_entropy`. These markers are written even if the original `arguments_raw` was already empty. Analyzers that depend on raw arguments (`parameter-entropy`, `argument-position-profile`, `tool-dump`, `command-retry-success`) produce reduced or empty output under non-`all` policies.

#### Common effects

- `bundle.json` records the resolved `output_rule` and `arguments_rule` as canonical rule IDs
- merged datasets may record `output_rule: mixed` and/or `arguments_rule: mixed` plus `observed_*_rules` arrays when inputs used different policies
- Ghostwriter still writes a full `raw_export.json`; retention filtering only applies to normalized NDJSON
- `merge` and `multi-analyze` do not re-filter existing NDJSON; apply the desired policy before merging

## Source-Specific Normalization Notes

### Mythic

Mythic has the richest normalization path:

- prefers submitted timestamps for task time and processed timestamps for result time
- rewrites some commands for better attribution
- preserves subtask lineage when possible
- can mark dispatch failures separately from agent-side execution failures
- can promote terminal `unknown` results to inferred `error`

Dispatcher parent tasks are skipped when the real execution is represented by a child task.

### Ghostwriter

Ghostwriter preserves chronology well but has weaker execution semantics:

- command parsing is mostly text splitting
- callback IDs are parsed from entry description text when present
- result status is conservatively `unknown`
- source-side entry IDs are currently stored in `c2_task_id`

### Cobalt Strike REST

Live ingest uses the teamserver REST server (authenticate with `POST /api/auth/login`, then `GET /api/v1/tasks` and per-task `GET /api/v1/tasks/{taskId}`). Janus maps each task to one `TaskEvent` and one merged `ResultEvent` (acknowledgements, result chunks, and errors in `output_text`). String task IDs are normalized to integer `task_id` for analyzer joins. Use `./janus-cli pull --source cobaltstrike` or `./janus-cli run --source cobaltstrike` with config keys under `cobaltstrike:` such as `rest_endpoint`, `username`, `password`, optional `api_token`, and `duration_ms`.

When using `janus-cli`, ensure `rest_endpoint` is reachable **from inside the Janus container** (routable IP/DNS, host networking, or `host.docker.internal`). A host-only `https://127.0.0.1:50443` works on the host but often fails in the default bridge network; see [Docker wrapper networking](#docker-wrapper-networking) and the [FAQ](FAQ.md#cobalt-strike-rest-and-janus-cli--docker).

### Outflank Implant Logs

Offline ingest reads local per-beacon Outflank implant logs, commonly named by implant UID under `/opt/outflank/shared/logs/api/implant_logs/json/`. Each line is a UTC timestamp followed by a JSON object. Janus normalizes `task_request` rows into tasks and `task_response` rows into results, hashing string `task.uid` / `implant.uid` values into integer IDs for analyzer joins.

Use `./janus-cli pull --source outflank --log-path out/input/TSO8IEAB.json` or `./janus-cli run --source outflank --log-path out/input/`. The Go wrapper only mounts `./out` into Docker, so the log path must be under `out/` unless you invoke the Python entrypoint directly inside a differently mounted container.

## Analyzer Registries

Two registry layers shape analysis behavior:

- `Core/analyzer_registry.py`: analyzer names, output filenames, and run sets
- `Core/analyzer_behavior_registry.py`: source-aware heuristics consumed by selected analyzers

The behavior registry is advisory. It exists to keep source-specific semantics from leaking into every analyzer implementation.

## Multi-Operation Analysis

`merge` and `multi-analyze` combine normalized runs into one dataset. `multi-analyze` then runs the registry-defined multi-operation analyzer set.

Important merge behavior:

- each source run keeps its own `operation_id` namespace
- if an input run has a missing, invalid, or duplicate `operation_id`, Janus remaps it during merge
- remap details are recorded in merged `bundle.json`
- analyzers then join on the merged `(operation_id, task_id)` pairs

## Run Diffing

`janus-cli diff --baseline <run_dir> --candidate <run_dir>` compares two completed Janus output directories. The diff layer is local-only and reads existing artifacts in this order:

- `bundle.json` for run identity, source metadata, retention settings, and parser/data-quality warnings
- analyzer JSON outputs for structured metrics when present
- `events.ndjson` as a fallback for command counts, status rates, retries, durations, dwell-time, and callback-health-adjacent signals

The command writes a deterministic `diff.json` for automation and renders the same comparison through the standard Janus `report.html` flow unless `--no-html` is supplied. `--format json` prints the same structured diff to stdout, and `--fail-on-regression` exits non-zero only when high-confidence regressions exceed `--max-regressions`.

Diff findings are intentionally scoped. Command-level comparisons are emphasized because aggregate trends can be distorted by different task volume, source coverage, or command mix. The comparability section warns when source sets differ, task volume differs by more than the configured threshold, command mix changes substantially, or unknown result status is high enough to undermine failure-rate claims.

Confidence levels consider sample size, unknown-status percentage, source overlap, missing analyzer artifacts, parser/data-quality warnings, retention settings, and whether a metric was directly observed or inferred. Janus only labels a finding as `improvement` or `regression` when the metric direction is clear and confidence is sufficient. Otherwise the finding is reported as `low-confidence change` or `not_comparable`.

This design lets Janus compare patterns across engagements without changing the single-operation event model.

## Fields That Likely Need To Move

The field most likely to move or split is `c2_task_id`.

Today it has incompatible meanings:

- Ghostwriter uses it as a source-side task or entry identifier
- Cobalt Strike REST uses it for the opaque string `taskId`
- Outflank uses it for the raw string `task.uid`

That makes it a poor shared-model field. The cleaner long-term direction is one of:

- split it into a dedicated shared field with a single meaning, such as `source_task_ref`
- move source-specific extras into a nested metadata object

By contrast, the other optional enrichments are reasonable to keep in the shared model because analyzers or reporting consume them:

- `processing_timestamp`
- `callback_sleep_info`
- `issued_command_name`
- `parent_task_id`
- `orphaned_subtask`
- `dispatch_failed`
- `terminal_inferred_error`

## Privacy

Janus does **not** use LLMs for analysis, summarization, or report generation. All analysis runs locally from the telemetry you ingest.

Janus does **not** send normalized operation data to external AI or SaaS analysis services. Network access is limited to the source systems you explicitly configure for data collection (Mythic, Ghostwriter, or Cobalt Strike REST endpoints). Outflank implant-log ingestion is offline/local file ingestion.

### What Janus Stores Today

Every Janus run can produce the following artifacts under `out/`:

| Artifact | Contains | Affected by retention controls |
| --- | --- | --- |
| `events.ndjson` | Normalized task and result events with timestamps, command names, arguments, output text, and identifiers | Yes — `output_rule` and `arguments_rule` filter sensitive fields before write |
| `bundle.json` | Run metadata: source, operation identifiers, counts, resolved retention settings, Janus version | No — metadata only; no raw telemetry |
| Analyzer JSON files | Per-analyzer output: aggregated statistics, findings, and detail rows that may include `arguments_raw` or `output_text` excerpts | Indirectly — analyzers receive post-policy events, so their output reflects the retention state |
| `report.html` | Self-contained HTML report rendering analyzer output | Indirectly — the report displays a retention banner and adjusts formatting when content is filtered |
| Ghostwriter `raw_export.json` | Full Ghostwriter oplog export as received from the API | **No** — retention controls do not filter `raw_export.json`; it is the unmodified source snapshot |

### Privacy Boundaries

**Sensitive fields by nature:**

- `arguments_raw` on task events — may contain file paths, hostnames, credentials, shellcode, Kerberos tickets, or other target-specific payloads
- `output_text` on result events — may contain process listings, directory contents, command output, and other data from the target environment
- Source-linked identifiers (`operation_id`, `callback_id`, `task_id`) — operational context that is useful for analysis but ties events to specific engagements

**What Janus does locally:**

- Connects to configured source systems over HTTPS (TLS verified by default) to pull telemetry
- Normalizes source-specific records into a shared event model
- Applies retention policy (filters `arguments_raw` and `output_text` before persistence)
- Runs analyzers against the normalized events
- Generates a self-contained HTML report
- Writes all artifacts to the local `out/` directory

**What Janus does not do:**

- Send normalized or raw data to any external service, cloud endpoint, or LLM provider
- Phone home, report usage, or check for updates
- Persist credentials to disk (API tokens and passwords are read from config or environment at runtime)

### Retention Controls

Janus provides two independent, operator-controlled retention policies applied after normalization and before `events.ndjson` is written. See [Retention controls and NDJSON content](#retention-controls-and-ndjson-content) for the full policy table.

**Resolution precedence:** CLI flag > config file > default (`all`).

**Where the policy is recorded:** `bundle.json` is the authoritative privacy record for a Janus run. It includes both `output_rule` and `arguments_rule` as resolved canonical strings. For merged datasets, these fields may be `mixed`, with `observed_output_rules` and `observed_arguments_rules` listing the exact policies present. Downstream consumers and the HTML report read this metadata first to understand the retention state.

**When filtered content is detected in events:** Task and result events include `arguments_retained` or `output_retained` fields when a non-default policy affected that event. These fields let analyzers distinguish "empty because the operator sent no arguments" from "empty because retention policy removed the content." Derived features (`arguments_present`, `arguments_length`, `arguments_shape`, `arguments_entropy`, `output_present`, `output_length`, `output_line_count`) and digests (`arguments_digest`) are persisted alongside the retention marker depending on the policy. For `output_rule: errors_only`, Janus also stamps result events with `output_retained: errors_only` even when the row keeps its visible error text, so downstream tools can still detect the active policy from `events.ndjson` alone.

### Artifact-Specific Caveats

- **Ghostwriter `raw_export.json`** is not filtered by any retention policy. It is a verbatim snapshot of the API response. If the raw export contains sensitive data, the operator is responsible for managing or deleting it.
- **`merge` and `multi-analyze`** do not re-filter existing NDJSON. Apply the desired retention policy during the original ingest to ensure merged datasets inherit the correct filtering. If inputs were created under different policies, Janus marks the merged bundle as `mixed` rather than pretending one policy applied everywhere.
- **Analyzer JSON output** may embed `arguments_raw` or `output_text` values in detail rows, findings, or examples when running under `output_rule: all` / `arguments_rule: all`. Under stricter policies, those fields are already empty or replaced in the source events, so analyzer output inherits the same reduction.
- **`report.html`** displays a retention policy banner in the report header when non-default or mixed policies are active. Table cells that would normally show raw arguments instead display contextual placeholders (e.g., "redacted", hash prefix, or shape summary).

### Analyzer Compatibility

Not all analyzers produce meaningful output under every retention policy. The table below summarizes the dependency and degradation behavior:

| Analyzer | Depends on `arguments_raw` | Depends on `output_text` | Behavior under restricted policy |
| --- | --- | --- | --- |
| `summary-visualization` | No | No | Full output |
| `command-failure-summary` | Detail rows only | Error messages | Core metrics intact; detail rows show empty args/output |
| `command-retry-success` | Yes (argument diff) | No | Cannot detect argument tuning between retries; sequence detection still works |
| `command-duration` | Detail rows only | No | Core metrics intact; detail rows show empty args |
| `outlier-context` | No | No | Full output |
| `callback-health` | Detail rows only | No | Core metrics intact; detail rows show empty args |
| `av-tracker` | No | Yes (successful `ps` output) | Cannot detect AV/EDR executables without `output_rule: all` |
| `dwell-time` | Detail rows only | No | Core metrics intact; context rows show empty args |
| `parameter-entropy` | Yes (full analysis) | No | Produces empty or severely limited findings |
| `argument-position-profile` | Yes (full analysis) | No | Produces empty or severely limited findings |
| `tool-dump` | Yes (matching + dumps) | No | Match accuracy degraded; dump content empty |

When analyzers detect that events were persisted under a restrictive or mixed retention policy, they include `privacy_warnings` in their metadata section describing the specific limitation. For single-operation analysis, Janus derives that state from `bundle.json`; event-level markers remain as provenance inside `events.ndjson`.

### Operator Responsibilities

Janus provides the retention controls; the operator is responsible for:

- **Choosing the right policy** for the engagement's data handling requirements before running ingest
- **Managing artifact lifecycle** — Janus does not enforce time-based retention, automatic deletion, or encryption at rest
- **Handling Ghostwriter `raw_export.json`** — this file is outside the retention policy scope
- **Protecting `Config/janus.yml`** — this file may contain API tokens and endpoint URLs; it is mounted read-only in the container but lives on the host filesystem
- **Reviewing `bundle.json`** — this file records the exact retention policy that was applied and can be used for compliance or audit purposes

## Output Summary

Janus writes deterministic, versioned analysis artifacts so runs can be replayed, diffed, merged, and consumed by downstream tooling. The architecture is intentionally biased toward:

- source-specific parsing at the edge
- a narrow normalized event contract in the middle
- source-aware but mostly source-agnostic analyzers on top

The main current architectural debt is not the parser boundary. It is the gap between documented field requirements and enforced schema, plus the overloaded meaning of `c2_task_id`.
