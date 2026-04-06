Use this skill for Janus requests that ask for insights from any Janus artifact, including report HTML, bundles, analyzer outputs, `events.ndjson`, raw exports, or standalone JSON snippets.

## Overview

Use this when the user already has Janus data and wants meaning, not parser or analyzer implementation work.

This skill interprets `report.html`, `bundle.json`, analyzer JSON, `events.ndjson`, `raw_export.json`, and user-provided JSON with source-aware caution, especially when Ghostwriter data weakens failure-centric conclusions.

## Workflow

1. Identify the artifact being interpreted:
   - `report.html`
   - `bundle.json`
   - Individual analyzer JSON
   - `events.ndjson`
   - `raw_export.json`
   - User-pasted JSON fragments (single files or snippets)
   - A full output directory
   - Multiple output directories for comparison
2. Read these files first when present:
   - `bundle.json`
   - `Core/analyzer_registry.py`
   - `Config/analyzers.yml`
   - `Config/analyzer_registry.yml`
   - `Core/html_output.py`
3. If interpreting a full run, load only the files needed for the user's question.
4. Check source and fidelity before making claims:
   - Mythic supports strong failure and retry conclusions
   - Ghostwriter supports chronology and argument-shape interpretation better than success/failure interpretation
5. Infer likely engagement context from evidence before interpreting findings:
   - Infer whether data looks like development, training/exercise, live operation, or mixed/unclear
   - Use indicators such as operation naming, command mix, retry/iteration patterns, repeated test scaffolding, analyst notes, and timeline cadence
   - State confidence (`high|medium|low`) and explicitly label this as an inference, not ground truth
   - Explain how inferred context changes interpretation (for example, repeated failures in development may indicate experimentation, not operator friction)
6. Separate output into:
   - What Janus observed
   - What Janus cannot support confidently from this dataset
   - Recommended next action

## Interpretation Rules

- Treat `bundle.json` as the primary run metadata source.
- When `bundle.json` is missing, infer scope and limits from `events.ndjson`/artifact fields.
- Always include an explicit engagement-context inference (`development`, `training`, `operation`, `mixed`, or `unclear`) with confidence and supporting evidence.
- If context appears non-operational (for example, BOF development or training), avoid framing findings as mission-impacting by default; reframe as engineering/training signals first.
- For raw Ghostwriter exports, use `entries[]` chronology and command shape, but avoid hard success/failure claims.
- Treat report quality warnings and suppressed sections as first-class evidence, not UI noise.
- If `status_counts.unknown` dominates results, do not present failure-rate claims as fact.
- For Ghostwriter runs, prefer dwell, sequencing, duration, parameter-entropy, and argument-profile insights over failure summaries.
- When comparing runs, normalize by source and scope before claiming improvement or regression.
- Distinguish operator friction from intentional delays. Janus already excludes some expected waits through the behavior registry.
- For merged datasets, verify whether operation IDs were remapped (`operations[].remapped_operation_id`) before comparing per-operation trends.
- Treat quality counters as first-class evidence (`skipped_entry_count`, `invalid_timestamp_count`, `fallback_task_id_count`, parser-specific skipped/invalid counts).

## Output Shape

When answering, prefer this structure:

- Dataset scope: source, operation, artifact type, count, and known quality limits
- Engagement context inference: likely context, confidence, and evidence
- Evidence summary: what the artifact directly shows
- Key findings: only supported claims
- Interpretation: what the findings likely mean operationally
- Recommendations: training, workflow, automation, or analyzer follow-up

---

## Report Reading Reference

**Read order:**
1. `bundle.json`
2. Relevant analyzer JSON files and/or `events.ndjson` / `raw_export.json`
3. `report.html` only for presentation context or to confirm suppressed sections and top findings

**What to pull from `bundle.json`:**
- `source`
- `operation_name`
- `operation_id`
- `task_count`
- `result_count`
- `status_counts`
- `analysis_timestamp`
- Endpoint fields when useful for provenance
- Merge remap indicators (`operations[].remapped_operation_id`, `original_id`) for multi-op confidence

**If `bundle.json` is missing:**
- Use `events.ndjson` to infer source, operation IDs, task/result counts, and status distribution
- For `raw_export.json`, infer constraints from source schema and missing status fidelity

**Analyzer reading heuristics:**
- `command_failure_summary.json`: use only when success/error fidelity is credible
- `command_retry_success.json`: interpret as parameter tuning or operator iteration, not just "mistakes"
- `command_duration.json`: look for long-tail commands and command clusters with meaningful dwell
- `outlier_context_analysis.json`: use to explain what surrounds slow tasks
- `callback_health.json`: treat as high-signal only when result states are reliable
- `dwell_time.json`: useful for context switching and dead-time analysis
- `parameter_entropy.json`: useful for spotting payload-like args, tokens, blobs, or structurally odd inputs
- `argument_position_profile.json`: useful for recurring slot-level patterns and tool usage conventions

**Comparison guidance:**
- Compare runs with the same source first.
- Check whether task counts are large enough to support the conclusion.
- If one run is Ghostwriter and the other is Mythic, qualify the comparison heavily.
- If operation IDs were remapped during merge, compare by operation name/slug and metadata context, not raw ID alone.

---

## Source Interpretation Reference

**Mythic** — best for:
- Failure-rate interpretation
- Retry-to-success patterns
- Callback health conclusions
- Rich command/result correlations

Typical caveat: partial Mythic exports reduce timing and subtask fidelity.

**Ghostwriter** — best for:
- Command chronology
- Dwell and sequencing interpretation
- Duration patterns
- Parameter-shape and argument-slot analysis

Hard caveats:
- Success/error truth is usually unavailable
- Output text may be sparse or empty
- Some callback/session attribution is heuristic

**Report quality signals:**

`Core/html_output.py` suppresses some sections when the dataset cannot support them. Treat these as mandatory interpretation constraints:

- Warnings about Ghostwriter fidelity
- Warnings that most results are `unknown`
- Suppressed `command-failure-summary`
- Suppressed `command-retry-success`
- Suppressed `callback-health`

If these appear, translate them into plain language for the user instead of paraphrasing the suppressed charts.
