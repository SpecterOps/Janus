---
name: janus-insight-interpreter
description: Use this skill for Janus requests that ask for insights from any Janus artifact, including report HTML, bundles, analyzer outputs, events.ndjson, raw exports, or standalone JSON snippets.
---

# Janus Insight Interpreter

## Overview

Use this skill when the user has Janus data and wants meaning, not parser or analyzer implementation work.

This skill interprets `report.html`, `bundle.json`, analyzer outputs, `events.ndjson`, `raw_export.json`, and ad-hoc JSON payloads with source-aware caution, especially when Ghostwriter data weakens failure-centric conclusions.

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
3. If interpreting a full run, load only the files needed for the user’s question.
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
- When `bundle.json` is missing, infer scope from `events.ndjson` and source markers in events.
- Always include an explicit engagement-context inference (`development`, `training`, `operation`, `mixed`, or `unclear`) with confidence and supporting evidence.
- If context appears non-operational (for example, BOF development or training), avoid framing findings as mission-impacting by default; reframe as engineering/training signals first.
- For raw Ghostwriter exports, use `entries[]` chronology and command shape, but avoid claiming hard success/failure rates.
- Treat report quality warnings and suppressed sections as first-class evidence, not UI noise.
- If `status_counts.unknown` dominates results, do not present failure-rate claims as fact.
- For Ghostwriter runs, prefer dwell, sequencing, duration, parameter-entropy, and argument-profile insights over failure summaries.
- When comparing runs, normalize by source and scope before claiming improvement or regression.
- Distinguish operator friction from intentional delays. Janus already excludes some expected waits through the behavior registry.
- For merged datasets, verify whether operation IDs were remapped (`operations[].remapped_operation_id`) before comparing per-operation trends.
- Treat metadata quality counters as evidence (`skipped_entry_count`, `invalid_timestamp_count`, `fallback_task_id_count`, parser-specific skipped/invalid counts).

## Output Shape

When answering, prefer this structure:

- Dataset scope: source, operation, artifact type, count, and quality limits
- Engagement context inference: likely context, confidence, and evidence
- Evidence summary: what the JSON/report directly shows
- Key findings: only supported claims
- Interpretation: what the findings likely mean operationally
- Recommendations: training, workflow, automation, or analyzer follow-up

## References

- `docs/architecture.md`
- `docs/partial-data.md`
- `docs/ghostwriter-api-reference.md`
