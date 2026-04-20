---
name: janus-analyzer-skill
description: Use this skill for Janus requests that ask what to measure, how to measure it, which analyzer should answer it, or how to implement or adjust source-aware analysis for Mythic or Ghostwriter telemetry.
---

# Janus Analyzer Skill

## Overview

Use this skill when the user wants Janus to answer a measurement question, design a new metric, extend an analyzer, or explain why a result differs between Mythic and Ghostwriter.

Start from the existing Janus execution path instead of inventing new analysis flows. Read only the source-specific reference that matches the request.

## Workflow

1. Pin down the question to answer in one sentence.
2. Determine the source: `mythic`, `ghostwriter`, or compare both. If the source is omitted, infer it from the task or config only when low-risk.
3. Read these core files first:
   - `janus.py`
   - `Core/analyzer_registry.py`
   - `Core/analyzer_behavior_registry.py`
   - `Config/analyzers.yml`
   - `Config/analyzer_registry.yml`
4. Route by source:
   - Mythic: read `Parsers/Mythic/mythic_pull.py`
   - Ghostwriter: read `Parsers/Ghostwriter/main.py`
   - Cobalt Strike REST: read `Parsers/CobaltStrike/cobalt_strike_rest.py`
   - CobaltStrike TSV: read `Parsers/CobaltStrike/cobalt_strike_tsv.py`
   - Partial Mythic: read `Parsers/Mythic/partial_data_adapter.py`
   - Cross-source comparison: read `docs/architecture.md` then parser files above
5. Classify the request before editing code:
   - Existing analyzer usage or report interpretation
   - Behavior-registry tweak
   - Parser normalization gap
   - New analyzer
6. Prefer the smallest change that answers the question cleanly.

## Implementation Rules

- Keep analyzer names in kebab-case and register outputs in `Core/analyzer_registry.py`.
- For a new analyzer, update all runtime registration points:
  - `Core/analyzer_registry.py`
  - `Config/analyzers.yml`
  - `janus.py` `ANALYZER_FUNCTIONS`
  - `janus.py` `run_analyze()`'s explicit analyzer dispatch branch
- Preserve the canonical task/result event model Janus already uses.
- Treat Ghostwriter result state as unreliable unless the source schema actually adds trustworthy status fields.
- Do not “equalize” Mythic downward; source-aware behavior should degrade weaker sources safely, not discard stronger Mythic fidelity.
- If a metric depends on success/error truth, say explicitly whether Ghostwriter can support it today.
- If only heuristics need adjustment for known commands, prefer `Config/analyzer_registry.yml` over hard-coding special cases.
- **Always update `Core/html_output.py` when an analyzer's output schema changes.** Find the `_render_<analyzer_name>` function and update any `.get(“key”)` references that no longer match. Silently empty tables are the failure mode.
- After adding a new analyzer, run it once through the real CLI/container path, not just direct Python imports, to catch missing `run_analyze()` registration.
- Parser robustness guardrails now exist and should be preserved:
  - `normalize_timestamp()` accepts ISO and epoch values; malformed timestamps should be handled intentionally (skip with counters or raise early).
  - `load_events()` can validate schema and warns on unknown event types.
  - `run_merge()` remaps missing/duplicate `operation_id` values to deterministic unique IDs to avoid cross-operation key collisions.

## What Good Output Looks Like

When answering the user, produce:

- The metric or question being answered
- The source scope and any fidelity limits
- Whether Janus already supports it or needs code changes
- If code changes are needed, the minimal files to touch

## References

- `docs/architecture.md`
- `docs/partial-data.md`
- `docs/ghostwriter-api-reference.md`
