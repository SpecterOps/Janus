Use this skill for Janus requests that ask what to measure, how to measure it, which analyzer should answer it, or how to implement or adjust source-aware analysis for Mythic or Ghostwriter telemetry.

## Overview

Use this when the user wants Janus to answer a measurement question, design a new metric, extend an analyzer, or explain why a result differs between Mythic and Ghostwriter.

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
   - Mythic: see Mythic reference below
   - Ghostwriter: see Ghostwriter reference below
   - Cross-source comparison: consult both
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
- Do not "equalize" Mythic downward; source-aware behavior should degrade weaker sources safely, not discard stronger Mythic fidelity.
- If a metric depends on success/error truth, say explicitly whether Ghostwriter can support it today.
- If only heuristics need adjustment for known commands, prefer `Config/analyzer_registry.yml` over hard-coding special cases.
- Always update `Core/html_output.py` when an analyzer output schema changes, or the report section can silently render empty.
- After adding a new analyzer, run it once through the real CLI/container path, not just direct Python imports, to catch missing `run_analyze()` registration.

## What Good Output Looks Like

When answering the user, produce:

- The metric or question being answered
- The source scope and any fidelity limits
- Whether Janus already supports it or needs code changes
- If code changes are needed, the minimal files to touch

---

## Mythic Reference

Use when the request is explicitly Mythic-backed or when the user needs the highest-fidelity Janus behavior.

**Read first:**
- `janus.py`
- `Parsers/Mythic/mythic_pull.py`
- `Parsers/Mythic/partial_data_adapter.py` only if the request involves partial exports
- `Core/models.py` if field semantics matter

**What Mythic gives Janus:**
- Native task and response pulls
- Reliable success/error inference via task completion and status fields
- Strong callback/session attribution
- Better support for failure, retry, callback-health, and result-quality analysis

**Practical guidance:**
- If the user asks why a failure-centric analyzer behaves well in Mythic, start with the parser and result status mapping.
- If the request is about partial Mythic exports, assume timing and subtask fidelity are reduced; the adapter synthesizes missing fields.
- If a command needs source-aware exceptions, prefer the behavior registry before adding analyzer-local branching.

**Typical change points:**
- New normalization or field mapping: `Parsers/Mythic/mythic_pull.py`
- Partial export handling: `Parsers/Mythic/partial_data_adapter.py`
- New analyzer registration: `Core/analyzer_registry.py`, `Config/analyzers.yml`, and `janus.py`
- Source-aware heuristics: `Config/analyzer_registry.yml`

---

## Ghostwriter Reference

Use when the request is explicitly Ghostwriter-backed or when the user wants a source-aware answer that accounts for Ghostwriter limits.

**Read first:**
- `janus.py`
- `Parsers/Ghostwriter/ghostwriter_pull.py`
- `Parsers/Ghostwriter/main.py`

**What Ghostwriter gives Janus:**
- Good command chronology
- Task and result event pairs derived from oplog entries
- Command text that often needs splitting into `command_name` and `arguments_raw`
- Weak or missing success/error truth
- Often sparse or empty command output

**Hard constraints:**
- `ResultEvent.status` is currently normalized as `unknown`
- Callback/session IDs are derived heuristically from description text when present
- Failure-centric and output-quality analyzers are inherently weaker than Mythic

**Practical guidance:**
- If the user asks for a Ghostwriter metric that depends on reliable status, call out the limitation before proposing code.
- For chronology, dwell, sequencing, and argument-shape analysis, Ghostwriter is usually still useful.
- Do not infer success/error from empty output or operator prose unless the source schema changes and Janus intentionally adopts that mapping.

**Typical change points:**
- Export or normalization logic: `Parsers/Ghostwriter/main.py`
- Compatibility import path: `Parsers/Ghostwriter/ghostwriter_pull.py`
- Source-aware heuristics: `Config/analyzer_registry.yml`
