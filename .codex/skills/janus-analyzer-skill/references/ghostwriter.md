# Ghostwriter Analyzer Context

Use this when the request is explicitly Ghostwriter-backed or when the user wants a source-aware answer that accounts for Ghostwriter limits.

## Read First

- `janus.py`
- `Parsers/Ghostwriter/ghostwriter_pull.py`
- `Parsers/Ghostwriter/main.py`
- `docs/ghostwriter-api-reference.md`

## What Ghostwriter Gives Janus

- Good command chronology
- Task and result event pairs derived from oplog entries
- Command text that often needs splitting into `command_name` and `arguments_raw`
- Weak or missing success/error truth
- Often sparse or empty command output

## Hard Constraints

- `ResultEvent.status` is currently normalized as `unknown`
- Callback/session IDs are derived heuristically from description text when present
- Failure-centric and output-quality analyzers are inherently weaker than Mythic

## Practical Guidance

- If the user asks for a Ghostwriter metric that depends on reliable status, call out the limitation before proposing code.
- For chronology, dwell, sequencing, and argument-shape analysis, Ghostwriter is usually still useful.
- Do not infer success/error from empty output or operator prose unless the source schema changes and Janus intentionally adopts that mapping.

## Typical Change Points

- Export or normalization logic: `Parsers/Ghostwriter/main.py`
- Compatibility import path: `Parsers/Ghostwriter/ghostwriter_pull.py`
- Source capability explanation: `docs/ghostwriter-api-reference.md`
- Source-aware heuristics: `Config/analyzer_registry.yml`
