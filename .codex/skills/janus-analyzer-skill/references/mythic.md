# Mythic Analyzer Context

Use this when the request is explicitly Mythic-backed or when the user needs the highest-fidelity Janus behavior.

## Read First

- `janus.py`
- `Parsers/Mythic/mythic_pull.py`
- `Parsers/Mythic/partial_data_adapter.py` only if the request involves partial exports
- `Core/models.py` if field semantics matter

## What Mythic Gives Janus

- Native task and response pulls
- Reliable success/error inference via task completion and status fields
- Strong callback/session attribution
- Better support for failure, retry, callback-health, and result-quality analysis

## Practical Guidance

- If the user asks why a failure-centric analyzer behaves well in Mythic, start with the parser and result status mapping.
- If the request is about partial Mythic exports, assume timing and subtask fidelity are reduced; the adapter synthesizes missing fields.
- If a command needs source-aware exceptions, prefer the behavior registry before adding analyzer-local branching.

## Typical Change Points

- New normalization or field mapping: `Parsers/Mythic/mythic_pull.py`
- Partial export handling: `Parsers/Mythic/partial_data_adapter.py`
- New analyzer registration: `Core/analyzer_registry.py` and `janus.py`
- Source-aware heuristics: `Config/analyzer_registry.yml`
