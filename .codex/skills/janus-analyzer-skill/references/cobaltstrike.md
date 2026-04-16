# Cobalt Strike Analyzer Context

Use this when the request is explicitly Cobalt Strike-backed or when the user wants source-aware guidance for Janus support of Cobalt Strike telemetry.

## Read First

- `janus.py`
- `Parsers/CobaltStrike/cobalt_strike_rest.py`
- `Core/models.py` if field semantics matter

## What Cobalt Strike Gives Janus

- Team server task and callback telemetry through the current REST ingestion path
- Useful command chronology and operator workflow evidence
- Source-aware normalization that may differ from Mythic and Ghostwriter in task or result richness

## Practical Guidance

- Confirm which Cobalt Strike ingest path the request assumes before proposing parser changes.
- For source-aware analyzer work, compare Cobalt Strike behavior against the normalized event model instead of assuming Mythic-like status fidelity.
- If a metric depends on strong success or error truth or rich output capture, verify the normalized fields first before promising parity with other sources.

## Typical Change Points

- Export or normalization logic: `Parsers/CobaltStrike/cobalt_strike_rest.py`
- New analyzer registration: `Core/analyzer_registry.py` and `janus.py`
- Source-aware heuristics: `Config/analyzer_registry.yml`
