# Report Reading Guide

Use this reference when reading Janus output files directly.

## Read Order

1. `bundle.json`
2. Relevant analyzer JSON files
3. `report.html` only for presentation context or to confirm suppressed sections and top findings

## What To Pull From `bundle.json`

- `source`
- `operation_name`
- `operation_id`
- `task_count`
- `result_count`
- `status_counts`
- `analysis_timestamp`
- Endpoint fields when useful for provenance

## Analyzer Reading Heuristics

- `command_failure_summary.json`: use only when success/error fidelity is credible
- `command_retry_success.json`: interpret as parameter tuning or operator iteration, not just “mistakes”
- `command_duration.json`: look for long-tail commands and command clusters with meaningful dwell
- `outlier_context_analysis.json`: use to explain what surrounds slow tasks
- `callback_health.json`: treat as high-signal only when result states are reliable
- `dwell_time.json`: useful for context switching and dead-time analysis
- `parameter_entropy.json`: useful for spotting payload-like args, tokens, blobs, or structurally odd inputs
- `argument_position_profile.json`: useful for recurring slot-level patterns and tool usage conventions

## Comparison Guidance

- Compare runs with the same source first.
- Check whether task counts are large enough to support the conclusion.
- If one run is Ghostwriter and the other is Mythic, qualify the comparison heavily.
