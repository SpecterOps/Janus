# Source Interpretation Guide

Use this reference when deciding how much confidence to place in Janus findings.

## Mythic

Best for:

- Failure-rate interpretation
- Retry-to-success patterns
- Callback health conclusions
- Rich command/result correlations

Typical caveat:

- Partial Mythic exports reduce timing and subtask fidelity

## Ghostwriter

Best for:

- Command chronology
- Dwell and sequencing interpretation
- Duration patterns
- Parameter-shape and argument-slot analysis

Hard caveats:

- Success/error truth is usually unavailable
- Output text may be sparse or empty
- Some callback/session attribution is heuristic

## Report Quality Signals

`Core/html_output.py` suppresses some sections when the dataset cannot support them.

Treat these as mandatory interpretation constraints:

- Warnings about Ghostwriter fidelity
- Warnings that most results are `unknown`
- Suppressed `command-failure-summary`
- Suppressed `command-retry-success`
- Suppressed `callback-health`

If these appear, translate them into plain language for the user instead of paraphrasing the suppressed charts.
