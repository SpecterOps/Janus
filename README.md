<p align="center">
    <img src="Assets/ditheredjanus.png" alt="Janus" width="800"/>
    <br/>
    <em>Janus analyzes C2 telemetry to surface failure patterns, operator friction, and automation opportunities across engagements.</em>
</p>

## Quick Start

Requires [Docker](https://www.docker.com/) and the `janus-cli` binary built for your operating system.

```bash
git clone https://github.com/SpecterOps/Janus/ && cd Janus
make cli
cp Config/janus.example.yml Config/janus.yml # set source, redaction settings, etc. 
./janus-cli run
```

`pull` and `run` include source preflight/auth handling; for provider-specific auth, config precedence, TLS caveats, and Docker networking details, see [docs/FAQ.md](docs/FAQ.md) and [docs/architecture.md](docs/architecture.md).

## Usage

```bash
./janus-cli run # full execution of the ingest, analyze, and report pipeline for the configured source
./janus-cli pull # ingest Mythic, Ghostwriter, Cobalt Strike, or Outflank logs from sources defined in config
./janus-cli analyze # analyze all previously ingested logs
./janus-cli report # generate an HTML report from latest analysis

./janus-cli analyze --analyzer dwell-time 
./janus-cli analyze --events out/complete/operation-chimera_20260306_174521/events.ndjson  
./janus-cli report --json out/complete/operation-chimera_20260306_174521/ 
./janus-cli merge --inputs out/partial/op1/ out/partial/op2/ --output out/merged/ 
./janus-cli multi-analyze --pattern "out/partial/*/" --output out/combined/ 
./janus-cli pull --source cobaltstrike 
./janus-cli run --source cobaltstrike 
./janus-cli run --source outflank --log-path out/input/TSO8IEAB.json
./janus-cli run --source mythic --response-page-size 100 # lower Mythic response pagination for huge output rows

./janus-cli status # display the current ingest/analyze/report state
./janus-cli config # print active configuration
```

## Demo 

<p align="center">
  <a href="Assets/Janus-Live-Demo.gif">
    <img
      src="Assets/Janus-Live-Demo.gif"
      alt="Janus live demo walkthrough"
      width="900"
    />
  </a>
</p>

## Analyzers

| Analyzer | What it answers |
|---|---|
| `summary-visualization` | What does the operation look like at a glance across time, volume, and status? |
| `command-failure-summary` | Which commands fail most, and how often? |
| `command-retry-success` | Which commands need repeated tuning to succeed? |
| `command-duration` | How long do commands take, and what's slow? |
| `outlier-context` | What surrounds unusually slow commands? |
| `callback-health` | Which implant sessions show failure patterns or crashes? |
| `av-tracker` | Which commands or callbacks coincided with AV/EDR detections in `ps` output? |
| `dwell-time` | Where are operators losing time between tasks? |
| `parameter-entropy` | Which arguments look structurally anomalous? |
| `argument-position-profile` | What shows up at a given argument slot? |
| `tool-dump` | Which registry-defined command/tool subsets should be exported for downstream datasets or pattern mining? |

`parameter-entropy` works best when you tune `Config/analyzer_registry.yml` to your own workflows. The current `upload` tuning reflects our observed data and should be treated as a starting point, not a universal baseline.

## Skills

Use repo-local skills by running `claude` or `codex` from the Janus folder, then invoking the skill with `/` or `$`.

- [janus-analyzer-skill](https://github.com/SpecterOps/Janus/blob/main/.codex/skills/janus-analyzer-skill/SKILL.md): Use for Janus measurement, analyzer-selection, and source-aware implementation requests across Janus-supported C2 telemetry.
- [janus-insight-interpreter](https://github.com/SpecterOps/Janus/blob/main/.codex/skills/janus-report-interpreter/SKILL.md): Use for evidence-based interpretation of Janus artifacts across Janus-supported C2 telemetry.


## Privacy

Janus runs analysis locally and does **not** use LLMs or external services for normalized operation data.

Retention policies (`output_rule` and `arguments_rule`) control what normalized content is written to disk. See [docs/architecture.md — Privacy](docs/architecture.md#privacy).

## Outputs

- `report.html` - visual HTML report
- `bundle.json` - versioned JSON metadata for automation and downstream tooling
- `events.ndjson` - normalized event stream for debugging, replay, and testing

For the full normalized event model and architecture notes, see docs below.



## Docs

- [Architecture](docs/architecture.md)
- [FAQ](docs/FAQ.md)
