# Janus FAQ

Short fixes for issues hit while setting up and running Janus.

## Build and CLI

### `go` is not recognized

Go is installed, but its `bin` directory is not on `PATH`.

```powershell
$env:PATH += ";C:\Program Files\Go\bin"
```

If you prefer not to change `PATH`, call the binary directly:

```powershell
& "C:\Program Files\Go\bin\go.exe" build ...
```

### Build `janus-cli.exe` from PowerShell

PowerShell does not include `make` by default. If `make cli` reports `The term 'make' is not recognized`, build the Windows executable directly from the Go module under `cmd/janus-cli`:

```powershell
cd C:\path\to\Janus
$env:PATH += ";C:\Program Files\Go\bin"

cd .\cmd\janus-cli
& "C:\Program Files\Go\bin\go.exe" build -ldflags="-s -w -X main.version=1.0.1" -o ..\..\janus-cli.exe .

cd ..\..
.\janus-cli.exe version
```

Run `go build` from `cmd\janus-cli`, not the repository root. The repo root is not a Go module, so `go build` there reports `cannot find main module`.

If you are building from WSL or another shell with `make`, use:

```bash
make cli
```

To cross-compile every release binary, use the `cli-all` target:

```bash
make cli-all
```

Do not run `make cli all`; `all` is not a target in this repository.

### `go.sum` checksum mismatch

If `go` reports a checksum mismatch, the local `go.sum` is likely stale or corrupted. Regenerate it from `cmd/janus-cli`:

```powershell
Remove-Item cmd\janus-cli\go.sum -Force
cd cmd\janus-cli
$env:GONOSUMCHECK = "*"
& "C:\Program Files\Go\bin\go.exe" mod tidy
```

## Docker

### Docker is not running

Start Docker Desktop, wait for the engine to come up, then retry the command.

### Docker socket permission denied

This usually appears on **Linux** with Docker Engine when your user can run `docker` but is not in the `docker` group, or you added the group but have not started a new login session yet. The error often mentions permission denied while connecting to the Docker API and paths such as `/var/run/docker.sock`.

Fix:

1. Add your user to the `docker` group: `sudo usermod -aG docker "$USER"`.
2. Apply the new group: log out and back in, or run `newgrp docker` in the terminal you use for Janus.
3. Confirm `docker info` works **without** `sudo`.

Do not rely on `sudo janus-cli ...` as a workaround: it can create root-owned files under `out/`, which breaks later runs as your normal user.

On macOS or Windows, use Docker Desktop and ensure it is fully started; socket permission issues there are uncommon compared to Linux Engine.

### Docker build fails with `error getting credentials`

This often happens on macOS when `janus-cli` is run with `sudo`. Docker Desktop stores registry credentials and helper access in the normal user's context, so the root context may fail before the image build starts.

Fix:

1. Run Janus without `sudo`: `./janus-cli run`.
2. Confirm Docker works as your normal user: `docker info`.
3. If Docker still fails to read credentials, refresh Docker Desktop's registry state with `docker logout` and `docker login`, or fix/remove the broken credential helper entry in `~/.docker/config.json`.

Avoid `sudo ./janus-cli ...` on macOS and Windows. It can break Docker credential lookup and can create root-owned files under `out/`.

### `janus analyze` says an analyzer is not a valid choice

The Docker image is stale. Rebuild it, then rerun with `--no-build` if you are iterating on the same session.

```powershell
docker build -t janus:latest .
.\janus-cli.exe analyze --no-build
```

### TLS or certificate errors

Keep `verify_tls: true` for normal HTTPS deployments. Use `verify_tls: false` only for local or lab endpoints with self-signed certs that the Janus runtime does not trust yet. For plain HTTP services, use an `http://...` endpoint instead of disabling verification.

### `--network=host` does nothing on Windows

That flag is Linux-only. If a container needs to reach a host-local service, use `host.docker.internal` in the endpoint URL instead of `localhost`.

### Cobalt Strike REST and janus-cli + Docker

`janus-cli` runs the Janus Python entrypoint **inside a Docker container**. In that network namespace, `https://127.0.0.1:...` and `https://localhost:...` refer to the **container’s** loopback interface, not your host. If Cobalt Strike REST (or another API) is listening on the host, you will often see **connection refused** even though `curl` from the host works.

What to do:

1. **Linux — host networking (quick):** run with `--docker-network host` (global flag before the subcommand is fine), for example:
   - `./janus-cli --docker-network host pull --source cobaltstrike`
   - Or set `docker.network_mode: host` in `Config/janus.yml` (see the example file).
2. **Keep default bridge networking:** point `cobaltstrike.rest_endpoint` at a **routable** teamserver IP or DNS name the container can reach, not loopback.
3. **Host gateway (Linux bridge):** use `https://host.docker.internal:PORT` in `rest_endpoint` and start the wrapper with `--docker-add-host host.docker.internal:host-gateway`, or add the same pair under `docker.run_extra` in `Config/janus.yml`.
4. **macOS / Windows Docker Desktop:** prefer `host.docker.internal` in the REST URL instead of `127.0.0.1` (`docker run --network host` is not supported the same way as on Linux Engine).

Extra `docker run` tokens for automation: set **`JANUS_DOCKER_RUN_EXTRA`** (space-separated; lowest precedence). Precedence for `--network` is: **`janus-cli --docker-network` > `docker.network_mode` in config > `JANUS_DOCKER_RUN_EXTRA`**.

Avoid `sudo janus-cli` when fixing Docker socket issues; it can leave root-owned files under `out/` (see **Docker socket permission denied** above).

## Python

### `python` or `python3` is not found

On Windows, run `python --version` and install Python from [python.org](https://www.python.org/downloads/) if needed. Make sure "Add Python to PATH" is enabled.

### `pytest` is not found

Install the test dependency in the active environment:

```powershell
pip install pytest
python -m pytest Tests/
```

### Missing Python dependencies

Install the repo requirements:

```powershell
pip install -r requirements.txt
```

Direct `python janus.py` is mainly for development. The recommended path is `janus-cli`, which builds the Docker image and handles mounts for you. Cobalt Strike ingest uses the REST workflow behind `./janus-cli pull --source cobaltstrike` and `./janus-cli run --source cobaltstrike`. Configure `cobaltstrike:` in `Config/janus.yml` or pass `--endpoint` / `--api-token` / credentials as flags; if you provide username/password, Janus logs in first and reuses the returned bearer token automatically.

## Payload size and `output_rule`

### My `events.ndjson` is huge (base64 / long success output)

Set `output_rule: errors_only` in `Config/janus.yml`. On the next pull (or when re-normalizing with the Python CLI’s `--output-rule errors_only` on `run`, `partial-load`, or `ghostwriter-load`), Janus clears `output_text` only for results with `status: success`, which drops most bulk from large successful returns while keeping error and unknown transcripts. To drop all output regardless of status, use `output_rule: none`.

**Caveats:**

- The `av-tracker` analyzer uses successful `ps` output; use `all` if you need AV/EDR coincidences from process listings.
- `merge` / `multi-analyze` do not re-filter existing NDJSON; generate events with `errors_only` before merging if you want smaller merged files.
- Ghostwriter `raw_export.json` is unchanged; only `events.ndjson` is affected.

Check `bundle.json` for `output_rule` to see what was applied for that run.

### Mythic pulls fail on very large response rows

Janus pages Mythic `response` rows at 500 rows per GraphQL request by default. If a deployment has unusually large `response_text` values, lower the page size:

```powershell
./janus-cli pull --source mythic --response-page-size 100
./janus-cli run --source mythic --response-page-size 100
```

You can also set it manually in `Config/janus.yml`:

```yaml
mythic:
  response_page_size: 100
```

`bundle.json` records the resolved `responses_page_size` used for that pull.

## Privacy and retention

### How do I strip sensitive arguments from stored events?

Set `arguments_rule` in `Config/janus.yml` or pass `--arguments-rule` on the CLI:

```yaml
arguments_rule: drop           # remove all raw arguments
arguments_rule: hash           # replace with SHA-256 digest (correlation without content)
arguments_rule: features_only  # replace with derived metadata (length, shape, entropy)
```

This is applied after normalization and before `events.ndjson` is written. `bundle.json` records the resolved policy.

### Which analyzers break under restricted retention?

`parameter-entropy` and `argument-position-profile` depend on full `arguments_raw` and produce empty or severely limited output under `drop`, `hash`, or `features_only`. `av-tracker` depends on successful `output_text` and produces no detections under `output_rule: errors_only` or `none`. Other analyzers degrade gracefully: core metrics stay intact but detail rows show empty arguments or output. See the compatibility table in [docs/architecture.md — Analyzer Compatibility](architecture.md#analyzer-compatibility).

### How do I verify what retention policy was applied?

Check `bundle.json` in the run directory:

```json
{
  "output_rule": "errors_only",
  "arguments_rule": "drop"
}
```

For normal single-operation runs, `bundle.json` is the authoritative privacy record. Event-level fields such as `arguments_retained` and `output_retained` are still written so analyzers can tell "empty by policy" from "genuinely empty", even when the original value was already blank. Under `output_rule: errors_only`, Janus also records `output_retained: errors_only` on result events whose output remains visible so downstream consumers can still detect the active policy when a dataset has no successful results.

If you merge runs with different settings, the merged `bundle.json` records `output_rule: mixed` and/or `arguments_rule: mixed` plus `observed_output_rules` / `observed_arguments_rules` arrays listing the exact policies present. The HTML report also displays a retention policy banner in the Report Overview section when non-default or mixed policies are active.

### Does Janus send data to any external service?

No. Janus does not use LLMs, cloud analytics, or telemetry services. Network access is limited to the source systems you configure for data collection (Mythic, Ghostwriter, or Cobalt Strike REST endpoints). See [docs/architecture.md — Privacy](architecture.md#privacy) for the full data handling model.

## Existing Events

### I already have an `events.ndjson`

Pass it directly with `--events`:

```powershell
.\janus-cli.exe analyze --events out\events.ndjson
.\janus-cli.exe analyze --events .\out\complete\operation-chimera_20260306_174521\events.ndjson
```

The file must resolve under this repo's `out/` tree so Docker can see it. Analyzer output lands in the same directory as the input file.

## Workflow

### Preferred Windows flow

1. Build the CLI once with the PowerShell commands in [Build `janus-cli.exe` from PowerShell](#build-janus-cliexe-from-powershell).
2. Start Docker Desktop.
3. Run `.\janus-cli.exe run`, `analyze`, or `status` as needed.

### After changing Python code

Rebuild the Docker image before rerunning analysis:

```powershell
.\janus-cli.exe build
```

### `go.sum` keeps getting corrupted

VS Code can append hidden JSON blobs to files in some cases. If `go.sum` looks wrong again, delete and regenerate it the same way as above.
