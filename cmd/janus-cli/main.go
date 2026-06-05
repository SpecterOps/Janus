package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3" (e.g. GitHub release workflow).
// Default should match [project].version in pyproject.toml (bundles use get_janus_version()).
var version = "1.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `janus-cli — Janus operator CLI

Usage: janus-cli <command> [options]

Commands:
  build          Build the Docker image
  pull           Pull data from Mythic, Ghostwriter, Cobalt Strike, or Outflank
  analyze        Run analyzers against the latest pull (or --events <path>)
  report         Generate HTML report from the latest analysis
  run            Pull + analyze + report in one shot for any supported source
  merge          Merge multiple operations into a unified dataset
  multi-analyze  Merge + run the multi-op analyzer set + report
  status         Show current output state
  config         Display current configuration
  version        Print the version and exit

Examples:
  janus-cli run                                       # full pipeline for the configured source
  janus-cli run --source ghostwriter                  # full pipeline using Ghostwriter
  janus-cli run --source cobaltstrike                 # full pipeline using Cobalt Strike REST
  janus-cli run --source outflank --log-path out/input/TSO8IEAB.json
  janus-cli run --op-id 3                             # full pipeline for operation 3
  janus-cli run --source mythic --response-page-size 100
  janus-cli pull --source mythic --op-id 2
  janus-cli pull --source cobaltstrike --username operator --password <teamserver-password>
  janus-cli analyze                                   # analyze latest pull
  janus-cli analyze --events out/events.ndjson        # analyze a specific events file
  janus-cli analyze --analyzer command-failure-summary
  janus-cli report                                    # report on latest analysis
  janus-cli report --json out/complete/operation-bofdev_20260318_140203
  janus-cli merge --pattern "partial/*/" --output out/combined/
  janus-cli status
  janus-cli config
  janus-cli version

Global docker wrapper flags (may appear before the subcommand):
  janus-cli --docker-network host pull --source cobaltstrike ...
  janus-cli --docker-add-host host.docker.internal:host-gateway pull --source cobaltstrike --insecure

Or set JANUS_DOCKER_RUN_EXTRA (extra docker run tokens; lowest precedence).
See docs/FAQ.md for Cobalt Strike REST + Docker / host-local APIs.
`)
}

func bindDockerRunFlags(fs *flag.FlagSet) (dockerNet *string, dockerAddHost *string) {
	dockerNet = fs.String("docker-network", "", "docker run --network (e.g. host on Linux); merges with leading global --docker-network")
	dockerAddHost = fs.String("docker-add-host", "", "docker run --add-host value (e.g. host.docker.internal:host-gateway)")
	return dockerNet, dockerAddHost
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	args := parseLeadingGlobalFlags(os.Args[1:])
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	cmd := args[0]
	args = args[1:]

	var rc int
	switch cmd {
	case "build":
		rc = cmdBuild(args)
	case "pull":
		rc = cmdPull(args)
	case "analyze":
		rc = cmdAnalyze(args)
	case "report":
		rc = cmdReport(args)
	case "run":
		rc = cmdRun(args)
	case "merge":
		rc = cmdMerge(args)
	case "multi-analyze":
		rc = cmdMultiAnalyze(args)
	case "status":
		rc = cmdStatus()
	case "config":
		rc = cmdConfig()
	case "version", "-v", "--version":
		fmt.Println(version)
		rc = 0
	case "-h", "--help", "help":
		usage()
		rc = 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", cmd)
		usage()
		rc = 1
	}
	os.Exit(rc)
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

func cmdBuild(_ []string) int {
	if err := buildImage(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func cmdPull(args []string) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	source := fs.String("source", "", "Data source: mythic, ghostwriter, cobaltstrike, or outflank")
	opID := fs.Int("op-id", 0, "Operation/oplog ID (Cobalt Strike and Outflank use a synthetic operation ID)")
	endpoint := fs.String("endpoint", "", "Override source endpoint/base URL")
	apiToken := fs.String("api-token", "", "Override source API token/bearer token")
	username := fs.String("username", "", "Override Cobalt Strike username")
	password := fs.String("password", "", "Override Cobalt Strike password")
	durationMS := fs.Int("duration-ms", 0, "Cobalt Strike REST login token lifetime in ms")
	opName := fs.String("operation-name", "", "Cobalt Strike or Outflank operation/display name")
	logPath := fs.String("log-path", "", "Outflank implant log file or directory under out/")
	insecure := fs.Bool("insecure", false, "Disable TLS verification for the selected source")
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	debug := fs.Bool("debug", false, "Print request/response for troubleshooting")
	responsePageSize := fs.Int("response-page-size", 0, "Mythic response rows per GraphQL page (default: config or 500)")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(args)
	if *responsePageSize < 0 {
		fmt.Fprintln(os.Stderr, "error: --response-page-size must be >= 1")
		return 1
	}

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	cfg, err := loadConfigRequired(configFile())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	src := resolveSource(*source, cfg)
	tid := resolveTargetID(src, *opID, cfg)

	if src == "ghostwriter" && (strings.TrimSpace(*username) != "" || strings.TrimSpace(*password) != "") {
		fmt.Fprintln(os.Stderr, "error: Ghostwriter uses API token auth only. Use --api-token or set ghostwriter.api_token / GHOSTWRITER_API_KEY.")
		return 1
	}

	if src == "cobaltstrike" {
		return cmdPullCobaltStrike(cfg, *endpoint, *username, *password, *apiToken, *durationMS, tid, *opName, *insecure, *debug, *dockerNet, *dockerAddHost)
	}
	if src == "outflank" {
		return cmdPullOutflank(cfg, *logPath, tid, *opName, *debug, *dockerNet, *dockerAddHost)
	}

	if tid == 0 {
		idName := "operation_id"
		idLabel := "operation ID"
		if src == "ghostwriter" {
			idName = "oplog_id"
			idLabel = "oplog ID"
		}
		fmt.Fprintf(os.Stderr, "error: %s required for %s pull. Use --op-id or set %s in Config/janus.yml\n", idLabel, src, idName)
		return 1
	}

	dockerArgs := []string{
		"run",
		"--source", src,
		"--config", "/config/janus.yml",
		"--out-dir", "out/complete",
	}
	if strings.TrimSpace(*endpoint) != "" {
		dockerArgs = append(dockerArgs, "--endpoint", strings.TrimSpace(*endpoint))
	}
	if strings.TrimSpace(*apiToken) != "" {
		dockerArgs = append(dockerArgs, "--api-token", strings.TrimSpace(*apiToken))
	}
	if *insecure || !resolveVerifyTLS(src, cfg) {
		dockerArgs = append(dockerArgs, "--insecure")
	}
	if src == "ghostwriter" {
		dockerArgs = append(dockerArgs, "--oplog-id", fmt.Sprintf("%d", tid))
	} else {
		dockerArgs = append(dockerArgs, "--operation-id", fmt.Sprintf("%d", tid))
	}
	if *debug {
		dockerArgs = append(dockerArgs, "--debug")
	}
	if src == "mythic" && *responsePageSize > 0 {
		dockerArgs = append(dockerArgs, "--response-page-size", fmt.Sprintf("%d", *responsePageSize))
	}

	if err := dockerRun(dockerArgs, false, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// defaultCSRestEndpoint matches janus.py DEFAULT_COBALT_STRIKE_REST_ENDPOINT.
const defaultCSRestEndpoint = "https://127.0.0.1:50050"

func resolveCobaltStrikeInputs(cfg *Config, endpoint string, username string, password string, apiToken string, durationMS int, opID int, opName string) (string, string, string, string, int, int, string) {
	token := strings.TrimSpace(apiToken)
	u := strings.TrimSpace(username)
	p := strings.TrimSpace(password)
	if token == "" {
		token = strings.TrimSpace(cfg.CobaltStrike.APIToken)
		if token == "" {
			token = strings.TrimSpace(cfg.CobaltStrike.RestAPIToken)
		}
	}
	if u == "" {
		u = strings.TrimSpace(cfg.CobaltStrike.Username)
	}
	if p == "" {
		p = strings.TrimSpace(cfg.CobaltStrike.Password)
	}

	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		ep = strings.TrimSpace(cfg.CobaltStrike.RestEndpoint)
	}
	if ep == "" {
		ep = defaultCSRestEndpoint
	}

	dur := durationMS
	if dur <= 0 && cfg.CobaltStrike.DurationMS > 0 {
		dur = cfg.CobaltStrike.DurationMS
	}

	resolvedOpID := opID
	if resolvedOpID == 0 && cfg.CobaltStrike.OperationID != 0 {
		resolvedOpID = cfg.CobaltStrike.OperationID
	}

	oname := strings.TrimSpace(opName)
	if oname == "" {
		oname = strings.TrimSpace(cfg.CobaltStrike.OperationName)
	}

	return ep, u, p, token, dur, resolvedOpID, oname
}

func cmdPullCobaltStrike(cfg *Config, endpoint string, username string, password string, apiToken string, durationMS int, opID int, opName string, insecure bool, debug bool, dockerNet string, dockerAddHost string) int {
	ep, u, p, token, dur, resolvedOpID, oname := resolveCobaltStrikeInputs(cfg, endpoint, username, password, apiToken, durationMS, opID, opName)
	if token == "" && (u == "" || p == "") {
		fmt.Fprintln(os.Stderr, "error: Cobalt Strike REST auth required for cobaltstrike pull: use --api-token, or --username and --password, or set cobaltstrike.api_token (or username/password) in Config/janus.yml")
		return 1
	}

	dockerArgs := []string{
		"cs-rest",
		"--config", "/config/janus.yml",
		"--out-dir", "out/complete",
		"--endpoint", ep,
		"--no-analyzers",
		"--operation-id", fmt.Sprintf("%d", resolvedOpID),
	}
	if token != "" {
		dockerArgs = append(dockerArgs, "--api-token", token)
	} else {
		dockerArgs = append(dockerArgs, "--username", u, "--password", p)
	}
	if dur > 0 {
		dockerArgs = append(dockerArgs, "--duration-ms", fmt.Sprintf("%d", dur))
	}
	if oname != "" {
		dockerArgs = append(dockerArgs, "--operation-name", oname)
	}
	if insecure || !resolveVerifyTLS("cobaltstrike", cfg) {
		dockerArgs = append(dockerArgs, "--insecure")
	}
	if debug {
		dockerArgs = append(dockerArgs, "--debug")
	}

	if err := dockerRun(dockerArgs, false, dockerNet, dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func resolveOutflankInputs(cfg *Config, logPath string, opID int, opName string) (string, int, string) {
	lp := strings.TrimSpace(logPath)
	if lp == "" {
		lp = strings.TrimSpace(cfg.Outflank.LogPath)
	}

	resolvedOpID := opID
	if resolvedOpID == 0 && cfg.Outflank.OperationID != 0 {
		resolvedOpID = cfg.Outflank.OperationID
	}

	oname := strings.TrimSpace(opName)
	if oname == "" {
		oname = strings.TrimSpace(cfg.Outflank.OperationName)
	}

	return lp, resolvedOpID, oname
}

func cmdPullOutflank(cfg *Config, logPath string, opID int, opName string, debug bool, dockerNet string, dockerAddHost string) int {
	lp, resolvedOpID, oname := resolveOutflankInputs(cfg, logPath, opID, opName)
	if lp == "" {
		fmt.Fprintln(os.Stderr, "error: Outflank log path required for outflank pull: use --log-path or set outflank.log_path in Config/janus.yml")
		fmt.Fprintln(os.Stderr, "hint: janus-cli only mounts ./out into Docker; put copied logs under out/input/ or another out/ subdirectory.")
		return 1
	}

	containerLogPath, err := resolveAnyPathUnderOutForDocker(lp, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: Outflank log path must be an existing file or directory under out/: %v\n", err)
		return 1
	}

	dockerArgs := []string{
		"outflank-load",
		containerLogPath,
		"--config", "/config/janus.yml",
		"--out-dir", "out/complete",
		"--no-analyzers",
	}
	if resolvedOpID != 0 {
		dockerArgs = append(dockerArgs, "--operation-id", fmt.Sprintf("%d", resolvedOpID))
	}
	if oname != "" {
		dockerArgs = append(dockerArgs, "--operation-name", oname)
	}
	_ = debug

	if err := dockerRun(dockerArgs, false, dockerNet, dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func cmdCsRest(args []string) int {
	fs := flag.NewFlagSet("cs-rest", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "Cobalt Strike REST base URL (no path suffix); default: config or "+defaultCSRestEndpoint)
	username := fs.String("username", "", "REST login username")
	password := fs.String("password", "", "REST login password")
	apiToken := fs.String("api-token", "", "Bearer token (skip login); or set cobaltstrike.api_token in config")
	durationMS := fs.Int("duration-ms", 0, "Login token lifetime in ms (0: use config duration_ms or Janus default)")
	opID := fs.Int("operation-id", 0, "Synthetic operation_id in bundle (0: use config or 0)")
	opName := fs.String("operation-name", "", "Display name for output paths (default: janus default)")
	outDir := fs.String("out-dir", "out/partial", "Output directory (under ./out mount)")
	noVersioning := fs.Bool("no-versioning", false, "Write directly to out-dir without versioned subfolder")
	noAnalyzers := fs.Bool("no-analyzers", false, "Only normalize to events.ndjson + bundle.json")
	insecure := fs.Bool("insecure", false, "Disable TLS verification for REST")
	debug := fs.Bool("debug", false, "Verbose REST troubleshooting")
	outputRule := fs.String("output-rule", "", "Optional: all or errors_only")
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(args)

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	cfg := &Config{}
	if c, err := loadConfig(configFile()); err == nil {
		cfg = c
	}

	ep, u, p, token, dur, resolvedOpID, oname := resolveCobaltStrikeInputs(cfg, *endpoint, *username, *password, *apiToken, *durationMS, *opID, *opName)
	if token == "" && (u == "" || p == "") {
		fmt.Fprintln(os.Stderr, "error: Cobalt Strike REST auth required: use --api-token, or --username and --password, or set cobaltstrike.api_token (or username/password) in Config/janus.yml")
		return 1
	}

	out := filepath.ToSlash(strings.TrimSpace(*outDir))
	if out == "" {
		out = "out/partial"
	}
	if out == "out" {
		out = "out/partial"
	}
	if !strings.HasPrefix(out, "out/") {
		out = filepath.ToSlash(filepath.Join("out", strings.TrimPrefix(out, "/")))
	}

	dockerArgs := []string{
		"cs-rest",
		"--config", "/config/janus.yml",
		"--out-dir", out,
		"--endpoint", ep,
	}
	if token != "" {
		dockerArgs = append(dockerArgs, "--api-token", token)
	} else {
		dockerArgs = append(dockerArgs, "--username", u, "--password", p)
	}
	if dur > 0 {
		dockerArgs = append(dockerArgs, "--duration-ms", fmt.Sprintf("%d", dur))
	}
	dockerArgs = append(dockerArgs, "--operation-id", fmt.Sprintf("%d", resolvedOpID))
	if oname != "" {
		dockerArgs = append(dockerArgs, "--operation-name", oname)
	}
	if *insecure {
		dockerArgs = append(dockerArgs, "--insecure")
	}
	if *debug {
		dockerArgs = append(dockerArgs, "--debug")
	}
	if *noVersioning {
		dockerArgs = append(dockerArgs, "--no-versioning")
	}
	if *noAnalyzers {
		dockerArgs = append(dockerArgs, "--no-analyzers")
	}
	if strings.TrimSpace(*outputRule) != "" {
		dockerArgs = append(dockerArgs, "--output-rule", strings.TrimSpace(*outputRule))
	}

	if err := dockerRun(dockerArgs, false, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func cmdAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	analyzer := fs.String("analyzer", "", "Run only this analyzer (default: all)")
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	eventsFlag := fs.String("events", "", "Path to events.ndjson to analyze (e.g. out/events.ndjson); skips auto-detection")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(args)

	containerEvents, containerOut, err := resolveAnalyzeTarget(*eventsFlag, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	if *analyzer != "" {
		rc := runAnalyzeTarget(containerEvents, containerOut, *analyzer, *dockerNet, *dockerAddHost)
		if rc == 0 && *eventsFlag != "" {
			// Update latest.txt so subsequent `report` targets the right folder.
			hostDir := filepath.Dir(*eventsFlag)
			if err := writeLatestMarker(hostDir); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update latest marker: %v\n", err)
			}
		}
		return rc
	}

	if err := dockerRun([]string{
		"analyze",
		"--all",
		"--events", containerEvents,
		"--out-dir", containerOut,
	}, false, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if *eventsFlag != "" {
		// Update latest.txt so subsequent `report` targets the right folder.
		hostDir := filepath.Dir(*eventsFlag)
		if err := writeLatestMarker(hostDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not update latest marker: %v\n", err)
		}
	}
	return 0
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	jsonDir := fs.String("json", "", "Path to a folder containing analysis JSON files (skips auto-detection of latest)")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(args)

	var target string
	if *jsonDir != "" {
		// Explicit folder supplied — validate it exists.
		info, err := os.Stat(*jsonDir)
		if err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "error: --json path does not exist or is not a directory: %s\n", *jsonDir)
			return 1
		}
		target = filepath.Clean(*jsonDir)
	} else {
		target = getLatestDir()
		if target == "" {
			fmt.Fprintln(os.Stderr, "error: no output directory found. Run 'pull' and 'analyze' first, or use --json <dir>.")
			return 1
		}
	}

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	if err := runReportTarget(target, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Printf("Report: %s\n", filepath.Join(target, "report.html"))
	return 0
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	source := fs.String("source", "", "Data source: mythic, ghostwriter, cobaltstrike, or outflank")
	opID := fs.Int("op-id", 0, "Operation/oplog ID (Cobalt Strike and Outflank use a synthetic operation ID)")
	endpoint := fs.String("endpoint", "", "Override source endpoint/base URL")
	apiToken := fs.String("api-token", "", "Override source API token/bearer token")
	username := fs.String("username", "", "Override Cobalt Strike username")
	password := fs.String("password", "", "Override Cobalt Strike password")
	durationMS := fs.Int("duration-ms", 0, "Cobalt Strike REST login token lifetime in ms")
	opName := fs.String("operation-name", "", "Cobalt Strike or Outflank operation/display name")
	logPath := fs.String("log-path", "", "Outflank implant log file or directory under out/")
	insecure := fs.Bool("insecure", false, "Disable TLS verification for the selected source")
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	responsePageSize := fs.Int("response-page-size", 0, "Mythic response rows per GraphQL page (default: config or 500)")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(args)
	if *responsePageSize < 0 {
		fmt.Fprintln(os.Stderr, "error: --response-page-size must be >= 1")
		return 1
	}

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	cfg, err := loadConfigRequired(configFile())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	src := resolveSource(*source, cfg)

	// Pull
	fmt.Printf("==> Pulling from %s...\n", strings.ToUpper(src[:1])+src[1:])
	pullArgs := []string{"--no-build", "--source", src}
	if *opID > 0 {
		pullArgs = append(pullArgs, "--op-id", fmt.Sprintf("%d", *opID))
	}
	if strings.TrimSpace(*endpoint) != "" {
		pullArgs = append(pullArgs, "--endpoint", strings.TrimSpace(*endpoint))
	}
	if strings.TrimSpace(*apiToken) != "" {
		pullArgs = append(pullArgs, "--api-token", strings.TrimSpace(*apiToken))
	}
	if strings.TrimSpace(*username) != "" {
		pullArgs = append(pullArgs, "--username", strings.TrimSpace(*username))
	}
	if strings.TrimSpace(*password) != "" {
		pullArgs = append(pullArgs, "--password", strings.TrimSpace(*password))
	}
	if *durationMS > 0 {
		pullArgs = append(pullArgs, "--duration-ms", fmt.Sprintf("%d", *durationMS))
	}
	if strings.TrimSpace(*opName) != "" {
		pullArgs = append(pullArgs, "--operation-name", strings.TrimSpace(*opName))
	}
	if strings.TrimSpace(*logPath) != "" {
		pullArgs = append(pullArgs, "--log-path", strings.TrimSpace(*logPath))
	}
	if *insecure {
		pullArgs = append(pullArgs, "--insecure")
	}
	if src == "mythic" && *responsePageSize > 0 {
		pullArgs = append(pullArgs, "--response-page-size", fmt.Sprintf("%d", *responsePageSize))
	}
	if n := firstNonEmpty(*dockerNet, globalDockerNetwork); n != "" {
		pullArgs = append([]string{"--docker-network", n}, pullArgs...)
	}
	if h := firstNonEmpty(*dockerAddHost, globalDockerAddHost); h != "" {
		pullArgs = append([]string{"--docker-add-host", h}, pullArgs...)
	}
	if rc := cmdPull(pullArgs); rc != 0 {
		return rc
	}

	latest := getLatestDir()
	if latest == "" {
		fmt.Fprintln(os.Stderr, "error: pull completed but no output directory was found.")
		return 1
	}

	containerEvents, containerOut, err := resolveAnalyzeTarget("", latest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Analyze
	fmt.Println("\n==> Running all analyzers...")
	if err := dockerRun([]string{
		"analyze",
		"--all",
		"--events", containerEvents,
		"--out-dir", containerOut,
	}, false, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Report
	fmt.Println("\n==> Generating HTML report...")
	if err := runReportTarget(latest, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if latest != "" {
		fmt.Printf("\nDone. Output in: %s\n", latest)
		reportPath := filepath.Join(latest, "report.html")
		if _, err := os.Stat(reportPath); err == nil {
			fmt.Printf("Report:          %s\n", reportPath)
		}
	}

	return 0
}

func cmdMerge(args []string) int {
	parsedArgs, explicitInputs, err := extractInputsArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	pattern := fs.String("pattern", "", "Glob pattern for operation directories")
	output := fs.String("output", "", "Output directory for merged data (required)")
	opName := fs.String("operation-name", "Multi-Operation Analysis", "Name for merged operation")
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(parsedArgs)

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	if *output == "" {
		fmt.Fprintln(os.Stderr, "error: --output is required")
		return 1
	}

	inputPaths, rc := resolveInputPaths(*pattern, append(explicitInputs, fs.Args()...))
	if rc != 0 {
		return rc
	}

	containerInputs := make([]string, 0, len(inputPaths))
	for _, p := range inputPaths {
		containerPath, err := resolvePathUnderOutForDocker(p, true, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		containerInputs = append(containerInputs, containerPath)
	}

	containerOutput, err := resolvePathUnderOutForDocker(*output, false, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	dockerArgs := []string{"merge", "--inputs"}
	dockerArgs = append(dockerArgs, containerInputs...)
	dockerArgs = append(dockerArgs, "--output", containerOutput)
	if *opName != "" {
		dockerArgs = append(dockerArgs, "--operation-name", *opName)
	}

	if err := dockerRun(dockerArgs, false, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func cmdMultiAnalyze(args []string) int {
	parsedArgs, explicitInputs, err := extractInputsArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fs := flag.NewFlagSet("multi-analyze", flag.ExitOnError)
	pattern := fs.String("pattern", "", "Glob pattern for operation directories")
	output := fs.String("output", "", "Output directory (required)")
	opName := fs.String("operation-name", "Multi-Operation Analysis", "Name for merged operation")
	noBuild := fs.Bool("no-build", false, "Skip Docker image rebuild")
	dockerNet, dockerAddHost := bindDockerRunFlags(fs)
	fs.Parse(parsedArgs)

	if !*noBuild {
		if err := buildImage(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	if *output == "" {
		fmt.Fprintln(os.Stderr, "error: --output is required")
		return 1
	}

	inputPaths, rc := resolveInputPaths(*pattern, append(explicitInputs, fs.Args()...))
	if rc != 0 {
		return rc
	}

	containerInputs := make([]string, 0, len(inputPaths))
	for _, p := range inputPaths {
		containerPath, err := resolvePathUnderOutForDocker(p, true, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		containerInputs = append(containerInputs, containerPath)
	}

	containerOutput, err := resolvePathUnderOutForDocker(*output, false, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	dockerArgs := []string{"multi-analyze", "--inputs"}
	dockerArgs = append(dockerArgs, containerInputs...)
	dockerArgs = append(dockerArgs, "--output", containerOutput)
	if *opName != "" {
		dockerArgs = append(dockerArgs, "--operation-name", *opName)
	}

	if err := dockerRun(dockerArgs, false, *dockerNet, *dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	reportPath := filepath.Join(*output, "report.html")
	if _, err := os.Stat(reportPath); err == nil {
		fmt.Printf("\nReport: %s\n", reportPath)
	}
	return 0
}

func resolveAnalyzeTarget(eventsFlag string, latestOverride string) (string, string, error) {
	if eventsFlag != "" {
		containerEventsPath, err := resolvePathUnderOutForDocker(eventsFlag, true, false)
		if err != nil {
			return "", "", err
		}
		if filepath.Base(containerEventsPath) != "events.ndjson" {
			return "", "", fmt.Errorf("--events must point to an events.ndjson file: %s", eventsFlag)
		}
		return containerEventsPath, filepath.ToSlash(filepath.Dir(containerEventsPath)), nil
	}

	latest := latestOverride
	if latest == "" {
		latest = getLatestDir()
	}
	if latest == "" {
		return "", "", fmt.Errorf("no output directory found.\n  Run 'pull' first, or use --events to analyze an existing events file:\n  janus-cli analyze --events out/events.ndjson")
	}

	eventsPath := filepath.Join(latest, "events.ndjson")
	if _, err := os.Stat(eventsPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("events file not found at %s\nRun './janus-cli pull' first.", eventsPath)
	}

	containerOut, err := resolvePathUnderOutForDocker(latest, true, true)
	if err != nil {
		return "", "", err
	}

	return filepath.ToSlash(filepath.Join(containerOut, "events.ndjson")), containerOut, nil
}

func runAnalyzeTarget(containerEvents string, containerOut string, analyzer string, dockerNet string, dockerAddHost string) int {
	reg, err := loadAnalyzers(configDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if _, ok := reg.Analyzers[analyzer]; !ok {
		fmt.Fprintf(os.Stderr, "error: unknown analyzer %q\n", analyzer)
		fmt.Fprintf(os.Stderr, "Available: %s\n", strings.Join(allAnalyzerNames(reg), ", "))
		return 1
	}
	if err := dockerRun([]string{
		"analyze",
		"--analyzer", analyzer,
		"--events", containerEvents,
		"--out-dir", containerOut,
	}, false, dockerNet, dockerAddHost); err != nil {
		fmt.Fprintf(os.Stderr, "error: analyzer %q failed: %v\n", analyzer, err)
		return 1
	}
	return 0
}

func runReportTarget(latest string, dockerNet string, dockerAddHost string) error {
	containerDir, err := resolvePathUnderOutForDocker(latest, true, true)
	if err != nil {
		return err
	}
	containerOutput := filepath.ToSlash(filepath.Join(containerDir, "report.html"))

	return dockerRun([]string{
		"html",
		"--analysis-dir", containerDir,
		"--output", containerOutput,
	}, false, dockerNet, dockerAddHost)
}

// extractInputsArgs removes the custom "--inputs" list from args so later flags
// still parse correctly, while preserving the input paths in encounter order.
func extractInputsArgs(args []string) ([]string, []string, error) {
	parsed := make([]string, 0, len(args))
	inputs := make([]string, 0)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg != "--inputs" {
			parsed = append(parsed, arg)
			continue
		}

		if i+1 >= len(args) || looksLikeFlag(args[i+1]) {
			return nil, nil, fmt.Errorf("--inputs requires at least one path")
		}

		for i+1 < len(args) && !looksLikeFlag(args[i+1]) {
			i++
			inputs = append(inputs, args[i])
		}
	}

	return parsed, inputs, nil
}

func looksLikeFlag(arg string) bool {
	return strings.HasPrefix(arg, "-") && arg != "-"
}

// resolveInputPaths handles --pattern glob expansion or positional --inputs args.
func resolveInputPaths(pattern string, positional []string) ([]string, int) {
	if pattern != "" {
		expanded := ensureOutPrefix(pattern)
		matches, err := filepath.Glob(expanded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: bad glob pattern: %v\n", err)
			return nil, 1
		}
		// Filter to directories only
		var dirs []string
		for _, m := range matches {
			info, err := os.Stat(m)
			if err == nil && info.IsDir() {
				dirs = append(dirs, filepath.ToSlash(m))
			}
		}
		if len(dirs) == 0 {
			fmt.Fprintf(os.Stderr, "error: no directories matched pattern: %s\n", pattern)
			return nil, 1
		}
		return dirs, 0
	}

	if len(positional) > 0 {
		return positional, 0
	}

	fmt.Fprintln(os.Stderr, "error: provide --pattern or input paths as positional arguments")
	return nil, 1
}
