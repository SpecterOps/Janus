package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Config structs (janus.yml)
// ---------------------------------------------------------------------------

type Config struct {
	Source       string          `yaml:"source"`
	Mythic       MythicCfg       `yaml:"mythic"`
	Ghostwriter  GhostwriterCfg  `yaml:"ghostwriter"`
	CobaltStrike CobaltStrikeCfg `yaml:"cobaltstrike"`
	// Docker configures extra `docker run` flags when janus-cli launches the Janus container.
	// Precedence for --network: CLI (--docker-network) overrides docker.network_mode, which
	// overrides JANUS_DOCKER_RUN_EXTRA. See docs/FAQ.md.
	Docker DockerCfg `yaml:"docker"`
}

// DockerCfg is optional janus-operator settings for the wrapper container (not Mythic/GW/CS).
type DockerCfg struct {
	NetworkMode string   `yaml:"network_mode"`
	RunExtra    []string `yaml:"run_extra"`
}

type MythicCfg struct {
	Endpoint         string `yaml:"endpoint"`
	APIToken         string `yaml:"api_token"`
	VerifyTLS        *bool  `yaml:"verify_tls"`
	OperationID      int    `yaml:"operation_id"`
	ResponsePageSize int    `yaml:"response_page_size"`
}

type GhostwriterCfg struct {
	Endpoint  string `yaml:"endpoint"`
	APIToken  string `yaml:"api_token"`
	VerifyTLS *bool  `yaml:"verify_tls"`
	OplogID   int    `yaml:"oplog_id"`
}

// CobaltStrikeCfg mirrors Config/janus.yml keys used by janus-cli pull/run for the Cobalt Strike source.
type CobaltStrikeCfg struct {
	RestEndpoint  string `yaml:"rest_endpoint"`
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	APIToken      string `yaml:"api_token"`
	RestAPIToken  string `yaml:"rest_api_token"`
	DurationMS    int    `yaml:"duration_ms"`
	OperationID   int    `yaml:"operation_id"`
	OperationName string `yaml:"operation_name"`
	VerifyTLS     *bool  `yaml:"verify_tls"`
}

// ---------------------------------------------------------------------------
// Analyzer registry structs (analyzers.yml)
// ---------------------------------------------------------------------------

type AnalyzerRegistry struct {
	Analyzers    map[string]string `yaml:"analyzers"`
	PartialLoad  []string          `yaml:"partial_load"`
	MultiAnalyze []string          `yaml:"multi_analyze"`
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

func loadConfigRequired(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s (copy Config/janus.example.yml and update values)", path)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadAnalyzers(configDir string) (*AnalyzerRegistry, error) {
	path := filepath.Join(configDir, "analyzers.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var reg AnalyzerRegistry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &reg, nil
}

func allAnalyzerNames(reg *AnalyzerRegistry) []string {
	names := make([]string, 0, len(reg.Analyzers))
	for name := range reg.Analyzers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

func resolveSource(argSource string, cfg *Config) string {
	if argSource != "" {
		return argSource
	}

	if cfg != nil {
		s := cfg.Source
		if s == "mythic" || s == "ghostwriter" || s == "cobaltstrike" {
			return s
		}

		hasMythic := hasMythicPullConfig(cfg)
		hasGhostwriter := hasGhostwriterPullConfig(cfg)
		hasCobaltStrike := hasCobaltStrikePullConfig(cfg)

		if hasGhostwriter && !hasMythic {
			return "ghostwriter"
		}
		if hasCobaltStrike && !hasMythic && !hasGhostwriter {
			return "cobaltstrike"
		}
	}

	return "mythic"
}

func resolveTargetID(source string, argOpID int, cfg *Config) int {
	if argOpID > 0 {
		return argOpID
	}
	if cfg == nil {
		return 0
	}
	if source == "ghostwriter" {
		return cfg.Ghostwriter.OplogID
	}
	if source == "cobaltstrike" {
		return cfg.CobaltStrike.OperationID
	}
	return cfg.Mythic.OperationID
}

func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) > 16 {
		return token[:8] + "..." + token[len(token)-4:]
	}
	return "***"
}

func resolveBool(b *bool, fallback bool) bool {
	if b != nil {
		return *b
	}
	return fallback
}

func resolveVerifyTLS(source string, cfg *Config) bool {
	if cfg == nil {
		return true
	}
	if source == "ghostwriter" {
		return resolveBool(cfg.Ghostwriter.VerifyTLS, true)
	}
	if source == "cobaltstrike" {
		return resolveBool(cfg.CobaltStrike.VerifyTLS, true)
	}
	return resolveBool(cfg.Mythic.VerifyTLS, true)
}

func configDir() string {
	return "Config"
}

func configFile() string {
	return filepath.Join(configDir(), "janus.yml")
}

func hasMythicPullConfig(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.Mythic.Endpoint != "" || cfg.Mythic.OperationID != 0 || cfg.Mythic.APIToken != ""
}

func hasGhostwriterPullConfig(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.Ghostwriter.Endpoint != "" || cfg.Ghostwriter.OplogID != 0 || cfg.Ghostwriter.APIToken != ""
}

func hasCobaltStrikeConfig(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	cs := cfg.CobaltStrike
	return cs.RestEndpoint != "" ||
		cs.Username != "" ||
		cs.Password != "" ||
		cs.APIToken != "" ||
		cs.RestAPIToken != "" ||
		cs.DurationMS != 0 ||
		cs.OperationID != 0 ||
		cs.OperationName != ""
}

func hasCobaltStrikePullConfig(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	cs := cfg.CobaltStrike
	return cs.RestEndpoint != "" ||
		cs.Username != "" ||
		cs.Password != "" ||
		cs.APIToken != "" ||
		cs.RestAPIToken != "" ||
		cs.OperationID != 0
}

// ensureOutPrefix prepends "out/" if the path doesn't already start with it.
func ensureOutPrefix(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "out/") && !strings.HasPrefix(p, "out\\") && p != "out" {
		return "out/" + p
	}
	return p
}

func resolvePathUnderOutForDocker(userPath string, mustExist bool, expectDir bool) (string, error) {
	if userPath == "" {
		return "", fmt.Errorf("path is empty")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	outAbs, err := filepath.Abs(filepath.Join(cwd, "out"))
	if err != nil {
		return "", fmt.Errorf("resolving out directory: %w", err)
	}

	userAbs, err := filepath.Abs(userPath)
	if err != nil {
		return "", fmt.Errorf("resolving path %q: %w", userPath, err)
	}

	if mustExist {
		info, statErr := os.Stat(userAbs)
		if statErr != nil {
			return "", fmt.Errorf("path not found: %s", userPath)
		}
		if expectDir && !info.IsDir() {
			return "", fmt.Errorf("path is not a directory: %s", userPath)
		}
		if !expectDir && info.IsDir() {
			return "", fmt.Errorf("path is a directory (expected file): %s", userPath)
		}
	}

	rel, err := filepath.Rel(outAbs, userAbs)
	if err != nil {
		return "", fmt.Errorf("resolving path under out/: %w", err)
	}

	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path must be under out/ directory: %s", userPath)
	}

	return filepath.ToSlash(filepath.Join("out", rel)), nil
}
