package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var versionedSuffix = regexp.MustCompile(`_\d{8}_\d{6}(_[a-f0-9]{8})?$`)

func isVersionedDir(path string) bool {
	name := filepath.Base(path)
	if name == "latest" || name == "latest.txt" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	// Check for bundle.json
	if _, err := os.Stat(filepath.Join(path, "bundle.json")); err == nil {
		return true
	}
	return versionedSuffix.MatchString(name)
}

func getLatestDir() string {
	completeDir := filepath.Join("out", "complete")

	// 1. Check latest.txt
	markerPath := filepath.Join(completeDir, "latest.txt")
	if data, err := os.ReadFile(markerPath); err == nil {
		name := strings.TrimSpace(string(data))
		candidate := filepath.Join(completeDir, name)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	// 2. Check latest symlink
	linkPath := filepath.Join(completeDir, "latest")
	if target, err := os.Readlink(linkPath); err == nil {
		resolved := target
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(completeDir, resolved)
		}
		if info, err := os.Stat(resolved); err == nil && info.IsDir() {
			return resolved
		}
	}

	// 3. Newest by mtime
	entries, err := os.ReadDir(completeDir)
	if err != nil {
		return ""
	}

	type dirEntry struct {
		path  string
		mtime time.Time
	}
	var versioned []dirEntry
	for _, e := range entries {
		p := filepath.Join(completeDir, e.Name())
		if isVersionedDir(p) {
			if info, err := e.Info(); err == nil {
				versioned = append(versioned, dirEntry{p, info.ModTime()})
			}
		}
	}

	if len(versioned) == 0 {
		return ""
	}

	sort.Slice(versioned, func(i, j int) bool {
		return versioned[i].mtime.After(versioned[j].mtime)
	})
	return versioned[0].path
}

// writeLatestMarker updates out/complete/latest.txt to point to the top-level
// versioned directory that contains dir (i.e. the direct child of out/complete/).
// It is a no-op when dir is not anywhere under out/complete/ (e.g. out/partial/).
func writeLatestMarker(dir string) error {
	completeDir := filepath.Join("out", "complete")
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	absComplete, err := filepath.Abs(completeDir)
	if err != nil {
		return err
	}

	// Walk up from abs until we find the direct child of absComplete.
	// This handles both flat layouts (out/complete/op-slug_ts/) and nested
	// layouts (out/complete/op-slug/op-slug_ts/).
	candidate := abs
	for {
		parent := filepath.Dir(candidate)
		if parent == absComplete {
			// candidate is a direct child of out/complete/ — use it.
			markerPath := filepath.Join(completeDir, "latest.txt")
			return os.WriteFile(markerPath, []byte(filepath.Base(candidate)), 0o644)
		}
		if parent == candidate {
			// Reached filesystem root without finding out/complete/ — not our tree.
			return nil
		}
		candidate = parent
	}
}

func cmdStatus() int {
	if _, err := os.Stat("out"); os.IsNotExist(err) {
		fmt.Println("No output directory found. Run './janus-cli pull' to get started.")
		return 0
	}

	type tierEntry struct {
		tier string
		path string
		info os.FileInfo
	}
	var allVersioned []tierEntry

	tiers := []struct {
		name string
		dir  string
	}{
		{"complete", filepath.Join("out", "complete")},
		{"partial", filepath.Join("out", "partial")},
	}

	for _, t := range tiers {
		entries, err := os.ReadDir(t.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(t.dir, e.Name())
			if isVersionedDir(p) {
				if info, err := e.Info(); err == nil {
					allVersioned = append(allVersioned, tierEntry{t.name, p, info})
				}
			}
		}
	}

	if len(allVersioned) == 0 {
		fmt.Println("No versioned output directories found. Run './janus-cli pull' to get started.")
		return 0
	}

	sort.Slice(allVersioned, func(i, j int) bool {
		return allVersioned[i].info.ModTime().After(allVersioned[j].info.ModTime())
	})

	latest := getLatestDir()
	completeCount := 0
	partialCount := 0
	for _, v := range allVersioned {
		if v.tier == "complete" {
			completeCount++
		} else {
			partialCount++
		}
	}

	abs, _ := filepath.Abs("out")
	fmt.Printf("Output directory: %s\n", abs)
	fmt.Printf("Versioned runs:   %d (%d complete, %d partial)\n\n", len(allVersioned), completeCount, partialCount)

	limit := 5
	if len(allVersioned) < limit {
		limit = len(allVersioned)
	}

	analyzerOutputs := map[string]string{
		"summary_visualization.json":     "summary-visualization",
		"command_failure_summary.json":   "command-failure-summary",
		"command_retry_success.json":     "command-retry-success",
		"command_duration.json":          "command-duration",
		"outlier_context_analysis.json":  "outlier-context",
		"callback_health.json":           "callback-health",
		"dwell_time.json":                "dwell-time",
		"parameter_entropy.json":         "parameter-entropy",
		"argument_position_profile.json": "argument-position-profile",
		"tool_dump.json":                 "tool-dump",
	}

	artifacts := []struct {
		file  string
		label string
	}{
		{"events.ndjson", "Events"},
	}
	for file, name := range analyzerOutputs {
		artifacts = append(artifacts, struct {
			file  string
			label string
		}{file, name})
	}
	artifacts = append(artifacts, struct {
		file  string
		label string
	}{"report.html", "HTML report"})

	for i := 0; i < limit; i++ {
		v := allVersioned[i]
		marker := ""
		if v.path == latest {
			marker = " (latest)"
		}
		mtime := v.info.ModTime().UTC()
		fmt.Printf("  [%s] %s%s\n", v.tier, filepath.Base(v.path), marker)
		fmt.Printf("    Created:  %s\n", mtime.Format("2006-01-02 15:04:05 UTC"))

		bundlePath := filepath.Join(v.path, "bundle.json")
		if data, err := os.ReadFile(bundlePath); err == nil {
			var bundle map[string]interface{}
			if json.Unmarshal(data, &bundle) == nil {
				opName, _ := bundle["operation_name"].(string)
				if opName == "" {
					opName = "unknown"
				}
				opID := "?"
				if id, ok := bundle["operation_id"]; ok {
					opID = fmt.Sprintf("%v", id)
				}
				taskCount := "?"
				if tc, ok := bundle["task_count"]; ok {
					taskCount = fmt.Sprintf("%v", tc)
				}
				ep, _ := bundle["mythic_endpoint"].(string)
				if ep == "" {
					ep, _ = bundle["ghostwriter_endpoint"].(string)
				}
				if ep == "" {
					ep, _ = bundle["cobaltstrike_rest_endpoint"].(string)
				}
				epSuffix := ""
				if ep != "" {
					epSuffix = " @ " + ep
				}
				fmt.Printf("    Operation: %s (ID %s)%s — %s tasks\n", opName, opID, epSuffix, taskCount)
			}
		}

		var present, missing []string
		for _, a := range artifacts {
			if _, err := os.Stat(filepath.Join(v.path, a.file)); err == nil {
				present = append(present, a.label)
			} else {
				missing = append(missing, a.label)
			}
		}
		if len(present) > 0 {
			fmt.Printf("    Present:   %s\n", strings.Join(present, ", "))
		}
		if len(missing) > 0 {
			fmt.Printf("    Missing:   %s\n", strings.Join(missing, ", "))
		}
		fmt.Println()
	}

	if len(allVersioned) > 5 {
		fmt.Printf("  ... and %d older run(s) across all tiers\n", len(allVersioned)-5)
	}

	return 0
}

func cmdConfig() int {
	cfgPath := configFile()
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		fmt.Printf("Config file not found: %s\n", cfgPath)
		fmt.Printf("Copy Config/janus.example.yml to %s and edit it.\n", cfgPath)
		return 1
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	source := resolveSource("", cfg)
	abs, _ := filepath.Abs(cfgPath)

	fmt.Printf("Config file:  %s\n", abs)
	fmt.Printf("Default pull source: %s\n", source)
	fmt.Printf("Mythic endpoint:     %s\n", orDefault(cfg.Mythic.Endpoint, "(not set)"))
	fmt.Printf("Mythic API token:    %s\n", maskToken(cfg.Mythic.APIToken))
	fmt.Printf("Mythic operation ID: %s\n", intOrNotSet(cfg.Mythic.OperationID))
	fmt.Printf("Mythic verify TLS:   %v\n", resolveBool(cfg.Mythic.VerifyTLS, true))
	fmt.Printf("Mythic response page size: %s\n", intOrDefault(cfg.Mythic.ResponsePageSize, "500"))
	fmt.Printf("Ghostwriter endpoint: %s\n", orDefault(cfg.Ghostwriter.Endpoint, "(not set)"))
	fmt.Printf("Ghostwriter API token: %s\n", maskToken(cfg.Ghostwriter.APIToken))
	fmt.Printf("Ghostwriter oplog ID:  %s\n", intOrNotSet(cfg.Ghostwriter.OplogID))
	fmt.Printf("Ghostwriter verify TLS: %v\n", resolveBool(cfg.Ghostwriter.VerifyTLS, true))
	csTok := cfg.CobaltStrike.APIToken
	if csTok == "" {
		csTok = cfg.CobaltStrike.RestAPIToken
	}
	fmt.Printf("Cobalt Strike REST endpoint: %s\n", orDefault(cfg.CobaltStrike.RestEndpoint, "(not set)"))
	fmt.Printf("Cobalt Strike REST token:   %s\n", maskToken(csTok))
	fmt.Printf("Cobalt Strike operation ID: %s\n", intOrNotSet(cfg.CobaltStrike.OperationID))
	fmt.Printf("Cobalt Strike verify TLS:   %v\n", resolveBool(cfg.CobaltStrike.VerifyTLS, true))
	fmt.Println("Cobalt Strike ingest source: janus-cli pull/run --source cobaltstrike")
	return 0
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func intOrNotSet(n int) string {
	if n == 0 {
		return "(not set)"
	}
	return fmt.Sprintf("%d", n)
}

func intOrDefault(n int, fallback string) string {
	if n == 0 {
		return fallback
	}
	return fmt.Sprintf("%d", n)
}
