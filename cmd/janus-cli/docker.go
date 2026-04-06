package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const imageName = "janus:latest"

const janusDockerRunExtraEnv = "JANUS_DOCKER_RUN_EXTRA"

// globalDockerNetwork and globalDockerAddHost are set from leading flags (janus-cli --docker-network host pull ...).
var globalDockerNetwork, globalDockerAddHost string

// parseLeadingGlobalFlags consumes optional global docker wrapper flags before the subcommand name.
func parseLeadingGlobalFlags(args []string) (rest []string) {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--docker-network" && i+1 < len(args):
			globalDockerNetwork = strings.TrimSpace(args[i+1])
			i += 2
		case strings.HasPrefix(a, "--docker-network="):
			globalDockerNetwork = strings.TrimSpace(strings.TrimPrefix(a, "--docker-network="))
			i++
		case a == "--docker-add-host" && i+1 < len(args):
			globalDockerAddHost = strings.TrimSpace(args[i+1])
			i += 2
		case strings.HasPrefix(a, "--docker-add-host="):
			globalDockerAddHost = strings.TrimSpace(strings.TrimPrefix(a, "--docker-add-host="))
			i++
		default:
			return args[i:]
		}
	}
	return args[i:]
}

// firstNonEmpty returns a if non-empty after trim, else b.
func firstNonEmpty(a, b string) string {
	a = strings.TrimSpace(a)
	if a != "" {
		return a
	}
	return strings.TrimSpace(b)
}

func stripNetworkFlags(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if t == "--network" && i+1 < len(tokens) {
			i++
			continue
		}
		if strings.HasPrefix(t, "--network=") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// buildDockerRunPrefixes returns docker CLI tokens to insert after `docker run --rm` (before -v).
// Precedence: cliNetwork / cliAddHost beat config beat raw env extras; config network_mode beats env --network.
func buildDockerRunPrefixes(cliNetwork, cliAddHost string, cfg *Config) []string {
	envTok := strings.Fields(os.Getenv(janusDockerRunExtraEnv))
	merged := append([]string(nil), envTok...)

	cfgNet := ""
	var cfgExtra []string
	if cfg != nil {
		cfgNet = strings.TrimSpace(cfg.Docker.NetworkMode)
		cfgExtra = cfg.Docker.RunExtra
	}

	useNet := firstNonEmpty(cliNetwork, cfgNet)
	if useNet != "" {
		merged = stripNetworkFlags(merged)
		merged = append([]string{"--network", useNet}, merged...)
	}

	if len(cfgExtra) > 0 {
		merged = append(merged, cfgExtra...)
	}

	if add := strings.TrimSpace(cliAddHost); add != "" {
		merged = append(merged, "--add-host", add)
	}
	return merged
}

func ensureDockerAvailable() error {
	cmd := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return wrapDockerConnectivityError(err, strings.TrimSpace(combined.String()))
	}
	return nil
}

func wrapDockerConnectivityError(err error, details string) error {
	lower := strings.ToLower(details)
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("docker CLI not found in PATH. Install Docker Desktop (or Docker Engine) and retry")
	}
	if strings.Contains(lower, "permission denied") &&
		(strings.Contains(lower, "docker.sock") ||
			strings.Contains(lower, "docker api") ||
			strings.Contains(lower, "docker daemon socket")) {
		return fmt.Errorf(
			"cannot access the Docker socket (permission denied). On Linux with Docker Engine: add your user to the docker group (sudo usermod -aG docker \"$USER\"), then log out and back in or run newgrp docker, and confirm docker info works without sudo. On macOS/Windows use Docker Desktop and ensure it is running. Avoid running janus-cli with sudo (it can leave root-owned files under out/). Details: %s",
			details,
		)
	}
	if strings.Contains(lower, "dockerdesktoplinuxengine") ||
		strings.Contains(lower, "cannot find the file specified") ||
		strings.Contains(lower, "is the docker daemon running") ||
		strings.Contains(lower, "cannot connect to the docker daemon") ||
		strings.Contains(lower, "connect: no such file or directory") {
		return fmt.Errorf(
			"docker daemon is not reachable. Start Docker Desktop/Engine and wait until `docker info` succeeds. Details: %s",
			details,
		)
	}
	if details != "" {
		return fmt.Errorf("docker preflight failed: %s", details)
	}
	return fmt.Errorf("docker preflight failed: %w", err)
}

// runWithProgressHint prints an animated status on stderr while fn runs (for long silent Docker steps).
func runWithProgressHint(msg string, fn func() error) error {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		dots := []string{"", ".", "..", "..."}
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				suffix := dots[i%len(dots)]
				// pad so previous longer line gets overwritten
				padLen := 4 - len(suffix)
				if padLen < 0 {
					padLen = 0
				}
				pad := strings.Repeat(" ", padLen)
				_, _ = fmt.Fprintf(os.Stderr, "\r%s%s%s", msg, suffix, pad)
				i++
			}
		}
	}()
	err := fn()
	close(stop)
	<-done
	clear := len(msg) + 8
	_, _ = fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", clear))
	return err
}

func buildImage() error {
	if err := ensureDockerAvailable(); err != nil {
		return err
	}
	err := runWithProgressHint("Docker: building image (quiet; please wait)", func() error {
		if err := runDockerBuildAttempt([]string{"build", "--network=host", "--progress=quiet", "-t", imageName, "."}); err == nil {
			return nil
		}
		// Fallback for Docker versions that do not support --progress=quiet.
		if err := runDockerBuildAttempt([]string{"build", "--network=host", "-q", "-t", imageName, "."}); err == nil {
			return nil
		}
		// Final fallback: run verbosely so users can see real build errors.
		verbose := exec.Command("docker", "build", "--network=host", "-t", imageName, ".")
		verbose.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
		verbose.Stdout = os.Stdout
		verbose.Stderr = os.Stderr
		_, _ = fmt.Fprintln(os.Stderr, "Docker: build failed in quiet mode; showing verbose logs...")
		return verbose.Run()
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Docker: image ready.")
	return nil
}

func runDockerBuildAttempt(args []string) error {
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")

	// Keep successful builds fully quiet so callers always get the same progress UX.
	var combined bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &combined

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(combined.String()))
	}
	return nil
}

func dockerMount(hostPath, containerPath string, readonly bool) []string {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		abs = hostPath
	}
	// Normalize to forward slashes for Docker Desktop on Windows
	abs = filepath.ToSlash(abs)

	mount := abs + ":" + containerPath
	if readonly {
		mount += ":ro"
	}
	return []string{"-v", mount}
}

func dockerRun(args []string, interactive bool, cliDockerNetwork, cliDockerAddHost string) error {
	if err := ensureDockerAvailable(); err != nil {
		return err
	}
	var cfg *Config
	if c, err := loadConfig(configFile()); err == nil {
		cfg = c
	}
	net := firstNonEmpty(cliDockerNetwork, globalDockerNetwork)
	host := firstNonEmpty(cliDockerAddHost, globalDockerAddHost)
	extras := buildDockerRunPrefixes(net, host, cfg)

	cmdArgs := []string{"run", "--rm"}
	if interactive {
		cmdArgs = append(cmdArgs, "-it")
	}
	cmdArgs = append(cmdArgs, extras...)

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	cmdArgs = append(cmdArgs, dockerMount(filepath.Join(cwd, "out"), "/data/out", false)...)
	cmdArgs = append(cmdArgs, dockerMount(filepath.Join(cwd, "Config"), "/config", true)...)
	cmdArgs = append(cmdArgs, imageName)
	cmdArgs = append(cmdArgs, args...)

	phase := "janus"
	if len(args) > 0 {
		phase = args[0]
	}
	fmt.Fprintf(os.Stderr, "Docker: starting container (%s) — output below\n", phase)

	cmd := exec.Command("docker", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
