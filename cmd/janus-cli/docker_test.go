package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Use the test executable as a portable fake Docker process.
func TestDockerHelper(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--janus-docker-helper" {
		return
	}
	fmt.Fprint(os.Stdout, os.Args[len(os.Args)-2])
	if os.Args[len(os.Args)-1] == "fail" {
		os.Exit(1)
	}
	os.Exit(0)
}

type dockerReply struct {
	args, output string
	fail         bool
}

func fakeDocker(t *testing.T, replies []dockerReply) *int {
	t.Helper()
	original := dockerCommand
	calls := 0
	dockerCommand = func(name string, args ...string) *exec.Cmd {
		if name != "docker" {
			t.Fatalf("unexpected executable %q", name)
		}
		if calls >= len(replies) {
			t.Fatalf("unexpected Docker command: %v", args)
		}
		reply := replies[calls]
		calls++
		if strings.Join(args, " ") != reply.args && !(reply.args == "run" && len(args) > 0 && args[0] == "run") {
			t.Fatalf("command = %v, want %s", args, reply.args)
		}
		status := "ok"
		if reply.fail {
			status = "fail"
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestDockerHelper$", "--", "--janus-docker-helper", reply.output, status)
		return cmd
	}
	t.Cleanup(func() { dockerCommand = original })
	return &calls
}

func TestBuildImage(t *testing.T) {
	info := dockerReply{args: "info --format {{.ServerVersion}}"}
	buildx := dockerReply{args: "buildx version"}
	quiet := "build --network=host --progress=quiet -t janus:latest ."
	fallback := "build --network=host -q -t janus:latest ."
	cases := []struct {
		name    string
		replies []dockerReply
		want    string
	}{
		{"success", []dockerReply{info, buildx, {args: quiet}}, ""},
		{"permission", []dockerReply{{info.args, "permission denied while connecting to docker API at /var/run/docker.sock", true}}, "docker info works without sudo"},
		{"daemon", []dockerReply{{info.args, "Cannot connect to the Docker daemon", true}}, "daemon is not reachable"},
		{"missing buildx", []dockerReply{info, {buildx.args, "docker: 'buildx' is not a docker command", true}}, "Buildx is missing or broken"},
		{"broken buildx", []dockerReply{info, {buildx.args, "exec format error", true}}, "Buildx is missing or broken"},
		{"buildx fails during build", []dockerReply{info, buildx, {quiet, "BuildKit is enabled but the buildx component is missing or broken", true}}, "Buildx is missing or broken"},
		{"ordinary failure once", []dockerReply{info, buildx, {quiet, "Dockerfile: RUN failed: dependency unavailable", true}}, "dependency unavailable"},
		{"credential failure once", []dockerReply{info, buildx, {quiet, "error getting credentials", true}}, "credential"},
		{"unsupported progress", []dockerReply{info, buildx, {quiet, "unknown flag: --progress", true}, {args: fallback}}, ""},
		{"unsupported quiet value", []dockerReply{info, buildx, {quiet, "invalid progress mode quiet", true}, {fallback, "build failed after fallback", true}}, "build failed after fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeDocker(t, tc.replies)
			err := buildImage()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if *calls != len(tc.replies) {
				t.Fatalf("commands = %d, want %d", *calls, len(tc.replies))
			}
		})
	}
}

func TestMissingDocker(t *testing.T) {
	original := dockerCommand
	dockerCommand = func(_ string, _ ...string) *exec.Cmd { return exec.Command("janus-nonexistent-docker-executable") }
	t.Cleanup(func() { dockerCommand = original })
	err := ensureDockerAvailable()
	if err == nil || !strings.Contains(err.Error(), "docker CLI not found in PATH") {
		t.Fatalf("error = %v", err)
	}
}

func TestDockerRunDoesNotRequireBuildx(t *testing.T) {
	calls := fakeDocker(t, []dockerReply{{args: "info --format {{.ServerVersion}}"}, {args: "run"}})
	if err := dockerRun([]string{"report"}, false, "", ""); err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Fatalf("commands = %d", *calls)
	}
}
