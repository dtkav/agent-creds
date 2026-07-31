package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBwrapEnvoyPortDeterministicRange(t *testing.T) {
	for _, slug := range []string{"smoke", "default", "a", "some-long-instance-name"} {
		p1 := BwrapEnvoyPort(slug)
		p2 := BwrapEnvoyPort(slug)
		if p1 != p2 {
			t.Errorf("port for %q not deterministic: %d != %d", slug, p1, p2)
		}
		if p1 < 20000 || p1 >= 29000 {
			t.Errorf("port for %q out of range: %d", slug, p1)
		}
	}
	// Pin the value the smoke script (scripts/bwrap-net-smoke.sh) computes
	// with its python FNV-1a implementation for the default smoke-test slug.
	if got := BwrapEnvoyPort("smoke"); got != 20502 {
		t.Errorf("BwrapEnvoyPort(smoke) = %d, want 20502 (smoke script parity)", got)
	}
}

func TestBwrapAgentArgv(t *testing.T) {
	cases := []struct {
		agent      string
		entrypoint string
		want0      string
		wantFlag   string
	}{
		{"claude", "", "claude", "--dangerously-skip-permissions"},
		{"codex", "", "codex", "--dangerously-bypass-approvals-and-sandbox"},
		{"pi", "", "pi", ""},
		{"", "", "/bin/bash", "-l"},
		{"claude", "run-thing", "/bin/bash", "run-thing"},
	}
	for _, c := range cases {
		cfg := ProjectConfig{Entrypoint: c.entrypoint}
		cfg.Sandbox.Agent = c.agent
		argv := bwrapAgentArgv(cfg)
		if argv[0] != c.want0 {
			t.Errorf("agent %q: argv[0] = %q, want %q", c.agent, argv[0], c.want0)
		}
		if c.wantFlag != "" && !strings.Contains(strings.Join(argv, " "), c.wantFlag) {
			t.Errorf("agent %q: argv %v missing %q", c.agent, argv, c.wantFlag)
		}
	}
}

func TestBwrapAgentBindsAbsolutePath(t *testing.T) {
	binds, paths, err := bwrapAgentBinds([]string{"/bin/bash", "-l"})
	if err != nil || binds != nil || paths != nil {
		t.Errorf("absolute entrypoint should need no binds: %v %v %v", binds, paths, err)
	}
}

func TestBwrapAgentBindsHostCommand(t *testing.T) {
	binds, paths, err := bwrapAgentBinds([]string{"go"})
	if err != nil {
		t.Fatalf("resolving host command: %v", err)
	}
	if !slices.Contains(paths, filepath.Dir(mustLookPath(t, "go"))) {
		t.Fatalf("PATH entries = %v, want launcher directory containing go", paths)
	}
	real, err := filepath.EvalSymlinks(mustLookPath(t, "go"))
	if err != nil {
		t.Fatalf("resolving go: %v", err)
	}
	if !slices.Contains(paths, filepath.Dir(real)) {
		t.Fatalf("PATH entries = %v, want resolved binary directory", paths)
	}
	if len(binds) == 0 {
		t.Fatal("host command outside system directories needs a read-only bind")
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("looking up %s: %v", name, err)
	}
	return path
}

func TestBwrapFileMountArgsCreatesScratchParents(t *testing.T) {
	got := bwrapFileMountArgs(
		"/generated/bwrap-resolv.conf",
		"/run/systemd/resolve/stub-resolv.conf",
	)
	want := []string{
		"--dir", "/run/systemd",
		"--dir", "/run/systemd/resolve",
		"--ro-bind", "/generated/bwrap-resolv.conf", "/run/systemd/resolve/stub-resolv.conf",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("bwrapFileMountArgs() = %q, want %q", got, want)
	}
}

func TestBwrapFileMountArgsLeavesPersistentParentsAlone(t *testing.T) {
	got := bwrapFileMountArgs("/generated/file", "/etc/regular-file")
	want := []string{"--ro-bind", "/generated/file", "/etc/regular-file"}
	if !slices.Equal(got, want) {
		t.Fatalf("bwrapFileMountArgs() = %q, want %q", got, want)
	}
}

func TestBwrapGeneratedScriptsParse(t *testing.T) {
	dir := t.TempDir()
	setup := filepath.Join(dir, "bwrap-setup.sh")
	launch := filepath.Join(dir, "bwrap-launch.sh")
	args := []string{"--die-with-parent", "--setenv", "X", "a b 'c'", "--chdir", "/tmp"}
	argv := []string{"claude", "--permission-mode", "bypassPermissions"}
	if err := writeBwrapSetupScript(setup, "/opt/agent-creds", dir, 21281, args, argv); err != nil {
		t.Fatalf("writeBwrapSetupScript: %v", err)
	}
	if err := writeBwrapLaunchScript(launch, dir, setup); err != nil {
		t.Fatalf("writeBwrapLaunchScript: %v", err)
	}
	for _, script := range []string{setup, launch} {
		out, err := exec.Command("bash", "-n", script).CombinedOutput()
		if err != nil {
			data, _ := os.ReadFile(script)
			t.Errorf("bash -n %s failed: %v\n%s\n--- script:\n%s", script, err, out, data)
		}
	}
	data, _ := os.ReadFile(setup)
	for _, want := range []string{"PORT=21281", "tcp dport $PORT", "setpriv --ambient-caps=-all", "'a b '\\''c'\\'''"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("setup script missing %q", want)
		}
	}
}
