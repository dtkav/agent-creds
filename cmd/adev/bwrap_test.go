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

func TestBwrapCDPProxyPortDeterministicRange(t *testing.T) {
	for _, slug := range []string{"relay-diffs", "default", "a"} {
		p1 := BwrapCDPProxyPort(slug)
		p2 := BwrapCDPProxyPort(slug)
		if p1 != p2 {
			t.Errorf("CDP port for %q not deterministic: %d != %d", slug, p1, p2)
		}
		if p1 < 29000 || p1 >= 38000 {
			t.Errorf("CDP port for %q out of range: %d", slug, p1)
		}
	}
}

func TestBwrapHostSocketsAreShortAndSeparated(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	slug := strings.Repeat("long-instance-name-", 20)
	apiSocket := bwrapSlirpAPISocket(slug)
	browserSocket := bwrapBrowserSocket(slug)
	for _, path := range []string{apiSocket, browserSocket} {
		if len(path) >= 108 {
			t.Fatalf("Unix socket path is %d bytes: %s", len(path), path)
		}
	}
	if filepath.Dir(apiSocket) == filepath.Dir(browserSocket) {
		t.Fatalf("control and bridge sockets share a mounted directory: %s", filepath.Dir(apiSocket))
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
	if err := writeBwrapSetupScript(setup, "/opt/agent-creds", dir, 21281, 31281, 50281, "/host-only/browser.sock", args, argv); err != nil {
		t.Fatalf("writeBwrapSetupScript: %v", err)
	}
	if err := writeBwrapLaunchScript(launch, dir, setup, "/host-only/slirp-api.sock"); err != nil {
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
	launchData, _ := os.ReadFile(launch)
	data = append(data, launchData...)
	for _, want := range []string{
		"PORT=21281",
		"CDP_PROXY_PORT=31281",
		"BROWSER_FORWARD_PORT=50281",
		"BROWSER_FORWARD_SOCKET='/host-only/browser.sock'",
		"tcp dport $PORT",
		"ct state established,related accept",
		`tcp dport "$CDP_PROXY_PORT"`,
		`tcp dport "$BROWSER_FORWARD_PORT"`,
		"CDP_LISTEN_ADDR=127.0.0.1:9222",
		"CDP_TRUST_FILTERED_UPSTREAM=1",
		"TCP_BROWSER_PORT=\"$BROWSER_FORWARD_PORT\"",
		"TCP_BRIDGE_HOST=10.0.2.2",
		"CALLBACK_LISTEN_HOST=10.0.2.100",
		"BROWSER_SOCKET_PATH=\"$BROWSER_FORWARD_SOCKET\"",
		"SLIRP_API='/host-only/slirp-api.sock'",
		"--api-socket=\"$SLIRP_API\"",
		"setpriv --ambient-caps=-all",
		"'a b '\\''c'\\'''",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("setup script missing %q", want)
		}
	}
}

func TestSandboxEnvClosureMountsUsesPrivateNixStore(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	envPath := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sandbox-env"
	depPath := "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-gh"
	for _, path := range []string{envPath, depPath} {
		if err := os.MkdirAll(
			filepath.Join(configHome, "agent-creds", "nix", "store", filepath.Base(path)),
			0755,
		); err != nil {
			t.Fatal(err)
		}
	}
	closure := sandboxEnvClosureFile(envPath)
	if err := os.MkdirAll(filepath.Dir(closure), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(closure, []byte(depPath+"\n"+envPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mounts, err := sandboxEnvClosureMounts(envPath)
	if err != nil {
		t.Fatalf("sandboxEnvClosureMounts: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("mounts = %v, want two closure paths", mounts)
	}
	for _, mount := range mounts {
		if !strings.HasPrefix(mount.Source, filepath.Join(configHome, "agent-creds", "nix", "store")) {
			t.Errorf("source %q is outside the private Nix store", mount.Source)
		}
		if filepath.Dir(mount.Target) != "/nix/store" {
			t.Errorf("target %q is not canonical", mount.Target)
		}
	}
}

func TestBwrapArgsEnterSandboxEnvWithoutMountingWholeNixStore(t *testing.T) {
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	scriptDir := filepath.Join(root, "agent-creds")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}
	envPath := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sandbox-env"
	mount := NixStoreMount{
		Source: filepath.Join(root, "store", filepath.Base(envPath)),
		Target: envPath,
	}
	if err := os.MkdirAll(mount.Source, 0755); err != nil {
		t.Fatal(err)
	}

	args, err := buildBwrapArgs(
		workDir, scriptDir, "test", ProjectConfig{}, envPath,
		[]NixStoreMount{mount}, 0, "", nil, nil,
	)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--ro-bind\x00" + mount.Source + "\x00" + mount.Target,
		"--setenv\x00SANDBOX_ENV\x00" + envPath,
		envPath + "/bin",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("bwrap args missing %q", want)
		}
	}
	if strings.Contains(joined, "--ro-bind\x00/nix\x00/nix") {
		t.Error("bwrap args expose the whole host Nix store")
	}
}

func TestBwrapArgsRequireSandboxEnvClosure(t *testing.T) {
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := buildBwrapArgs(
		workDir, filepath.Join(root, "agent-creds"), "test",
		ProjectConfig{}, "", nil, 0, "", nil, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "sandbox environment is required") {
		t.Fatalf("buildBwrapArgs error = %v, want missing sandbox environment", err)
	}

	_, err = buildBwrapArgs(
		workDir, filepath.Join(root, "agent-creds"), "test",
		ProjectConfig{}, "/nix/store/test-sandbox-env", nil, 0, "", nil, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "closure is empty") {
		t.Fatalf("buildBwrapArgs error = %v, want empty closure", err)
	}
}
