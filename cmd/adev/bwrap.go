package main

// bwrap runtime backend for `adev console`.
//
// A third value on the runtime axis ([sandbox] runtime = "bwrap"): adev owns
// a bubblewrap invocation that confines the WHOLE agent process, so claude,
// codex, and pi run inside it unmodified. envoy + vault remain the credential
// and egress plane, exactly as in the container backends.
//
// Topology (all unprivileged, no docker for the sandbox itself):
//
//   zmx session "adev-<slug>"                      (attach/detach layer)
//     └─ systemd-run --user --scope               (cgroup memory/cpu limits)
//         └─ bwrap-launch.sh                      (host mount ns)
//             ├─ slirp4netns                      (usermode tap, attached via
//             │                                    --userns-path/--netns-type=path)
//             └─ unshare --map-current-user --net --keep-caps bwrap-setup.sh
//                 │   configures tap0 with ONLY a 10.0.2.2/32 host route
//                 │   (no default route -> no direct internet), installs an
//                 │   nft output filter (envoy port only), starts the
//                 │   dns-responder on :53 inside the netns, then drops all
//                 │   capabilities and
//                 └─ exec bwrap (mount sandbox, --unshare-pid, no
//                     --unshare-net: it inherits the confined netns)
//                     └─ agent (claude / codex / pi), prompting disabled
//
// The agent sits in bwrap's nested user namespace which does NOT own the
// network namespace, so even a compromised agent cannot re-add a default
// route or alter the nft filter: the only reachable destination is the
// instance's envoy CONNECT listener, published by docker on
// 127.0.0.1:<per-slug port> and reached from inside as 10.0.2.2:<port>.
// Egress is envoy or nothing, the same invariant as the containers.

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

// BwrapEnvoyPort returns the deterministic host-loopback port on which the
// instance's envoy CONNECT listener (container port 10000) is published.
// Port: 20000 + (fnv32a(slug) % 9000).
func BwrapEnvoyPort(slug string) int {
	h := fnv.New32a()
	h.Write([]byte(slug))
	return 20000 + int(h.Sum32()%9000)
}

// bwrapSessionName returns the zmx session name for an instance.
func bwrapSessionName(slug string) string {
	return "adev-" + slug
}

// bwrapScopeUnit returns the systemd user scope unit for an instance.
func bwrapScopeUnit(slug string) string {
	return "adev-sandbox-" + slug + ".scope"
}

// listBwrapSlugs returns the slugs of live bwrap instances (zmx sessions
// named adev-<slug>).
func listBwrapSlugs() []string {
	out, err := exec.Command("zmx", "list", "--short").Output()
	if err != nil {
		return nil
	}
	var slugs []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, "adev-") {
			slugs = append(slugs, strings.TrimPrefix(name, "adev-"))
		}
	}
	return slugs
}

// bwrapSessionExists reports whether a zmx session for the slug is live.
func bwrapSessionExists(slug string) bool {
	for _, s := range listBwrapSlugs() {
		if s == slug {
			return true
		}
	}
	return false
}

// mergeBwrapInstances folds live bwrap sessions into a docker-derived
// instance list. A bwrap instance's envoy container makes it appear as
// "partial" to the docker scan; a live zmx session upgrades it to running.
// Returns the merged list and the set of bwrap slugs.
func mergeBwrapInstances(instances []Instance) ([]Instance, map[string]bool) {
	bwrapSlugs := make(map[string]bool)
	for _, slug := range listBwrapSlugs() {
		bwrapSlugs[slug] = true
		found := false
		for i := range instances {
			if instances[i].Slug == slug {
				instances[i].Status = "running"
				found = true
				break
			}
		}
		if !found {
			instances = append(instances, Instance{Name: slug, Slug: slug, Status: "running"})
		}
	}
	return instances, bwrapSlugs
}

// attachBwrapInstance attaches the current terminal to a live instance session.
func attachBwrapInstance(slug string) error {
	cmd := exec.Command("zmx", "attach", bwrapSessionName(slug))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// stopBwrapInstance tears down the zmx session, slirp4netns helper, and
// systemd scope for an instance. Returns true if any of them existed.
// The envoy container and docker network are cleaned up by the caller via
// InstanceManager.CleanupInstance (shared with the container runtimes).
func stopBwrapInstance(scriptDir, slug string) bool {
	found := false
	if bwrapSessionExists(slug) {
		found = true
		runQuiet("zmx", "kill", bwrapSessionName(slug), "--force")
	}
	// slirp4netns usually exits with the netns; kill leftovers by pid file.
	instanceGenDir := filepath.Join(scriptDir, "generated", "instances", slug)
	pidFile := filepath.Join(instanceGenDir, "slirp.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
			if proc, err := os.FindProcess(pid); err == nil {
				proc.Signal(syscall.SIGTERM)
			}
		}
		os.Remove(pidFile)
		found = true
	}
	// Release the scope (no-op when systemd was unavailable at launch).
	runQuiet("systemctl", "--user", "stop", bwrapScopeUnit(slug))
	runQuiet("systemctl", "--user", "reset-failed", bwrapScopeUnit(slug))
	return found
}

// bwrapPreflight verifies the host tools the backend depends on.
func bwrapPreflight() error {
	required := []string{"bwrap", "slirp4netns", "unshare", "setpriv", "zmx", "docker"}
	var missing []string
	for _, tool := range required {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("bwrap runtime requires %s on the host PATH", strings.Join(missing, ", "))
	}
	return nil
}

// systemdScopeAvailable reports whether a systemd user scope can be created.
func systemdScopeAvailable() bool {
	return runQuiet("systemd-run", "--user", "--scope", "-q", "--collect", "true") == nil
}

// systemdScopeArgs converts the toml memory/cpus limits into a systemd-run
// prefix, or nil when no scope can be created.
func systemdScopeArgs(slug string, cfg ProjectConfig) []string {
	if !systemdScopeAvailable() {
		fmt.Fprintln(os.Stderr, "Warning: systemd user scope unavailable; running without memory/cpu limits")
		return nil
	}
	// Clear any stale scope from a previous session.
	runQuiet("systemctl", "--user", "stop", bwrapScopeUnit(slug))
	runQuiet("systemctl", "--user", "reset-failed", bwrapScopeUnit(slug))
	args := []string{"systemd-run", "--user", "--scope", "-q", "--collect",
		"--unit", strings.TrimSuffix(bwrapScopeUnit(slug), ".scope"),
		"-p", "TasksMax=512"}
	if cfg.Sandbox.Memory != "" {
		args = append(args, "-p", "MemoryMax="+strings.ToUpper(cfg.Sandbox.Memory))
	}
	if cfg.Sandbox.CPUs != "" {
		if f, err := strconv.ParseFloat(cfg.Sandbox.CPUs, 64); err == nil && f > 0 {
			args = append(args, "-p", fmt.Sprintf("CPUQuota=%d%%", int(f*100)))
		}
	}
	return args
}

// shq single-quotes a string for safe embedding in a generated shell script.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// bwrapAgentArgv returns the in-sandbox command for the configured agent.
// The outer boundary (netns + mount sandbox) replaces the agent's own
// prompting, so each agent runs with its permission system disabled —
// same trust posture as the container backends.
func bwrapAgentArgv(cfg ProjectConfig) []string {
	if cfg.Entrypoint != "" {
		return []string{"/bin/bash", "-lc", cfg.Entrypoint}
	}
	switch cfg.Sandbox.Agent {
	case "claude":
		return []string{"claude", "--permission-mode", "bypassPermissions", "--dangerously-skip-permissions"}
	case "codex":
		return []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}
	case "pi":
		return []string{"pi"}
	case "":
		// No agent configured: confined interactive shell.
		return []string{"/bin/bash", "-l"}
	default:
		return []string{cfg.Sandbox.Agent}
	}
}

// bwrapAgentBinds resolves the agent entrypoint on the HOST (the bwrap
// backend runs host binaries, not a container image) and returns extra
// ro-bind bwrap args plus PATH entries that make it callable inside.
func bwrapAgentBinds(argv []string) (bindArgs []string, pathDirs []string, err error) {
	entry := argv[0]
	if strings.HasPrefix(entry, "/") {
		return nil, nil, nil // absolute path (e.g. /bin/bash): already bound
	}
	lp, err := exec.LookPath(entry)
	if err != nil {
		return nil, nil, fmt.Errorf("agent %q not found on host PATH (bwrap runtime runs host binaries): %w", entry, err)
	}
	real, err := filepath.EvalSymlinks(lp)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving %s: %w", lp, err)
	}
	seen := make(map[string]bool)
	addBind := func(dir string) {
		if dir == "" || seen[dir] || strings.HasPrefix(dir, "/usr/") || strings.HasPrefix(dir, "/bin/") {
			return
		}
		seen[dir] = true
		bindArgs = append(bindArgs, "--ro-bind", dir, dir)
	}
	// Directory holding the PATH entry (often a symlink farm like ~/.local/bin).
	lpDir := filepath.Dir(lp)
	addBind(lpDir)
	pathDirs = append(pathDirs, lpDir)
	// Also put the resolved binary directory on PATH. Some launchers are
	// symlinks into state below the agent config directory (Codex standalone
	// uses ~/.local/bin/codex -> ~/.codex/.../current/bin/codex). The sandbox
	// mounts its own ~/.codex, so that alias may not exist even though the
	// resolved release is mounted below. Calling the mounted binary directly
	// keeps the launcher independent of config-directory symlinks.
	realDir := filepath.Dir(real)
	if realDir != lpDir {
		pathDirs = append(pathDirs, realDir)
	}
	// Install root of the resolved binary. For node-based agents climb to the
	// prefix that holds both bin/ and lib/node_modules; for bin/ layouts take
	// the parent so sibling dirs come along.
	root := filepath.Dir(real)
	for p := root; p != "/" && p != "."; p = filepath.Dir(p) {
		if filepath.Base(p) == "node_modules" {
			root = filepath.Dir(filepath.Dir(p)) // lib/node_modules -> prefix
			break
		}
	}
	if filepath.Base(root) == "bin" {
		root = filepath.Dir(root)
	}
	addBind(root)
	return bindArgs, pathDirs, nil
}

// runBwrapConsole is the entry point for [sandbox] runtime = "bwrap":
// attach to the instance's live zmx session, or create the instance.
func runBwrapConsole(workDir, scriptDir, slug string, cfg ProjectConfig) {
	if err := bwrapPreflight(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if bwrapSessionExists(slug) {
		fmt.Printf("Attaching to '%s' (bwrap)...\n", slug)
		if err := attachBwrapInstance(slug); err != nil {
			fmt.Fprintf(os.Stderr, "Error attaching: %v\n", err)
			os.Exit(1)
		}
		return
	}
	createBwrapInstance(workDir, scriptDir, slug, cfg, true)
}

// runBwrapStart starts an instance without attaching the current terminal.
func runBwrapStart(workDir, scriptDir, slug string, cfg ProjectConfig) {
	if err := bwrapPreflight(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if bwrapSessionExists(slug) {
		fmt.Printf("Already running: '%s' (bwrap)\n", slug)
		return
	}
	createBwrapInstance(workDir, scriptDir, slug, cfg, false)
}

// createBwrapInstance prepares configs, tokens, and the per-instance envoy
// container, generates the launch scripts, and starts the zmx-hosted bwrap
// session. When attach is true, the current terminal follows the session.
func createBwrapInstance(workDir, scriptDir, slug string, cfg ProjectConfig, attach bool) {
	envoyName := "adev-" + slug + "-envoy"
	networkName := "adev-" + slug
	sessionName := bwrapSessionName(slug)
	instanceGenDir := filepath.Join(scriptDir, "generated", "instances", slug)
	instanceLogsDir := filepath.Join(instanceGenDir, "logs")
	instanceHomeDir := filepath.Join(instanceGenDir, "home")
	for _, dir := range []string{instanceLogsDir, instanceHomeDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating instance directory: %v\n", err)
			os.Exit(1)
		}
	}

	if err := os.Chdir(scriptDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error changing to %s: %v\n", scriptDir, err)
		os.Exit(1)
	}

	spinner := NewSpinner()
	spinner.Status("starting (bwrap)")
	spinner.Start()

	cleanup := func() {
		run("docker", "rm", "-f", envoyName)
		run("docker", "network", "rm", networkName)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		spinner.Stop()
		cleanup()
		os.Exit(1)
	}()

	spinner.Status("building sandbox environment")
	sandboxEnv, err := ensureSandboxEnv(cfg, scriptDir, spinner)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error preparing sandbox environment: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	nixMounts, err := sandboxEnvClosureMounts(sandboxEnv)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error preparing sandbox environment: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	// Generate configs (CA, envoy.json, domains.json, merged config) —
	// identical Generate() path to the container runtimes.
	spinner.Status("generating configs...")
	gen, err := NewGenerator(scriptDir, instanceGenDir, cfg)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if err := gen.Generate(); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error generating configs: %v\n", err)
		os.Exit(1)
	}
	vaultConfigYAML, vaultConfigErr := decryptVaultConfigYAML()
	legacyEnvLoaded := exportLegacyVaultEnv()
	if !cfg.Vault.IsRemote() {
		if vaultConfigErr != nil && !legacyEnvLoaded {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error preparing vault config: %v\n", vaultConfigErr)
			os.Exit(1)
		}
		if err := validateVaultStartupConfig(vaultConfigYAML); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error preparing vault config: %v\n", err)
			os.Exit(1)
		}
		setVaultComposeSecret(vaultConfigYAML)
	}

	// Ensure vault is running (local only)
	if !cfg.Vault.IsRemote() {
		out, _ := runOutput("docker", "compose", "ps", "--status", "running")
		if len(out) == 0 || !contains(string(out), "vault") {
			spinner.Status("starting vault...")
			if err := runWithOutput("docker", "compose", "up", "-d", "--build", "--quiet-pull"); err != nil {
				spinner.Stop()
				fmt.Fprintf(os.Stderr, "Error starting vault: %v\n", err)
				os.Exit(1)
			}
			if err := waitForVaultRunning(); err != nil {
				spinner.Stop()
				fmt.Fprintf(os.Stderr, "Error starting vault: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Mint tokens for credentialed upstreams and shape them into env vars.
	tokenEntries, _ := mintTokens(cfg, instanceGenDir, spinner)
	if want := expectedMintedTokens(cfg); len(tokenEntries) != want {
		spinner.Stop()
		fmt.Fprintf(os.Stderr,
			"Error minting sandbox credentials: minted %d of %d configured tokens\n",
			len(tokenEntries), want)
		cleanup()
		os.Exit(1)
	}
	infos := make(map[string]*CredentialInfo)
	for _, e := range tokenEntries {
		if info, err := vaultSSHInfo(cfg.Vault, cfg.Upstream[e.Host].Credential); err == nil {
			infos[e.Host] = info
		}
	}
	shaped := shapeTokens(tokenEntries, infos)
	staticResolved, err := resolveStaticEnvForConsole(cfg.StaticEnv, vaultConfigYAML, scriptDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: resolving static env: %v\n", err)
		staticResolved = make(map[string]string)
	}
	// sandbox.env is sourced by the setup script at every session start, so
	// discharge refresh and hot reload keep working across restarts.
	if err := generateSandboxEnv(instanceGenDir, shaped, staticResolved); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: generating sandbox.env: %v\n", err)
	}

	// Build dns-responder if needed (runs INSIDE the instance netns on :53).
	dnsResponderBin := filepath.Join(scriptDir, "generated", "dns-responder")
	dnsResponderSrc := filepath.Join(scriptDir, "cmd", "dns-responder", "main.go")
	if !fileExists(dnsResponderBin) || fileNewer(dnsResponderSrc, dnsResponderBin) {
		spinner.Status("building dns-responder...")
		cmd := exec.Command("go", "build", "-o", "../../generated/dns-responder", ".")
		cmd.Dir = filepath.Join(scriptDir, "cmd", "dns-responder")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Per-instance envoy container with the CONNECT listener published on
	// host loopback. Inside the sandbox this is 10.0.2.2:<port> — the ONLY
	// reachable destination.
	envoyPort := BwrapEnvoyPort(slug)
	os.WriteFile(filepath.Join(instanceGenDir, "envoy-port"), []byte(fmt.Sprintf("%d\n", envoyPort)), 0600)

	spinner.Status("starting envoy...")
	run("docker", "rm", "-f", envoyName)        // stale instance
	run("docker", "network", "rm", networkName) // may not exist
	if err := run("docker", "network", "create", "--ipv6", networkName); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error creating network %s: %v\n", networkName, err)
		os.Exit(1)
	}
	envoyArgs := []string{"run", "-d",
		"--name", envoyName,
		"--restart", "unless-stopped",
		"--network", networkName,
		"--network-alias", "envoy",
		"--ulimit", "nofile=65536:65536",
		"-p", fmt.Sprintf("127.0.0.1:%d:10000", envoyPort),
		"-v", scriptDir + "/generated/certs/ca.crt:/certs/ca.crt:ro",
		"-v", scriptDir + "/generated/certs/ca.key:/certs/ca.key:ro",
		"-v", filepath.Join(instanceGenDir, "domains.json") + ":/etc/envoy/domains.json:ro",
		"-v", filepath.Join(instanceGenDir, "envoy.json") + ":/etc/envoy/envoy.json:ro",
		"-v", scriptDir + "/envoy-entrypoint.sh:/entrypoint.sh:ro",
		"-v", scriptDir + "/generated/dns-responder:/usr/local/bin/dns-responder:ro",
		"-v", instanceLogsDir + ":/var/log/adev",
	}
	envoyArgs = append(envoyArgs,
		"--entrypoint", "/entrypoint.sh",
		"envoyproxy/envoy:v1.28-latest",
		"-c", "/etc/envoy/envoy.json")
	if err := run("docker", envoyArgs...); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error starting envoy: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	if !cfg.Vault.IsRemote() {
		if err := run("docker", "network", "connect", "agent-creds_agent-creds", envoyName); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error connecting envoy to vault network: %v\n", err)
			cleanup()
			os.Exit(1)
		}
	}
	// Envoy-only attachment to upstream networks (sandbox can never reach them).
	extraNetworks := make(map[string]struct{})
	for _, upstream := range cfg.Upstream {
		if upstream.Network != "" && upstream.Network != networkName {
			extraNetworks[upstream.Network] = struct{}{}
		}
	}
	for network := range extraNetworks {
		if err := run("docker", "network", "connect", network, envoyName); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error connecting envoy to upstream network %s: %v\n", network, err)
			cleanup()
			os.Exit(1)
		}
	}
	// Generated files consumed by the sandbox.
	spinner.Status("generating sandbox...")
	resolvConf := filepath.Join(instanceGenDir, "bwrap-resolv.conf")
	os.WriteFile(resolvConf, []byte("nameserver 127.0.0.1\n"), 0644)
	caBundle := filepath.Join(instanceGenDir, "bwrap-ca-bundle.crt")
	if err := writeBwrapCABundle(scriptDir, caBundle); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error writing CA bundle: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	agentArgv := bwrapAgentArgv(cfg)
	agentBinds, agentPathDirs, err := bwrapAgentBinds(agentArgv)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	// Agent profiles normally supply their entrypoint as a shell command, so
	// agentArgv starts with /bin/bash even though that command later invokes
	// codex/claude/pi. Resolve and mount the configured agent binary as well;
	// otherwise the bwrap PATH contains only system directories and the shell
	// entrypoint fails with "<agent>: command not found".
	if cfg.Sandbox.Agent != "" && agentArgv[0] != cfg.Sandbox.Agent {
		profileBinds, profilePathDirs, bindErr := bwrapAgentBinds(
			[]string{cfg.Sandbox.Agent},
		)
		if bindErr != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error: %v\n", bindErr)
			cleanup()
			os.Exit(1)
		}
		agentBinds = append(agentBinds, profileBinds...)
		agentPathDirs = append(agentPathDirs, profilePathDirs...)
	}

	bwrapArgs, err := buildBwrapArgs(
		workDir, scriptDir, slug, cfg, sandboxEnv, nixMounts,
		agentBinds, agentPathDirs,
	)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	setupScript := filepath.Join(instanceGenDir, "bwrap-setup.sh")
	if err := writeBwrapSetupScript(setupScript, scriptDir, instanceGenDir, envoyPort, bwrapArgs, agentArgv); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error writing setup script: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	launchScript := filepath.Join(instanceGenDir, "bwrap-launch.sh")
	if err := writeBwrapLaunchScript(launchScript, instanceGenDir, setupScript); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error writing launch script: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	// Hot reload: watch the project toml, regenerate envoy config live, and
	// re-mint changed tokens. Filesystem/netns policy applies on next start.
	stopWatcher := startBwrapConfigWatcher(workDir, scriptDir, instanceGenDir, envoyName, cfg)
	defer stopWatcher()

	spinner.Stop()
	signal.Stop(sigChan)

	// Discharge refresh + denial monitoring while attached (parity with the
	// container path; sandbox.env is re-read at every session start).
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	defer refreshCancel()
	if len(tokenEntries) > 0 {
		startDischargeRefresh(refreshCtx, cfg, scriptDir, instanceGenDir, vaultConfigYAML)
	}
	startDenialMonitor(refreshCtx, cfg.Vault)

	// Session command: scope-wrapped launcher, hosted by zmx.
	sessionCmd := append(systemdScopeArgs(slug, cfg), "/bin/bash", launchScript)
	if !attach {
		start := exec.Command(
			"zmx", append([]string{"run", sessionName, "-d"}, sessionCmd...)...)
		start.Stdout = os.Stdout
		start.Stderr = os.Stderr
		if err := start.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting zmx session: %v\n", err)
			cleanup()
			os.Exit(1)
		}
		fmt.Printf("Started '%s' (bwrap, envoy 127.0.0.1:%d).\n", slug, envoyPort)
		return
	}
	fmt.Printf("Starting '%s' (bwrap, envoy 127.0.0.1:%d, ctrl+\\ detaches)...\n", slug, envoyPort)
	attached := exec.Command("zmx", append([]string{"attach", sessionName}, sessionCmd...)...)
	attached.Stdin = os.Stdin
	attached.Stdout = os.Stdout
	attached.Stderr = os.Stderr
	attached.Run()
	// No cleanup: the session keeps running detached; use 'adev stop'.
}

// writeBwrapCABundle concatenates the host CA bundle with the agent-creds
// proxy CA so every tool inside the sandbox trusts the TLS bump.
func writeBwrapCABundle(scriptDir, dest string) error {
	var buf []byte
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", filepath.Join(scriptDir, "generated", "certs", "ca.crt")} {
		data, err := os.ReadFile(p)
		if err != nil {
			if p == "/etc/ssl/certs/ca-certificates.crt" {
				continue // no system bundle: proxy CA alone still covers envoy egress
			}
			return err
		}
		buf = append(buf, data...)
		if len(buf) > 0 && buf[len(buf)-1] != '\n' {
			buf = append(buf, '\n')
		}
	}
	return os.WriteFile(dest, buf, 0644)
}

// bwrapMountParentArgs returns the arguments needed to recreate a bind
// target's parent below a scratch root. The sandbox replaces /home, /run,
// /var, and /tmp, so an arbitrary project or plugin mount cannot assume its
// host-side parent hierarchy exists inside the mount namespace.
func bwrapMountParentArgs(target string) []string {
	target = filepath.Clean(target)
	var args []string
	for _, root := range []string{"/run", "/var", "/tmp", "/home"} {
		if !strings.HasPrefix(target, root+"/") {
			continue
		}
		parent := filepath.Dir(target)
		if parent == root {
			break
		}
		relative, err := filepath.Rel(root, parent)
		if err != nil {
			break
		}
		current := root
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			args = append(args, "--dir", current)
		}
		break
	}
	return args
}

// bwrapFileMountArgs returns the arguments needed to bind a file at target.
func bwrapFileMountArgs(source, target string) []string {
	return append(bwrapMountParentArgs(target), "--ro-bind", source, target)
}

// bwrapDirMountArgs returns the arguments needed to bind a directory at an
// arbitrary target inside one of the sandbox's scratch roots.
func bwrapDirMountArgs(source, target string, readonly bool) []string {
	bind := "--bind"
	if readonly {
		bind = "--ro-bind"
	}
	return append(bwrapMountParentArgs(target), bind, source, target)
}

// bwrapResolvMountArgs follows the host's /etc/resolv.conf symlink before
// /run is replaced with an empty tmpfs. Binding at the resolved location
// preserves the symlink from the read-only /etc tree.
func bwrapResolvMountArgs(source string) []string {
	target := "/etc/resolv.conf"
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	return bwrapFileMountArgs(source, target)
}

// buildBwrapArgs assembles the bwrap argument list (pre shell-quoting).
// Filesystem policy: project rw at its real path, toolchain ro, instance
// gen dir ro, instance-scoped home, tmpfs elsewhere.
func buildBwrapArgs(
	workDir, scriptDir, slug string,
	cfg ProjectConfig,
	sandboxEnv string,
	nixMounts []NixStoreMount,
	agentBinds, agentPathDirs []string,
) ([]string, error) {
	if sandboxEnv == "" {
		return nil, fmt.Errorf("sandbox environment is required for bwrap")
	}
	if len(nixMounts) == 0 {
		return nil, fmt.Errorf("sandbox environment closure is empty: %s", sandboxEnv)
	}

	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("resolving current user: %w", err)
	}
	homeDir := usr.HomeDir
	if homeDir == "" {
		homeDir = "/home/" + usr.Username
	}
	instanceGenDir := filepath.Join(scriptDir, "generated", "instances", slug)
	envoyPort := BwrapEnvoyPort(slug)

	args := []string{
		"--die-with-parent",
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
		"--hostname", "adev-" + slug,
		"--proc", "/proc",
		"--dev", "/dev",
		"--ro-bind", "/usr", "/usr",
	}
	// Replicate the host's merged-usr layout.
	for _, link := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		if target, err := os.Readlink("/" + link); err == nil {
			args = append(args, "--symlink", target, "/"+link)
		} else if fileExists("/" + link) {
			args = append(args, "--ro-bind", "/"+link, "/"+link)
		}
	}
	args = append(args, "--ro-bind", "/etc", "/etc")
	args = append(args, "--dir", "/nix", "--dir", "/nix/store")
	for _, mount := range nixMounts {
		args = append(args, "--ro-bind", mount.Source, mount.Target)
	}
	if fileExists("/opt") {
		args = append(args, "--ro-bind", "/opt", "/opt")
	}
	args = append(args,
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--tmpfs", "/var",
		"--dir", "/var/tmp",
		"--tmpfs", "/home",
		// Instance-scoped home (persists across session restarts).
		"--bind", filepath.Join(instanceGenDir, "home"), homeDir,
	)

	// Agent config dirs: same persisted dirs the container runtimes mount,
	// so login state carries across runtimes and instances.
	claudeConfigDir := filepath.Join(scriptDir, "claude-dev", "claude-config")
	os.MkdirAll(claudeConfigDir, 0755)
	claudeJSON := filepath.Join(claudeConfigDir, ".claude.json")
	if _, err := os.Stat(claudeJSON); os.IsNotExist(err) {
		os.WriteFile(claudeJSON, []byte("{}"), 0600)
	}
	codexConfigDir := filepath.Join(scriptDir, "claude-dev", "codex-config")
	os.MkdirAll(codexConfigDir, 0755)
	piConfigDir := filepath.Join(scriptDir, "claude-dev", "pi-config")
	os.MkdirAll(piConfigDir, 0755)
	args = append(args,
		"--bind", claudeConfigDir, filepath.Join(homeDir, ".claude"),
		"--bind", claudeJSON, filepath.Join(homeDir, ".claude.json"),
		"--bind", codexConfigDir, filepath.Join(homeDir, ".codex"),
		"--bind", piConfigDir, filepath.Join(homeDir, ".pi"),
	)
	if gitConfig := filepath.Join(homeDir, ".gitconfig"); fileExists(gitConfig) {
		args = append(args, "--ro-bind", gitConfig, filepath.Join(homeDir, ".gitconfig"))
	}

	// Project rw at its real path; instance gen dir ro (CA, tokens, configs).
	args = append(args, bwrapDirMountArgs(workDir, workDir, false)...)
	args = append(args, "--ro-bind", instanceGenDir, "/run/adev-instance")
	args = append(args, bwrapResolvMountArgs(filepath.Join(instanceGenDir, "bwrap-resolv.conf"))...)

	// Host binds for the agent installation (resolved from host PATH).
	args = append(args, agentBinds...)

	// Plugin mounts.
	for _, mount := range cfg.Mounts {
		if !fileExists(mount.Source) {
			fmt.Fprintf(os.Stderr, "Warning: mount source %s does not exist, skipping\n", mount.Source)
			continue
		}
		args = append(args, bwrapDirMountArgs(
			mount.Source, mount.Target, mount.Readonly,
		)...)
	}

	// Environment: cleared, then rebuilt. --clearenv also scrubs the
	// nested-claude vars (CLAUDECODE, CLAUDE_CODE_*, CLAUDE_PID, ...).
	pathEntries := append([]string{}, agentPathDirs...)
	pathEntries = append(pathEntries, filepath.Join(sandboxEnv, "bin"))
	pathEntries = append(pathEntries,
		"/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
	proxyURL := fmt.Sprintf("http://10.0.2.2:%d", envoyPort)
	caBundle := "/run/adev-instance/bwrap-ca-bundle.crt"
	env := [][2]string{
		{"HOME", homeDir},
		{"USER", usr.Username},
		{"LOGNAME", usr.Username},
		{"SHELL", "/bin/bash"},
		{"PATH", strings.Join(pathEntries, ":")},
		{"LANG", envOr("LANG", "C.UTF-8")},
		{"COLORTERM", "truecolor"},
		// All egress is envoy or nothing: proxy env is the sanctioned path.
		{"HTTP_PROXY", proxyURL},
		{"HTTPS_PROXY", proxyURL},
		{"http_proxy", proxyURL},
		{"https_proxy", proxyURL},
		{"NO_PROXY", "localhost,127.0.0.1,::1"},
		{"no_proxy", "localhost,127.0.0.1,::1"},
		{"SSL_CERT_FILE", caBundle},
		{"CURL_CA_BUNDLE", caBundle},
		{"REQUESTS_CA_BUNDLE", caBundle},
		{"PIP_CERT", caBundle},
		{"GIT_SSL_CAINFO", caBundle},
		{"NIX_SSL_CERT_FILE", caBundle},
		{"NODE_EXTRA_CA_CERTS", caBundle},
	}
	env = append(env,
		[2]string{"SANDBOX_ENV", sandboxEnv},
		[2]string{"TERMINFO_DIRS", filepath.Join(sandboxEnv, "share", "terminfo") + ":/usr/share/terminfo"},
		[2]string{"XDG_DATA_DIRS", filepath.Join(sandboxEnv, "share") + ":/usr/share:/share"},
	)
	if cfg.Sandbox.Agent == "claude" || cfg.Sandbox.Agent == "" {
		env = append(env,
			[2]string{"CLAUDE_CONFIG_DIR", filepath.Join(homeDir, ".claude")},
			[2]string{"CLAUDE_CODE_FORCE_SESSION_PERSISTENCE", "1"},
		)
	}
	// Plugin/project env vars.
	var projectEnvNames []string
	for _, e := range cfg.Env {
		if value := resolveEnvValueFrom(e.Value, workDir); value != "" {
			env = append(env, [2]string{e.Name, value})
			projectEnvNames = append(projectEnvNames, e.Name)
		}
	}
	if len(projectEnvNames) > 0 {
		env = append(env, [2]string{"ADEV_PROJECT_ENV_NAMES", strings.Join(projectEnvNames, " ")})
	}
	args = append(args, "--clearenv")
	for _, kv := range env {
		args = append(args, "--setenv", kv[0], kv[1])
	}

	args = append(args, "--chdir", workDir)
	return args, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// writeBwrapSetupScript writes the script that runs inside the instance
// user+net namespace (host mount ns, ambient caps from unshare --keep-caps):
// configure the slirp tap with a host-only route, install the nft output
// filter, start the dns-responder, then drop ALL capabilities and exec bwrap.
func writeBwrapSetupScript(path, scriptDir, instanceGenDir string, envoyPort int, bwrapArgs, agentArgv []string) error {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	b.WriteString("# Auto-generated by adev (bwrap runtime) — do not edit\n")
	b.WriteString("# Runs inside the instance user+network namespace with ambient caps.\n")
	b.WriteString("set -u\n")
	fmt.Fprintf(&b, "GEN=%s\n", shq(instanceGenDir))
	fmt.Fprintf(&b, "PORT=%d\n", envoyPort)
	b.WriteString(`
# Wait for slirp4netns to attach the tap device.
for i in $(seq 1 300); do ip link show tap0 >/dev/null 2>&1 && break; sleep 0.1; done
if ! ip link show tap0 >/dev/null 2>&1; then
    echo "adev: slirp4netns did not attach; the sandbox will have no egress" >&2
fi
ip link set lo up 2>/dev/null
ip link set tap0 up 2>/dev/null
# Host-only route: 10.0.2.2 (the slirp gateway = host loopback) is the ONLY
# destination with a route. No default route -> no direct internet.
ip addr add 10.0.2.100 peer 10.0.2.2/32 dev tap0 2>/dev/null
# Port-level filter: envoy's published CONNECT port only (plus loopback).
if ! nft -f - >/dev/null 2>&1 <<NFT
table inet adev {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ip daddr 10.0.2.2 tcp dport $PORT accept
  }
}
NFT
then
    echo "adev: nft unavailable; relying on route confinement only" >&2
fi
# dns-responder inside the netns: allowlist-enforcing, answers 10.0.2.2.
setpriv --ambient-caps=-all,+net_bind_service --inh-caps=-all,+net_bind_service -- \
`)
	fmt.Fprintf(&b, "    %s -ip 10.0.2.2 -domains \"$GEN/domains.json\" -log \"$GEN/logs/dns.log\" >/dev/null 2>&1 &\n",
		shq(filepath.Join(scriptDir, "generated", "dns-responder")))
	b.WriteString(`
# Credential tokens + static env, re-read every session start.
ENVARGS=()
if [ -f "$GEN/sandbox.env" ]; then
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        ENVARGS+=(--setenv "${line%%=*}" "${line#*=}")
    done < "$GEN/sandbox.env"
fi

# Drop ALL capabilities before entering the mount sandbox: the agent (in
# bwrap's nested userns) ends up with no privileges over this netns, so the
# route + filter confinement above cannot be undone from inside.
exec setpriv --ambient-caps=-all --inh-caps=-all --bounding-set=-all -- \
    bwrap \
`)
	for _, a := range bwrapArgs {
		fmt.Fprintf(&b, "    %s \\\n", shq(a))
	}
	b.WriteString("    ${ENVARGS[@]+\"${ENVARGS[@]}\"} \\\n")
	b.WriteString("    --setenv TERM \"${TERM:-xterm-256color}\" \\\n")
	b.WriteString("    -- \\\n")
	for i, a := range agentArgv {
		sep := " \\\n"
		if i == len(agentArgv)-1 {
			sep = "\n"
		}
		fmt.Fprintf(&b, "    %s%s", shq(a), sep)
	}
	return os.WriteFile(path, []byte(b.String()), 0700)
}

// writeBwrapLaunchScript writes the zmx session command: it forks the
// slirp4netns attacher (which waits for this pid to enter its new netns),
// then execs into the unshare'd setup script, keeping the session PTY.
func writeBwrapLaunchScript(path, instanceGenDir, setupScript string) error {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	b.WriteString("# Auto-generated by adev (bwrap runtime) — do not edit\n")
	b.WriteString("set -u\n")
	fmt.Fprintf(&b, "GEN=%s\n", shq(instanceGenDir))
	fmt.Fprintf(&b, "SETUP=%s\n", shq(setupScript))
	b.WriteString(`P=$$
HOST_NET=$(readlink /proc/self/ns/net)
mkdir -p "$GEN/logs"
(
    # Wait until the launcher (same pid after exec) is in its new netns,
    # then attach slirp4netns via the owning userns.
    for i in $(seq 1 600); do
        [ "$(readlink /proc/$P/ns/net 2>/dev/null || echo "$HOST_NET")" != "$HOST_NET" ] && break
        sleep 0.1
    done
    exec slirp4netns --mtu=65520 --userns-path=/proc/$P/ns/user --netns-type=path /proc/$P/ns/net tap0
) >> "$GEN/logs/slirp.log" 2>&1 &
echo $! > "$GEN/slirp.pid"
exec unshare --map-current-user --net --keep-caps /bin/bash "$SETUP"
`)
	return os.WriteFile(path, []byte(b.String()), 0700)
}

// startBwrapConfigWatcher watches the project toml and applies egress
// changes live: regenerate envoy config, restart the envoy container, and
// re-mint changed tokens. Returns a stop function.
func startBwrapConfigWatcher(workDir, scriptDir, instanceGenDir, envoyName string, cfg ProjectConfig) func() {
	configPath := filepath.Join(workDir, "agent-creds.toml")
	if !fileExists(configPath) {
		return func() {}
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return func() {}
	}
	watcher.Add(configPath)
	currentHosts := sortedUpstreamKeys(cfg.Upstream)
	currentUpstreams := copyUpstreamMap(cfg.Upstream)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				newCfg, err := LoadProjectConfigWithPlugins(workDir, scriptDir)
				if err != nil {
					continue
				}
				newHosts := sortedUpstreamKeys(newCfg.Upstream)
				routingChanged := len(newHosts) != len(currentHosts)
				if !routingChanged {
					for i := range newHosts {
						if newHosts[i] != currentHosts[i] {
							routingChanged = true
							break
						}
					}
				}
				if !routingChanged {
					for host, upstream := range newCfg.Upstream {
						if upstreamChanged(currentUpstreams[host], upstream) {
							routingChanged = true
							break
						}
					}
				}
				if routingChanged {
					if newGen, err := NewGenerator(scriptDir, instanceGenDir, newCfg); err == nil {
						if err := newGen.Generate(); err == nil {
							run("docker", "restart", envoyName)
							currentHosts = newHosts
						}
					}
				}
				remintTokens(newCfg, scriptDir, instanceGenDir, currentUpstreams)
				currentUpstreams = copyUpstreamMap(newCfg.Upstream)
			case _, ok := <-watcher.Errors:
				if !ok {
					return
				}
			}
		}
	}()
	return func() { watcher.Close() }
}
