package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func runConsole(args []string) {
	// Get directories
	workDir, _ := os.Getwd()

	// Load per-project config
	cfg, err := LoadProjectConfig(workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading agent-creds.toml: %v\n", err)
		os.Exit(1)
	}

	// Determine instance name
	name := cfg.Sandbox.Name
	if name == "" {
		name = filepath.Base(workDir)
	}
	// Allow override from args
	if len(args) > 0 {
		name = args[0]
	}
	slug := Slug(name)

	// Get the actual executable path (resolves symlinks)
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe)) // go up from bin/

	mgr := NewInstanceManager(scriptDir)
	inst := mgr.GetInstance(slug)

	// Check if we can attach to an existing instance
	if mgr.CanAttach(inst) {
		fmt.Printf("Attaching to '%s'...\n", slug)
		if err := mgr.AttachToInstance(inst); err != nil {
			fmt.Fprintf(os.Stderr, "Error attaching: %v\n", err)
			os.Exit(1)
		}
		return // Attacher exits cleanly, no cleanup
	}

	// If there's a stale instance, clean it up
	if inst != nil {
		fmt.Printf("Cleaning up stale instance '%s'...\n", slug)
		mgr.CleanupInstance(inst)
	}

	// Create new instance
	createInstance(workDir, scriptDir, slug, cfg)
}

func createInstance(workDir, scriptDir, slug string, cfg ProjectConfig) {
	containerName := "adev-" + slug + "-net"
	envoyName := "adev-" + slug + "-envoy"
	sandboxName := "adev-" + slug + "-sandbox"
	networkName := "adev-" + slug

	if err := os.Chdir(scriptDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error changing to %s: %v\n", scriptDir, err)
		os.Exit(1)
	}

	spinner := NewSpinner()
	spinner.Status("starting")
	spinner.Start()

	cleanup := func() {
		run("docker", "rm", "-f", sandboxName)
		run("docker", "rm", "-f", containerName)
		run("docker", "rm", "-f", envoyName)
		run("docker", "network", "rm", networkName)
		// Clean up sockets
		os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-browser.sock", slug)))
		os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-cdp.sock", slug)))
	}

	// Handle cleanup on interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		spinner.Stop()
		cleanup()
		os.Exit(1)
	}()

	// Run generator to ensure configs are up to date
	spinner.Status("generating configs...")
	gen, err := NewGenerator(scriptDir, cfg)
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

	// Ensure authz is running (local only)
	if !cfg.Vault.IsRemote() {
		out, _ := runOutput("docker", "compose", "ps", "--status", "running")
		if len(out) == 0 || !contains(string(out), "authz") {
			spinner.Status("starting authz...")
			if err := run("docker", "compose", "up", "-d", "--build", "--quiet-pull"); err != nil {
				spinner.Stop()
				fmt.Fprintf(os.Stderr, "Error starting authz: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Build aenv if needed
	aenvBin := "generated/aenv"
	aenvSrc := "cmd/aenv/main.go"
	if !fileExists(aenvBin) || fileNewer(aenvSrc, aenvBin) {
		spinner.Status("building aenv...")
		cmd := exec.Command("go", "build", "-o", "../../generated/aenv", ".")
		cmd.Dir = "cmd/aenv"
		cmd.Run()
	}

	// Build cdp-proxy if needed
	cdpProxyBin := "generated/cdp-proxy"
	cdpProxySrc := "cmd/cdp-proxy/main.go"
	if !fileExists(cdpProxyBin) || fileNewer(cdpProxySrc, cdpProxyBin) {
		spinner.Status("building cdp-proxy...")
		cmd := exec.Command("go", "build", "-o", "../../generated/cdp-proxy", ".")
		cmd.Dir = "cmd/cdp-proxy"
		cmd.Run()
	}

	// Build sandbox if needed
	sandboxImage := cfg.Sandbox.Image
	if sandboxImage == "" {
		sandboxImage = "sandbox"
		needsBuild := !imageExists(sandboxImage)
		if !needsBuild {
			marker := "generated/.sandbox-built"
			needsBuild = fileNewer("claude-dev/Dockerfile", marker) ||
				fileNewer("claude-dev/entrypoint.sh", marker) ||
				fileNewer("generated/aenv", marker) ||
				fileNewer("generated/certs/ca.crt", marker) ||
				fileNewer("generated/hosts", marker)
		}
		if needsBuild {
			spinner.Status("building sandbox...")
			uid := fmt.Sprintf("%d", os.Getuid())
			gid := fmt.Sprintf("%d", os.Getgid())
			run("docker", "build", "-q", "-t", sandboxImage,
				"--build-arg", "USER_UID="+uid,
				"--build-arg", "USER_GID="+gid,
				"-f", "claude-dev/Dockerfile", ".")
			os.WriteFile("generated/.sandbox-built", []byte{}, 0644)
		}
	}

	// Build sandbox-net if needed
	needsNetBuild := !imageExists("sandbox-net")
	if !needsNetBuild {
		marker := "generated/.sandbox-net-built"
		needsNetBuild = fileNewer("claude-dev/sandbox-net/Dockerfile", marker) ||
			fileNewer("claude-dev/sandbox-net/entrypoint.sh", marker)
	}
	if needsNetBuild {
		spinner.Status("building sandbox-net...")
		run("docker", "build", "-q", "-t", "sandbox-net",
			"-f", "claude-dev/sandbox-net/Dockerfile", "claude-dev/sandbox-net")
		os.WriteFile("generated/.sandbox-net-built", []byte{}, 0644)
	}

	// Creds mount
	var credsMounts []string
	if fileExists("creds") {
		credsMounts = []string{"-v", scriptDir + "/creds:/creds:ro"}
	}

	// Pip cache mount (speeds up pip installs)
	var pipCacheMounts []string
	homeDir, _ := os.UserHomeDir()
	pipCache := filepath.Join(homeDir, ".cache", "pip")
	if fileExists(pipCache) {
		pipCacheMounts = []string{"-v", pipCache + ":/home/devuser/.cache/pip"}
	}

	// Create claude config dir (namespaced per project)
	claudeConfigDir := filepath.Join(scriptDir, "claude-dev/claude-config")
	os.MkdirAll(claudeConfigDir, 0755)

	// Create per-sandbox network
	spinner.Status("creating network...")
	createNetArgs := []string{"network", "create", "--ipv6", networkName}
	if err := run("docker", createNetArgs...); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error creating network %s: %v\n", networkName, err)
		os.Exit(1)
	}

	// Start per-sandbox envoy
	spinner.Status("starting envoy...")
	if err := run("docker", "run", "-d", "--rm",
		"--name", envoyName,
		"--network", networkName,
		"--network-alias", "envoy",
		"-v", scriptDir+"/generated/certs/ca.crt:/certs/ca.crt:ro",
		"-v", scriptDir+"/generated/certs/ca.key:/certs/ca.key:ro",
		"-v", scriptDir+"/generated/domains.json:/etc/envoy/domains.json:ro",
		"-v", scriptDir+"/generated/envoy.json:/etc/envoy/envoy.json:ro",
		"-v", scriptDir+"/envoy-entrypoint.sh:/entrypoint.sh:ro",
		"--entrypoint", "/entrypoint.sh",
		"envoyproxy/envoy:v1.28-latest",
		"-c", "/etc/envoy/envoy.json"); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error starting envoy: %v\n", err)
		os.Exit(1)
	}

	// Connect envoy to authz network (local only)
	if !cfg.Vault.IsRemote() {
		if err := run("docker", "network", "connect", "agent-creds_agent-creds", envoyName); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error connecting envoy to authz network: %v\n", err)
			os.Exit(1)
		}
	}

	// Start sandbox-net on per-sandbox network
	spinner.Status("starting network filter...")
	if err := run("docker", "run", "-d", "--rm",
		"--name", containerName,
		"--network", networkName,
		"--cap-add=NET_ADMIN",
		"sandbox-net"); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error starting sandbox-net: %v\n", err)
		os.Exit(1)
	}

	time.Sleep(500 * time.Millisecond)

	// Start browser-forward server with instance-based socket path
	var browserSock string
	if cfg.Sandbox.UseHostBrowserEnabled() {
		spinner.Status("starting browser forward...")
		browserSock, err = startBrowserForward(containerName, slug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: browser forwarding disabled: %v\n", err)
			browserSock = ""
		}
	}

	// Start CDP forward with instance-based socket path
	var cdpSock string
	if cfg.Sandbox.UseHostBrowserCDPEnabled() {
		spinner.Status("starting CDP forward...")
		cdpSock, err = startCDPForward(slug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: CDP forwarding disabled: %v\n", err)
			cdpSock = ""
		}
	}

	// Stop spinner
	spinner.Stop()

	// Run sandbox
	args := []string{"run", "-it", "--rm",
		"--name", sandboxName,
		"--network=container:" + containerName,
		"-e", "CLAUDE_CONFIG_DIR=/home/devuser/.claude",
		"-v", workDir + ":/workspace",
		"-v", claudeConfigDir + ":/home/devuser/.claude",
	}
	// Add browser forwarding if available
	if browserSock != "" {
		args = append(args, "-v", browserSock+":/run/browser-forward.sock")
		args = append(args, "-e", "BROWSER=/usr/local/bin/open-browser")
	}
	// Add CDP forwarding if available
	if cdpSock != "" {
		args = append(args, "-v", cdpSock+":/run/cdp-forward.sock")
	}
	args = append(args, credsMounts...)
	args = append(args, pipCacheMounts...)
	// Mount project config for aenv (read-only, well-known path)
	agentCredsToml := filepath.Join(workDir, "agent-creds.toml")
	if fileExists(agentCredsToml) {
		args = append(args, "-v", agentCredsToml+":/etc/aenv/agent-creds.toml:ro")
	}

	if sandboxImage == "" {
		sandboxImage = "sandbox"
	}
	args = append(args, sandboxImage)

	cmd := exec.Command("docker", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	// Cleanup (owner responsibility)
	cleanup()
}
