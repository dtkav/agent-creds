package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)


func runConsole(args []string) {
	// Get directories
	workDir, _ := os.Getwd()

	// Get the actual executable path (resolves symlinks)
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe)) // go up from bin/

	// Load per-project config with plugins
	cfg, err := LoadProjectConfigWithPlugins(workDir, scriptDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
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

	// Ensure vault is running (local only)
	if !cfg.Vault.IsRemote() {
		out, _ := runOutput("docker", "compose", "ps", "--status", "running")
		if len(out) == 0 || !contains(string(out), "vault") {
			spinner.Status("starting vault...")
			if err := run("docker", "compose", "up", "-d", "--build", "--quiet-pull"); err != nil {
				spinner.Stop()
				fmt.Fprintf(os.Stderr, "Error starting vault: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Build aenv if needed (CGO_ENABLED=0 for static binary, required by Nix-based image)
	aenvBin := "generated/aenv"
	aenvSrc := "cmd/aenv/main.go"
	if !fileExists(aenvBin) || fileNewer(aenvSrc, aenvBin) {
		spinner.Status("building aenv...")
		cmd := exec.Command("go", "build", "-o", "../../generated/aenv", ".")
		cmd.Dir = "cmd/aenv"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Build cdp-proxy if needed
	cdpProxyBin := "generated/cdp-proxy"
	cdpProxySrc := "cmd/cdp-proxy/main.go"
	if !fileExists(cdpProxyBin) || fileNewer(cdpProxySrc, cdpProxyBin) {
		spinner.Status("building cdp-proxy...")
		cmd := exec.Command("go", "build", "-o", "../../generated/cdp-proxy", ".")
		cmd.Dir = "cmd/cdp-proxy"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Build tcp-bridge if needed (for gVisor mode)
	tcpBridgeBin := "generated/tcp-bridge"
	tcpBridgeSrc := "cmd/tcp-bridge/main.go"
	if !fileExists(tcpBridgeBin) || fileNewer(tcpBridgeSrc, tcpBridgeBin) {
		spinner.Status("building tcp-bridge...")
		cmd := exec.Command("go", "build", "-o", "../../generated/tcp-bridge", ".")
		cmd.Dir = "cmd/tcp-bridge"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Generate SSH key pair if not present (used by adev console to SSH into sandbox)
	sshKeyPath := filepath.Join(scriptDir, "generated", "sandbox-key")
	sshPubKeyPath := sshKeyPath + ".pub"
	if !fileExists(sshKeyPath) {
		spinner.Status("generating SSH key...")
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", sshKeyPath, "-N", "", "-C", "adev-sandbox")
		cmd.Run()
	}

	// Get sandbox image (default to registry)
	sandboxImage := cfg.Sandbox.Image
	var envPath string // Nix store path for sandbox-env (only for local builds)
	if sandboxImage == "" {
		sandboxImage = "docker.system3.md/sandbox"
	}
	if sandboxImage == "sandbox-local" {
		// Build base image + env separately (env rebuilds are fast)
		if err := ensureBaseImage(scriptDir, spinner); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error building base image: %v\n", err)
			os.Exit(1)
		}
		var err error
		envPath, err = ensureSandboxEnv(cfg, scriptDir, spinner)
		if err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error building sandbox env: %v\n", err)
			os.Exit(1)
		}
		sandboxImage = "sandbox-base"
	} else if !imageExists(sandboxImage) {
		spinner.Status("pulling sandbox image...")
		if err := run("docker", "pull", sandboxImage); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error: image %s not found locally and pull failed: %v\n", sandboxImage, err)
			os.Exit(1)
		}
	}

	// Creds mount
	var credsMounts []string
	if fileExists("creds") {
		credsMounts = []string{"-v", scriptDir + "/creds:/creds:ro"}
	}

	// Git config mount (preserves git identity for commits)
	var gitConfigMounts []string
	homeDir, _ := os.UserHomeDir()
	gitConfig := filepath.Join(homeDir, ".gitconfig")
	if fileExists(gitConfig) {
		gitConfigMounts = []string{"-v", gitConfig + ":/home/devuser/.gitconfig:ro"}
	}

	// Create claude config dir (namespaced per project)
	claudeConfigDir := filepath.Join(scriptDir, "claude-dev/claude-config")
	os.MkdirAll(claudeConfigDir, 0755)

	// Create per-sandbox network (remove stale one first if it exists without containers)
	spinner.Status("creating network...")
	run("docker", "network", "rm", networkName) // ignore error - may not exist
	if err := run("docker", "network", "create", "--ipv6", networkName); err != nil {
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
		"--ulimit", "nofile=65536:65536",
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

	// Connect envoy to vault network (local only)
	if !cfg.Vault.IsRemote() {
		if err := run("docker", "network", "connect", "agent-creds_agent-creds", envoyName); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error connecting envoy to vault network: %v\n", err)
			os.Exit(1)
		}
	}

	// gVisor (default): sandbox-net starts later with --network=host
	// runc: sandbox-net starts now, sandbox shares its network namespace
	useHostNetfilter := cfg.Sandbox.UsesHostNetfilter()

	// Get gateway IP (browser/cdp forward listens here, reachable from containers)
	gatewayIP, err := GetNetworkGateway(networkName)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error getting gateway IP: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	if !useHostNetfilter {
		// runc mode: sandbox-net on Docker network, sandbox will share its namespace
		spinner.Status("starting network filter...")
		if err := run("docker", "run", "-d", "--rm",
			"--name", containerName,
			"--network", networkName,
			"--cap-add=NET_ADMIN",
			"-v", scriptDir+"/claude-dev/sandbox-net/entrypoint.sh:/entrypoint.sh:ro",
			"alpine", "sh", "-c", "apk add --no-cache iptables ip6tables && /entrypoint.sh"); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error starting sandbox-net: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Forwarder state (protected by mutex for config watcher)
	var fwdMu sync.Mutex
	var browserFwd, cdpFwd *ForwardState
	cdpPort := int(cfg.Sandbox.UseHostBrowserCDP)

	// Allocate TCP ports for gVisor mode (bound to 127.0.0.1, DNAT'd by sandbox-net)
	tcpBrowserPort, tcpCDPPort := AllocateTCPPorts(slug)

	// Start browser-forward server (TCP, tcp-bridge creates Unix socket in container)
	if cfg.Sandbox.UseHostBrowserEnabled() {
		spinner.Status("starting browser forward...")
		browserFwd, err = startBrowserForwardTCP(sandboxName, gatewayIP, tcpBrowserPort, cfg.BrowserTargets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: browser forwarding disabled: %v\n", err)
		}
	}

	// Start CDP forward (TCP, tcp-bridge creates Unix socket in container)
	if cfg.Sandbox.UseHostBrowserCDPEnabled() {
		spinner.Status("starting CDP forward...")
		cdpFwd, err = startCDPForwardTCP(gatewayIP, tcpCDPPort, cdpPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: CDP forwarding disabled: %v\n", err)
		}
	}

	// Track current upstream hosts for hot-reload detection
	currentHosts := sortedUpstreamKeys(cfg.Upstream)

	// Watch config file for changes
	configPath := filepath.Join(workDir, "agent-creds.toml")
	if fileExists(configPath) {
		watcher, err := fsnotify.NewWatcher()
		if err == nil {
			watcher.Add(configPath)
			go func() {
				defer watcher.Close()
				for {
					select {
					case event, ok := <-watcher.Events:
						if !ok {
							return
						}
						if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
							// Reload config with plugins
							newCfg, err := LoadProjectConfigWithPlugins(workDir, scriptDir)
							if err != nil {
								continue
							}

							fwdMu.Lock()
							// Handle browser forwarding changes
							wantBrowser := newCfg.Sandbox.UseHostBrowserEnabled()
							haveBrowser := browserFwd != nil
							if wantBrowser && !haveBrowser {
								browserFwd, _ = startBrowserForwardTCP(sandboxName, gatewayIP, tcpBrowserPort, newCfg.BrowserTargets)
							} else if !wantBrowser && haveBrowser {
								browserFwd.Close()
								browserFwd = nil
							}

							// Handle CDP forwarding changes
							newCdpPort := int(newCfg.Sandbox.UseHostBrowserCDP)
							wantCDP := newCfg.Sandbox.UseHostBrowserCDPEnabled()
							haveCDP := cdpFwd != nil
							if wantCDP && !haveCDP {
								cdpFwd, _ = startCDPForwardTCP(gatewayIP, tcpCDPPort, newCdpPort)
							} else if !wantCDP && haveCDP {
								cdpFwd.Close()
								cdpFwd = nil
							} else if wantCDP && haveCDP && newCdpPort != cdpPort {
								cdpFwd.Close()
								cdpFwd, _ = startCDPForwardTCP(gatewayIP, tcpCDPPort, newCdpPort)
							}
							cdpPort = newCdpPort
							fwdMu.Unlock()

							// Handle upstream changes: regenerate configs and restart envoy
							newHosts := sortedUpstreamKeys(newCfg.Upstream)
							if !slices.Equal(newHosts, currentHosts) {
								newGen, err := NewGenerator(scriptDir, newCfg)
								if err == nil {
									if err := newGen.Generate(); err == nil {
										run("docker", "restart", envoyName)
										currentHosts = newHosts
									}
								}
							}
						}
					case _, ok := <-watcher.Errors:
						if !ok {
							return
						}
					}
				}
			}()
		}
	}

	// Build sandbox args
	args := []string{"run", "--rm",
		"--name", sandboxName,
		"--tmpfs", "/run:exec",  // s6-svscan creates service dirs here
		"--tmpfs", "/tmp:exec",  // dropbear host key, ready signal, etc.
	}
	// Network configuration depends on runtime:
	// - gvisor (default): connect directly to network, sandbox-net uses --network=host
	// - runc: share network namespace with sandbox-net container
	if useHostNetfilter {
		args = append(args, "--network", networkName)
		// gVisor doesn't work with Docker's embedded DNS (127.0.0.11)
		// Mount custom resolv.conf with external DNS servers
		resolvConf := filepath.Join(scriptDir, "generated", "resolv.conf")
		if !fileExists(resolvConf) {
			os.WriteFile(resolvConf, []byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"), 0644)
		}
		args = append(args, "-v", resolvConf+":/etc/resolv.conf:ro")
	} else {
		args = append(args, "--network=container:"+containerName)
	}
	args = append(args,
		"-e", "CLAUDE_CONFIG_DIR=/home/devuser/.claude",
		"-v", workDir+":/workspace",
		"-v", claudeConfigDir+":/home/devuser/.claude",
		// Mount agent-creds CA so proxy TLS is trusted system-wide
		"-v", scriptDir+"/generated/certs/ca.crt:/etc/ssl/agent-creds-ca.crt:ro",
		// Mount entrypoint and binaries so changes take effect without image rebuild
		"-v", scriptDir+"/claude-dev/entrypoint.sh:/entrypoint.sh:ro",
		"-v", scriptDir+"/generated/aenv:/usr/local/bin/aenv:ro",
		"-v", scriptDir+"/generated/cdp-proxy:/usr/local/bin/cdp-proxy:ro",
		"-v", scriptDir+"/generated/tcp-bridge:/usr/local/bin/tcp-bridge:ro",
		// SSH public key for passwordless login (mounted to /etc/adev/ so tmpfs on /tmp doesn't hide it)
		"-v", sshPubKeyPath+":/etc/adev/pubkey:ro",
	)
	// Mount host Nix store for sandbox-env (local builds only)
	if envPath != "" {
		args = append(args,
			"-v", nixDir()+":/nix:ro",
			"-e", "SANDBOX_ENV="+envPath,
		)
	}
	// Browser and CDP forwarding via TCP (tcp-bridge creates Unix sockets in container)
	if browserFwd != nil {
		args = append(args, "-e", fmt.Sprintf("TCP_BROWSER_PORT=%d", tcpBrowserPort))
		args = append(args, "-e", "BROWSER=/usr/local/bin/open-browser")
	}
	if cdpFwd != nil {
		args = append(args, "-e", fmt.Sprintf("TCP_CDP_PORT=%d", tcpCDPPort))
		args = append(args, "-e", fmt.Sprintf("CDP_PORT=%d", cdpPort))
	}
	args = append(args, credsMounts...)
	args = append(args, gitConfigMounts...)
	// Mount merged config for aenv display (includes agent + plugin upstreams),
	// and raw project config in workspace for user reference.
	mergedConfigToml := filepath.Join(scriptDir, "generated", "merged-config.toml")
	agentCredsToml := filepath.Join(workDir, "agent-creds.toml")
	if fileExists(mergedConfigToml) {
		args = append(args, "-v", mergedConfigToml+":/etc/aenv/agent-creds.toml:ro")
	} else if fileExists(agentCredsToml) {
		args = append(args, "-v", agentCredsToml+":/etc/aenv/agent-creds.toml:ro")
	}
	if fileExists(agentCredsToml) {
		args = append(args, "-v", agentCredsToml+":/workspace/agent-creds.toml:ro")
	}

	// Plugin mounts
	for _, mount := range cfg.Mounts {
		if !fileExists(mount.Source) {
			fmt.Fprintf(os.Stderr, "Warning: mount source %s does not exist, skipping\n", mount.Source)
			continue
		}
		mountStr := mount.Source + ":" + mount.Target
		if mount.Readonly {
			mountStr += ":ro"
		}
		args = append(args, "-v", mountStr)
	}

	// Plugin environment variables
	for _, env := range cfg.Env {
		value := resolveEnvValue(env.Value)
		if value != "" {
			args = append(args, "-e", env.Name+"="+value)
		}
	}

	// Add custom runtime if configured (only for sandbox, not sandbox-net or envoy)
	if rt := cfg.Sandbox.RuntimeArg(); rt != "" {
		args = append(args, "--runtime="+rt)
	}

	if sandboxImage == "" {
		sandboxImage = "sandbox"
	}

	// Start sandbox
	spinner.Status("starting sandbox...")
	detachedArgs := append([]string{"run", "-dit", "--rm"}, args[2:]...)
	detachedArgs = append(detachedArgs, sandboxImage)
	if err := run("docker", detachedArgs...); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error starting sandbox: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	if useHostNetfilter {
		// gVisor: get subnet from Docker network (no need to wait for sandbox IP)
		subnet, err := GetNetworkSubnet(networkName)
		if err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error getting network subnet: %v\n", err)
			cleanup()
			os.Exit(1)
		}
		envoyIP, err := GetContainerIP(envoyName, networkName)
		if err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error getting envoy IP: %v\n", err)
			cleanup()
			os.Exit(1)
		}

		// Get IPv6 addresses for dual-stack DNAT
		subnet6 := GetNetworkSubnet6(networkName)
		envoyIP6 := GetContainerIP6(envoyName, networkName)
		gatewayIP6 := GetNetworkGateway6(networkName)

		spinner.Status("starting network filter...")
		chainName := "ADEV-" + strings.ToUpper(slug)
		entrypointArgs := fmt.Sprintf("%s %s %s %s %s %s %s", subnet, envoyIP, chainName, gatewayIP, subnet6, envoyIP6, gatewayIP6)
		if err := runQuiet("docker", "run", "-d", "--rm",
			"--name", containerName,
			"--network=host",
			"--cap-add=NET_ADMIN",
			"-v", scriptDir+"/claude-dev/sandbox-net/entrypoint-host.sh:/entrypoint.sh:ro",
			"alpine", "sh", "-c", fmt.Sprintf("apk add --no-cache iptables ip6tables && /entrypoint.sh %s", entrypointArgs)); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error starting sandbox-net: %v\n", err)
			cleanup()
			os.Exit(1)
		}
	}

	// Wait for entrypoint to finish (touches /tmp/adev-ready when sshd is up)
	spinner.Status("waiting for sandbox...")
	waitCmd := exec.Command("docker", "exec", sandboxName,
		"sh", "-c", "until [ -f /tmp/adev-ready ]; do sleep 0.1; done")
	waitCmd.Run()

	// Get container IP for SSH
	var sshIP string
	if useHostNetfilter {
		sshIP, err = GetContainerIP(sandboxName, networkName)
	} else {
		sshIP, err = GetContainerIP(containerName, networkName)
	}
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error getting container IP: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	spinner.Stop()
	signal.Stop(sigChan)

	// SSH into the sandbox (dropbear runs as devuser on port 2222)
	sshCmd := exec.Command("ssh",
		"-i", sshKeyPath,
		"-p", "2222",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=10",
		"devuser@"+sshIP)
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Run()
	// No cleanup: use 'adev stop' to stop.
}

func sortedUpstreamKeys(m map[string]UpstreamConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
