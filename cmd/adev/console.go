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

	// Socket paths for cleanup
	browserSockCleanup := filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-browser.sock", slug))
	cdpSockCleanup := filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-cdp.sock", slug))

	cleanup := func() {
		run("docker", "rm", "-f", sandboxName)
		run("docker", "rm", "-f", containerName)
		run("docker", "rm", "-f", envoyName)
		run("docker", "network", "rm", networkName)
		// Clean up sockets
		os.Remove(browserSockCleanup)
		os.Remove(cdpSockCleanup)
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

	// Build vsock-bridge if needed (for gVisor mode)
	vsockBridgeBin := "generated/vsock-bridge"
	vsockBridgeSrc := "cmd/vsock-bridge/main.go"
	if !fileExists(vsockBridgeBin) || fileNewer(vsockBridgeSrc, vsockBridgeBin) {
		spinner.Status("building vsock-bridge...")
		cmd := exec.Command("go", "build", "-o", "../../generated/vsock-bridge", ".")
		cmd.Dir = "cmd/vsock-bridge"
		cmd.Run()
	}

	// Get sandbox image (default to registry)
	sandboxImage := cfg.Sandbox.Image
	if sandboxImage == "" {
		sandboxImage = "docker.system3.md/sandbox"
	}
	if !imageExists(sandboxImage) {
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

	// Pip cache mount (speeds up pip installs)
	var pipCacheMounts []string
	homeDir, _ := os.UserHomeDir()
	pipCache := filepath.Join(homeDir, ".cache", "pip")
	if fileExists(pipCache) {
		pipCacheMounts = []string{"-v", pipCache + ":/home/devuser/.cache/pip"}
	}

	// Git config mount (preserves git identity for commits)
	var gitConfigMounts []string
	gitConfig := filepath.Join(homeDir, ".gitconfig")
	if fileExists(gitConfig) {
		gitConfigMounts = []string{"-v", gitConfig + ":/home/devuser/.gitconfig:ro"}
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

	// Connect envoy to vault network (local only)
	if !cfg.Vault.IsRemote() {
		if err := run("docker", "network", "connect", "agent-creds_agent-creds", envoyName); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error connecting envoy to vault network: %v\n", err)
			os.Exit(1)
		}
	}

	// Start sandbox-net for runc (gvisor starts it later with --network=host)
	useHostNetfilter := cfg.Sandbox.UsesHostNetfilter()

	// Get gateway IP for gVisor mode (browser/cdp forward listens here)
	var gatewayIP string
	if useHostNetfilter {
		var err error
		gatewayIP, err = GetNetworkGateway(networkName)
		if err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error getting gateway IP: %v\n", err)
			cleanup()
			os.Exit(1)
		}
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
	browserSockPath := filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-browser.sock", slug))
	cdpSockPath := filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-cdp.sock", slug))
	cdpPort := int(cfg.Sandbox.UseHostBrowserCDP)

	// Allocate TCP ports for gVisor mode (bound to 127.0.0.1, DNAT'd by sandbox-net)
	tcpBrowserPort, tcpCDPPort := AllocateTCPPorts(slug)

	// Start browser-forward server
	if cfg.Sandbox.UseHostBrowserEnabled() {
		spinner.Status("starting browser forward...")
		if useHostNetfilter {
			// gVisor: use TCP on gateway IP (directly reachable from sandbox)
			browserFwd, err = startBrowserForwardTCP(sandboxName, gatewayIP, tcpBrowserPort, cfg.BrowserTargets)
		} else {
			// runc: use Unix socket
			browserFwd, err = startBrowserForward(containerName, slug, cfg.BrowserTargets)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: browser forwarding disabled: %v\n", err)
		}
	}

	// Start CDP forward
	if cfg.Sandbox.UseHostBrowserCDPEnabled() {
		spinner.Status("starting CDP forward...")
		if useHostNetfilter {
			// gVisor: use TCP on gateway IP (directly reachable from sandbox)
			cdpFwd, err = startCDPForwardTCP(gatewayIP, tcpCDPPort, cdpPort)
		} else {
			// runc: use Unix socket
			cdpFwd, err = startCDPForward(slug, cdpPort)
		}
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
							// Reload config
							newCfg, err := LoadProjectConfig(workDir)
							if err != nil {
								continue
							}

							fwdMu.Lock()
							// Handle browser forwarding changes
							wantBrowser := newCfg.Sandbox.UseHostBrowserEnabled()
							haveBrowser := browserFwd != nil
							if wantBrowser && !haveBrowser {
								if useHostNetfilter {
									browserFwd, _ = startBrowserForwardTCP(sandboxName, gatewayIP, tcpBrowserPort, newCfg.BrowserTargets)
								} else {
									browserFwd, _ = startBrowserForward(containerName, slug, newCfg.BrowserTargets)
								}
							} else if !wantBrowser && haveBrowser {
								browserFwd.Close()
								browserFwd = nil
							}

							// Handle CDP forwarding changes
							newCdpPort := int(newCfg.Sandbox.UseHostBrowserCDP)
							wantCDP := newCfg.Sandbox.UseHostBrowserCDPEnabled()
							haveCDP := cdpFwd != nil
							if wantCDP && !haveCDP {
								if useHostNetfilter {
									cdpFwd, _ = startCDPForwardTCP(gatewayIP, tcpCDPPort, newCdpPort)
								} else {
									cdpFwd, _ = startCDPForward(slug, newCdpPort)
								}
							} else if !wantCDP && haveCDP {
								cdpFwd.Close()
								cdpFwd = nil
							} else if wantCDP && haveCDP && newCdpPort != cdpPort {
								// Port changed, restart
								cdpFwd.Close()
								if useHostNetfilter {
									cdpFwd, _ = startCDPForwardTCP(gatewayIP, tcpCDPPort, newCdpPort)
								} else {
									cdpFwd, _ = startCDPForward(slug, newCdpPort)
								}
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
	}
	// Network configuration depends on runtime:
	// - runc: share network namespace with sandbox-net container
	// - gvisor: connect directly to network, sandbox-net uses --network=host for iptables
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
	)
	// Browser and CDP forwarding: TCP for gVisor, Unix sockets for runc
	if useHostNetfilter {
		// gVisor: use TCP via DNAT (ports passed as env vars for tcp-bridge)
		if browserFwd != nil {
			args = append(args, "-e", fmt.Sprintf("TCP_BROWSER_PORT=%d", tcpBrowserPort))
			args = append(args, "-e", "BROWSER=/usr/local/bin/open-browser")
		}
		if cdpFwd != nil {
			args = append(args, "-e", fmt.Sprintf("TCP_CDP_PORT=%d", tcpCDPPort))
			args = append(args, "-e", fmt.Sprintf("CDP_PORT=%d", cdpPort))
		}
	} else {
		// runc: mount Unix sockets directly
		args = append(args, "-v", browserSockPath+":/run/browser-forward.sock")
		if browserFwd != nil {
			args = append(args, "-e", "BROWSER=/usr/local/bin/open-browser")
		}
		args = append(args, "-v", cdpSockPath+":/run/cdp-forward.sock")
		if cdpFwd != nil {
			args = append(args, "-e", fmt.Sprintf("CDP_PORT=%d", cdpPort))
		}
	}
	args = append(args, credsMounts...)
	args = append(args, pipCacheMounts...)
	args = append(args, gitConfigMounts...)
	// Mount project config for aenv (read-only, well-known path and in workspace)
	agentCredsToml := filepath.Join(workDir, "agent-creds.toml")
	if fileExists(agentCredsToml) {
		args = append(args, "-v", agentCredsToml+":/etc/aenv/agent-creds.toml:ro")
		args = append(args, "-v", agentCredsToml+":/workspace/agent-creds.toml:ro")
	}

	// Add custom runtime if configured (only for sandbox, not sandbox-net or envoy)
	if rt := cfg.Sandbox.RuntimeArg(); rt != "" {
		args = append(args, "--runtime="+rt)
	}

	if sandboxImage == "" {
		sandboxImage = "sandbox"
	}

	// For gvisor: start detached, start sandbox-net with --network=host, then attach
	// For runc: run interactively in one step
	if useHostNetfilter {
		// Start sandbox detached
		spinner.Status("starting sandbox...")
		detachedArgs := append([]string{}, args...)
		detachedArgs = append(detachedArgs[:2], append([]string{"-dit"}, detachedArgs[2:]...)...)
		detachedArgs = append(detachedArgs, sandboxImage)

		if err := run("docker", detachedArgs...); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error starting sandbox: %v\n", err)
			cleanup()
			os.Exit(1)
		}

		// Get IPs for host iptables setup
		sandboxIP, err := GetContainerIP(sandboxName, networkName)
		if err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error getting sandbox IP: %v\n", err)
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

		// Start sandbox-net with --network=host to setup host iptables
		spinner.Status("starting network filter...")
		chainName := "ADEV-" + strings.ToUpper(slug)
		if err := run("docker", "run", "-d", "--rm",
			"--name", containerName,
			"--network=host",
			"--cap-add=NET_ADMIN",
			"-v", scriptDir+"/claude-dev/sandbox-net/entrypoint-host.sh:/entrypoint.sh:ro",
			"alpine", "sh", "-c", fmt.Sprintf("apk add --no-cache iptables && /entrypoint.sh %s %s %s", sandboxIP, envoyIP, chainName)); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error starting sandbox-net: %v\n", err)
			cleanup()
			os.Exit(1)
		}

		// Stop spinner before interactive session
		spinner.Stop()

		// Attach to sandbox interactively
		cmd := exec.Command("docker", "attach", sandboxName)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	} else {
		// Stop spinner before interactive session
		spinner.Stop()

		// Run sandbox interactively (original behavior)
		args = append([]string{}, args...)
		args = append(args[:2], append([]string{"-it"}, args[2:]...)...)
		args = append(args, sandboxImage)

		cmd := exec.Command("docker", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}

	// Cleanup
	cleanup()
}

func sortedUpstreamKeys(m map[string]UpstreamConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
