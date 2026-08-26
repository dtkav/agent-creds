package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
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
	cfg, err = applyGlobalTapConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading global tap config: %v\n", err)
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

	// bwrap runtime: zmx-hosted namespace sandbox instead of docker containers.
	if cfg.Sandbox.Runtime == "bwrap" {
		runBwrapConsole(workDir, scriptDir, slug, cfg)
		return
	}

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

func runStart(args []string) {
	workDir, _ := os.Getwd()
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe))
	cfg, err := LoadProjectConfigWithPlugins(workDir, scriptDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	cfg, err = applyGlobalTapConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading global tap config: %v\n", err)
		os.Exit(1)
	}
	name := cfg.Sandbox.Name
	if name == "" {
		name = filepath.Base(workDir)
	}
	if len(args) > 0 {
		name = args[0]
	}
	if cfg.Sandbox.Runtime != "bwrap" {
		fmt.Fprintln(os.Stderr, "Error: detached start currently requires runtime = \"bwrap\"")
		os.Exit(1)
	}
	runBwrapStart(workDir, scriptDir, Slug(name), cfg)
}

func createInstance(workDir, scriptDir, slug string, cfg ProjectConfig) {
	containerName := "adev-" + slug + "-net"
	envoyName := "adev-" + slug + "-envoy"
	legacyTapName := legacyTapContainerName(slug)
	sandboxName := "adev-" + slug + "-sandbox"
	networkName := "adev-" + slug
	instanceGenDir := filepath.Join(scriptDir, "generated", "instances", slug)
	instanceLogsDir := filepath.Join(instanceGenDir, "logs")
	if err := os.MkdirAll(instanceLogsDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating instance directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.Chdir(scriptDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error changing to %s: %v\n", scriptDir, err)
		os.Exit(1)
	}

	spinner := NewSpinner()
	spinner.Status("starting")
	spinner.Start()

	cleanup := func() {
		if cfg.TapEnabled {
			_ = unregisterTapSource(scriptDir, slug)
		}
		run("docker", "rm", "-f", sandboxName)
		run("docker", "rm", "-f", containerName)
		run("docker", "rm", "-f", legacyTapName)
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
	if cfg.TapEnabled {
		if err := prepareTapSourceRuntime(scriptDir, slug); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error preparing traffic tap: %v\n", err)
			os.Exit(1)
		}
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
		vaultHealth := vaultHealthURL(cfg.Vault.HTTPAddr())
		if !vaultHTTPHealthy(vaultHealth) {
			spinner.Status("starting vault...")
			if err := runWithOutput("docker", "compose", "up", "-d", "--build", "--quiet-pull", "--force-recreate", "vault"); err != nil {
				spinner.Stop()
				fmt.Fprintf(os.Stderr, "Error starting vault: %v\n", err)
				os.Exit(1)
			}
			if err := waitForVaultRunning(vaultHealth); err != nil {
				spinner.Stop()
				fmt.Fprintf(os.Stderr, "Error starting vault: %v\n", err)
				os.Exit(1)
			}
		}
		spinner.Status("reloading vault config...")
		if err := reloadLocalVaultConfig(vaultConfigYAML); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error reloading vault config: %v\n", err)
			os.Exit(1)
		}
	}

	// Mint every configured credential before starting the sandbox. A partial
	// environment is never useful: anonymous reads can otherwise disguise a
	// broken write credential.
	tokenEntries, infos, err := mintTokens(cfg, instanceGenDir, spinner)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error minting sandbox credentials: %v\n", err)
		os.Exit(1)
	}
	if err := materializeCredentialFiles(instanceGenDir, tokenEntries); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error materializing sandbox credentials: %v\n", err)
		os.Exit(1)
	}

	// Generate sandbox.env if there are credentialed upstreams or static env vars
	sandboxEnvGenerated := false
	if len(tokenEntries) > 0 || len(cfg.StaticEnv) > 0 {
		shaped := shapeTokens(tokenEntries, infos)

		// Resolve static env vars
		staticResolved, err := resolveStaticEnvForConsole(cfg.StaticEnv, vaultConfigYAML, scriptDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: resolving static env: %v\n", err)
			staticResolved = make(map[string]string)
		}

		if err := generateSandboxEnv(instanceGenDir, shaped, staticResolved); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error generating sandbox credential environment: %v\n", err)
			os.Exit(1)
		} else {
			sandboxEnvGenerated = true
		}
	}

	// Build aenv if needed (CGO_ENABLED=0 for static binary, required by Nix-based image)
	aenvBin := "generated/aenv"
	aenvSrc := "cmd/aenv/main.go"
	if !fileExists(aenvBin) || fileNewer(aenvSrc, aenvBin) {
		spinner.Status("building aenv...")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", "../../generated/aenv", ".")
		cmd.Dir = "cmd/aenv"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Build cdp-proxy if needed
	cdpProxyBin := "generated/cdp-proxy"
	cdpProxySrc := "cmd/cdp-proxy/main.go"
	if !fileExists(cdpProxyBin) || fileNewer(cdpProxySrc, cdpProxyBin) {
		spinner.Status("building cdp-proxy...")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", "../../generated/cdp-proxy", ".")
		cmd.Dir = "cmd/cdp-proxy"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Build tcp-bridge if needed (for gVisor mode)
	tcpBridgeBin := "generated/tcp-bridge"
	tcpBridgeSrc := "cmd/tcp-bridge/main.go"
	if !fileExists(tcpBridgeBin) || fileNewer(tcpBridgeSrc, tcpBridgeBin) {
		spinner.Status("building tcp-bridge...")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", "../../generated/tcp-bridge", ".")
		cmd.Dir = "cmd/tcp-bridge"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Run()
	}

	// Build dns-responder if needed
	dnsResponderBin := "generated/dns-responder"
	dnsResponderSrc := "cmd/dns-responder/main.go"
	if !fileExists(dnsResponderBin) || fileNewer(dnsResponderSrc, dnsResponderBin) {
		spinner.Status("building dns-responder...")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", "../../generated/dns-responder", ".")
		cmd.Dir = "cmd/dns-responder"
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

	// Get sandbox image. The public default builds locally; deployments can
	// select a prebuilt image in the project sandbox policy.
	sandboxImage := cfg.Sandbox.Image
	var envPath string // Nix store path for sandbox-env (only for local builds)
	if sandboxImage == "" {
		sandboxImage = "sandbox-local"
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

	agentState, err := prepareAgentState(
		scriptDir, instanceGenDir, "/workspace", "/home/devuser", cfg)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error preparing agent state: %v\n", err)
		os.Exit(1)
	}
	if len(cfg.Skills) > 0 && envPath == "" {
		spinner.Stop()
		fmt.Fprintln(os.Stderr, "Error preparing skills: registered skills require image = \"sandbox-local\"")
		os.Exit(1)
	}
	skillMounts, err := prepareSkillMounts(cfg, envPath, "/home/devuser", agentState)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error preparing skills: %v\n", err)
		os.Exit(1)
	}

	// Create per-sandbox network (remove stale one first if it exists without containers)
	spinner.Status("creating network...")
	run("docker", "rm", "-f", legacyTapName)
	run("docker", "network", "rm", networkName) // ignore error - may not exist
	if err := run("docker", "network", "create", "--ipv6", networkName); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error creating network %s: %v\n", networkName, err)
		os.Exit(1)
	}

	// Start per-sandbox envoy
	spinner.Status("starting envoy...")
	envoyArgs := []string{"run", "-d",
		"--name", envoyName,
		"--restart", "unless-stopped",
		"--network", networkName,
		"--network-alias", "envoy",
		"--ulimit", "nofile=65536:65536",
		"-v", scriptDir + "/generated/certs/ca.crt:/certs/ca.crt:ro",
		"-v", scriptDir + "/generated/certs/ca.key:/certs/ca.key:ro",
		"-v", filepath.Join(instanceGenDir, "domains.json") + ":/etc/envoy/domains.json:ro",
		"-v", filepath.Join(instanceGenDir, "envoy.json") + ":/etc/envoy/envoy.json:ro",
		"-v", scriptDir + "/envoy-entrypoint.sh:/entrypoint.sh:ro",
		"-v", scriptDir + "/generated/dns-responder:/usr/local/bin/dns-responder:ro",
		"-v", instanceLogsDir + ":/var/log/adev",
	}
	if cfg.TapEnabled {
		envoyArgs = append(envoyArgs,
			"-v", tapSourceRuntimeDir(scriptDir, slug)+":/run/adev-tap",
		)
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

	// Connect envoy to vault network (local only)
	if !cfg.Vault.IsRemote() {
		if err := run("docker", "network", "connect", "agent-creds_agent-creds", envoyName); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error connecting envoy to vault network: %v\n", err)
			os.Exit(1)
		}
	}

	// An upstream may live on another isolated Docker network. Attach only
	// Envoy: the sandbox remains unable to resolve or connect to the origin
	// directly, preserving the proxy authorization boundary.
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
	if cfg.TapEnabled {
		if err := registerTapSource(scriptDir, workDir, slug); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error attaching traffic tap: %v\n", err)
			cleanup()
			os.Exit(1)
		}
	}
	tapUIPort, err := ensureGlobalTap(scriptDir, slug, spinner)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error starting traffic tap: %v\n", err)
		cleanup()
		os.Exit(1)
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
	var browserFwd *ForwardState
	cdpFwds := make(map[int]*ForwardState) // keyed by Chrome CDP port
	cdpTCPPorts := make(map[int]int)       // Chrome CDP port → allocated TCP port

	// Allocate TCP port for browser forwarding
	tcpBrowserPort := AllocateTCPBrowserPort(slug)
	containerCallbackForwarder := func(port string) error {
		go proxyLocalPort(sandboxName, port)
		return nil
	}

	// Start browser-forward server (TCP, tcp-bridge creates Unix socket in container)
	if cfg.Sandbox.UseHostBrowserEnabled() {
		spinner.Status("starting browser forward...")
		browserFwd, err = startBrowserForwardTCP(gatewayIP, tcpBrowserPort, cfg.BrowserTargets, containerCallbackForwarder)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: browser forwarding disabled: %v\n", err)
		}
	}

	// Start CDP forwarders (one per unique Chrome CDP port)
	if cfg.Sandbox.UseHostBrowserCDPEnabled() {
		ports := CDPPorts(cfg.CDPTargets)
		for _, cdpPort := range ports {
			tcpPort := AllocateTCPCDPPort(slug, cdpPort)
			cdpTCPPorts[cdpPort] = tcpPort
			spinner.Status(fmt.Sprintf("starting CDP forward :%d...", cdpPort))
			fwd, err := startCDPForwardTCP(gatewayIP, tcpPort, cdpPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: CDP forwarding for port %d disabled: %v\n", cdpPort, err)
				continue
			}
			cdpFwds[cdpPort] = fwd
		}
	}

	// Track current upstream configs for hot-reload detection
	currentHosts := sortedUpstreamKeys(cfg.Upstream)
	currentUpstreams := copyUpstreamMap(cfg.Upstream)

	// Watch the selected project policy for changes.
	configPath, configExists, _ := projectConfigPath(workDir)
	if configExists {
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
							newCfg, err = applyGlobalTapConfig(newCfg)
							if err != nil {
								continue
							}

							fwdMu.Lock()
							// Handle browser forwarding changes
							wantBrowser := newCfg.Sandbox.UseHostBrowserEnabled()
							haveBrowser := browserFwd != nil
							if wantBrowser && !haveBrowser {
								browserFwd, _ = startBrowserForwardTCP(gatewayIP, tcpBrowserPort, newCfg.BrowserTargets, containerCallbackForwarder)
							} else if !wantBrowser && haveBrowser {
								browserFwd.Close()
								browserFwd = nil
							}

							// Handle CDP forwarding changes (diff port sets)
							wantCDP := newCfg.Sandbox.UseHostBrowserCDPEnabled()
							if wantCDP {
								newPorts := CDPPorts(newCfg.CDPTargets)
								newPortSet := make(map[int]bool)
								for _, p := range newPorts {
									newPortSet[p] = true
								}
								// Remove forwarders for ports no longer needed
								for p, fwd := range cdpFwds {
									if !newPortSet[p] {
										fwd.Close()
										delete(cdpFwds, p)
										delete(cdpTCPPorts, p)
									}
								}
								// Add forwarders for new ports
								for _, p := range newPorts {
									if _, exists := cdpFwds[p]; !exists {
										tcpPort := AllocateTCPCDPPort(slug, p)
										cdpTCPPorts[p] = tcpPort
										if fwd, err := startCDPForwardTCP(gatewayIP, tcpPort, p); err == nil {
											cdpFwds[p] = fwd
										}
									}
								}
							} else {
								// CDP disabled — close all
								for p, fwd := range cdpFwds {
									fwd.Close()
									delete(cdpFwds, p)
									delete(cdpTCPPorts, p)
								}
							}
							fwdMu.Unlock()

							// Handle upstream changes: regenerate configs and restart envoy
							newHosts := sortedUpstreamKeys(newCfg.Upstream)
							routingChanged := !slices.Equal(newHosts, currentHosts)
							if !routingChanged {
								for host, upstream := range newCfg.Upstream {
									if upstreamChanged(currentUpstreams[host], upstream) {
										routingChanged = true
										break
									}
								}
							}
							if routingChanged {
								newGen, err := NewGenerator(scriptDir, instanceGenDir, newCfg)
								if err == nil {
									if err := newGen.Generate(); err == nil {
										run("docker", "restart", envoyName)
										currentHosts = newHosts
									}
								}
							}

							// Handle credential/caveat changes: re-mint affected tokens
							remintTokens(newCfg, scriptDir, instanceGenDir, currentUpstreams)
							currentUpstreams = copyUpstreamMap(newCfg.Upstream)
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
		"--tmpfs", "/run:exec", // s6-svscan creates service dirs here
		"--tmpfs", "/tmp:exec", // dropbear host key, ready signal, etc.
	}
	// Network configuration depends on runtime:
	// - gvisor (default): connect directly to network, sandbox-net uses --network=host
	// - runc: share network namespace with sandbox-net container
	if useHostNetfilter {
		args = append(args, "--network", networkName)
		// gVisor doesn't work with Docker's embedded DNS (127.0.0.11)
		// Write placeholder resolv.conf (overwritten with envoy IP after sandbox starts)
		// Uses 127.0.0.1 as fail-safe so DNS fails rather than bypasses during the brief window
		resolvConf := filepath.Join(instanceGenDir, "resolv.conf")
		os.WriteFile(resolvConf, []byte("nameserver 127.0.0.1\n"), 0644)
		args = append(args, "-v", resolvConf+":/etc/resolv.conf:ro")
	} else {
		args = append(args, "--network=container:"+containerName)
	}
	args = append(args, "-v", workDir+":/workspace")
	if cfg.Sandbox.Agent == "claude" {
		args = append(args, "-e", "CLAUDE_CONFIG_DIR=/home/devuser/.claude")
	}
	args = append(args, agentState.dockerArgs()...)
	args = append(args, skillDockerArgs(skillMounts)...)
	args = append(args,
		// Mount agent-creds CA so proxy TLS is trusted system-wide
		"-v", scriptDir+"/generated/certs/ca.crt:/etc/ssl/agent-creds-ca.crt:ro",
		// Mount entrypoint and binaries so changes take effect without image rebuild
		"-v", scriptDir+"/claude-dev/entrypoint.sh:/entrypoint.sh:ro",
		"-v", scriptDir+"/generated/aenv:/usr/local/bin/aenv:ro",
		"-v", scriptDir+"/generated/cdp-proxy:/usr/local/bin/cdp-proxy:ro",
		"-v", scriptDir+"/generated/tcp-bridge:/usr/local/bin/tcp-bridge:ro",
		// SSH public key for passwordless login (mounted to /etc/adev/ so tmpfs on /tmp doesn't hide it)
		"-v", sshPubKeyPath+":/etc/adev/pubkey:ro",
		// Network activity logs (DNS + HTTP access log, written by envoy container)
		"-v", instanceLogsDir+":/etc/adev/logs:ro",
	)
	// Mount sandbox.env as /workspace/.env (read-only) when generated
	if sandboxEnvGenerated {
		sandboxEnvPath := filepath.Join(instanceGenDir, "sandbox.env")
		args = append(args, "-v", sandboxEnvPath+":/workspace/.env:ro")
	}
	if hasCredentialFileEntries(tokenEntries) {
		args = append(args, "-v", credentialProjectionDir(instanceGenDir)+":/run/credentials:ro")
	}
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
	if len(cdpFwds) > 0 {
		// CDP_PORT_MAP=9222:51234,9333:51235 (chrome_port:tcp_port pairs)
		var pairs []string
		for _, cdpPort := range CDPPorts(cfg.CDPTargets) {
			if tcpPort, ok := cdpTCPPorts[cdpPort]; ok {
				pairs = append(pairs, fmt.Sprintf("%d:%d", cdpPort, tcpPort))
			}
		}
		args = append(args, "-e", "CDP_PORT_MAP="+strings.Join(pairs, ","))
	}
	args = append(args, credsMounts...)
	args = append(args, gitConfigMounts...)
	// Mount merged config for aenv display (includes agent + plugin upstreams),
	// and the raw project policy in the workspace under its source name.
	mergedConfigToml := filepath.Join(instanceGenDir, "merged-config.toml")
	projectConfig, projectConfigExists, _ := projectConfigPath(workDir)
	if fileExists(mergedConfigToml) {
		args = append(args, "-v", mergedConfigToml+":/etc/aenv/agent-creds.toml:ro")
	} else if projectConfigExists {
		args = append(args, "-v", projectConfig+":/etc/aenv/agent-creds.toml:ro")
	}
	if projectConfigExists {
		args = append(args, "-v", projectConfig+":/workspace/"+filepath.Base(projectConfig)+":ro")
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
	var projectEnvNames []string
	for _, env := range cfg.Env {
		value := resolveEnvValueFrom(env.Value, workDir)
		if value != "" {
			args = append(args, "-e", env.Name+"="+value)
			projectEnvNames = append(projectEnvNames, env.Name)
		}
	}
	if len(projectEnvNames) > 0 {
		args = append(args, "-e", "ADEV_PROJECT_ENV_NAMES="+strings.Join(projectEnvNames, " "))
	}

	// Resource limits
	if cfg.Sandbox.Memory != "" {
		args = append(args, "--memory", cfg.Sandbox.Memory)
	}
	if cfg.Sandbox.CPUs != "" {
		args = append(args, "--cpus", cfg.Sandbox.CPUs)
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

		// Write resolv.conf pointing to envoy (dns-responder runs there)
		resolvConf := filepath.Join(instanceGenDir, "resolv.conf")
		os.WriteFile(resolvConf, []byte(fmt.Sprintf("nameserver %s\n", envoyIP)), 0644)

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
	if tapUIPort != 0 {
		fmt.Printf("Traffic tap: http://127.0.0.1:%d\n", tapUIPort)
	}
	// Start background discharge refresh for credentialed upstreams
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	defer refreshCancel()
	if len(tokenEntries) > 0 {
		startDischargeRefresh(refreshCtx, workDir, scriptDir, instanceGenDir)
	}

	// Start denial monitoring
	startDenialMonitor(refreshCtx, cfg.Vault, cfg.Upstream)

	// SSH into the sandbox (dropbear runs as devuser on port 2222)
	sshArgs := []string{
		"-i", sshKeyPath,
		"-p", "2222",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=10",
		"devuser@" + sshIP,
	}
	// The session runs the resolved entrypoint (agent profile default,
	// project [sandbox] override). Empty entrypoint keeps the plain
	// login shell.
	if cfg.Entrypoint != "" {
		sshArgs = append(sshArgs, "-t", "bash", "-lc", fmt.Sprintf("%q", cfg.Entrypoint))
	}
	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Run()
	// No cleanup: use 'adev stop' to stop.
}

// TokenEntry holds a minted combined token for one sandbox delivery target.
type TokenEntry struct {
	EnvVar         string // legacy environment-variable delivery
	CredentialFile string // basename projected under /run/credentials
	Combined       string // authz,discharge combined token
	Host           string // upstream host
}

func upstreamTokenEnv(upstream UpstreamConfig, info *CredentialInfo) string {
	if env := strings.TrimSpace(upstream.Env); env != "" {
		return env
	}
	if info != nil && len(info.EnvVars) > 0 {
		return info.EnvVars[0]
	}
	return ""
}

// mintTokens mints tokens for all credentialed upstreams.
// It returns an error instead of a partial result: all sandbox engines share
// the same fail-closed credential bootstrap.
func mintTokens(cfg ProjectConfig, instanceGenDir string, spinner *Spinner) ([]TokenEntry, map[string]*CredentialInfo, error) {
	authzDir, err := prepareCredentialAuthzDir(instanceGenDir)
	if err != nil {
		return nil, nil, err
	}

	var tokens []TokenEntry
	infos := make(map[string]*CredentialInfo)

	for _, host := range sortedUpstreamKeys(cfg.Upstream) {
		upstream := cfg.Upstream[host]
		if !upstream.MintsToken() {
			continue
		}

		// Step 1: Get credential metadata
		if spinner != nil {
			spinner.Status(fmt.Sprintf("minting tokens... %s", host))
		}
		info, err := vaultSSHInfo(cfg.Vault, upstream.Credential)
		if err != nil {
			return nil, nil, fmt.Errorf("reading credential metadata for %s: %w", host, err)
		}
		infos[host] = info
		if upstream.Authorization != "" && info.Authorization == nil {
			return nil, nil, fmt.Errorf("authorization.%s: credential %s does not publish a provider authorization schema", upstream.Authorization, upstream.Credential)
		}

		// Determine primary env var name
		envVar := upstreamTokenEnv(upstream, info)
		if upstream.CredentialFile == "" && envVar == "" {
			return nil, nil, fmt.Errorf("credential for %s declares no environment variable", host)
		}

		// Step 2: Check for cached authz token
		cachePath := filepath.Join(authzDir, host+".token")
		var authzToken string
		if data, err := os.ReadFile(cachePath); err == nil {
			authzToken = strings.TrimSpace(string(data))
		}

		// Step 3: Mint if no cache
		if authzToken == "" {
			authzToken, err = vaultSSHMint(cfg.Vault, upstream.Credential, host, upstream.Methods, upstream.Paths, upstream.Authorization != "", upstream.OmitHostCaveat)
			if err != nil {
				return nil, nil, fmt.Errorf("minting %s: %w", host, err)
			}
			// Step 4: Cache authz token
			if err := os.WriteFile(cachePath, []byte(authzToken+"\n"), 0600); err != nil {
				return nil, nil, fmt.Errorf("caching token for %s: %w", host, err)
			}
		}

		// Step 5: Get discharge (retry with fresh token if cached token fails)
		discharge, err := vaultSSHDischarge(cfg.Vault, authzToken, upstream.AuthorizationConstraint)
		if err != nil && fileExists(cachePath) {
			// Cached token may be stale (e.g., vault key rotated) — delete and re-mint
			os.Remove(cachePath)
			authzToken, err = vaultSSHMint(cfg.Vault, upstream.Credential, host, upstream.Methods, upstream.Paths, upstream.Authorization != "", upstream.OmitHostCaveat)
			if err != nil {
				return nil, nil, fmt.Errorf("re-minting %s: %w", host, err)
			}
			if err := os.WriteFile(cachePath, []byte(authzToken+"\n"), 0600); err != nil {
				return nil, nil, fmt.Errorf("caching refreshed token for %s: %w", host, err)
			}
			discharge, err = vaultSSHDischarge(cfg.Vault, authzToken, upstream.AuthorizationConstraint)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("discharging %s: %w", host, err)
		}

		// Step 6: Store combined token
		combined := authzToken + "," + discharge
		entry, err := newTokenEntry(host, upstream, envVar, combined, time.Now())
		if err != nil {
			return nil, nil, fmt.Errorf("materializing %s: %w", host, err)
		}
		tokens = append(tokens, entry)

		fmt.Fprintf(os.Stderr, "  %s → %s ✓\n", host, entry.deliveryName())
	}

	return tokens, infos, nil
}

func sortedUpstreamKeys(m map[string]UpstreamConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortDomains(keys)
	return keys
}

// startDischargeRefresh launches a background goroutine that refreshes all
// sandbox credentials every 45 minutes. Each pass reloads project config and
// atomically replaces each file- and environment-delivered capability.
func startDischargeRefresh(ctx context.Context, workDir, scriptDir, instanceGenDir string) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(45 * time.Minute):
			}

			if err := refreshSandboxCredentialEnv(workDir, scriptDir, instanceGenDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: credential refresh failed: %v (current credentials remain usable until expiry)\n", err)
			}
		}
	}()
}

// refreshSandboxCredentialEnv re-discharges every configured authorization
// and atomically replaces the environment file mounted into a sandbox. Long-
// lived bwrap sessions invoke this from a host-side companion process, because
// a process environment cannot be changed after the sandbox starts.
func refreshSandboxCredentialEnv(workDir, scriptDir, instanceGenDir string) error {
	cfg, err := LoadProjectConfigWithPlugins(workDir, scriptDir)
	if err != nil {
		return fmt.Errorf("loading sandbox config: %w", err)
	}
	tokens, infos, err := mintTokens(cfg, instanceGenDir, nil)
	if err != nil {
		return err
	}
	if err := materializeCredentialFiles(instanceGenDir, tokens); err != nil {
		return err
	}
	var vaultConfigYAML []byte
	if staticEnvNeedsSecrets(cfg.StaticEnv) {
		vaultConfigYAML, err = decryptVaultConfigYAML()
		if err != nil {
			return fmt.Errorf("decrypting static environment: %w", err)
		}
	}
	staticResolved, err := resolveStaticEnvForConsole(
		cfg.StaticEnv, vaultConfigYAML, scriptDir)
	if err != nil {
		return fmt.Errorf("resolving static environment: %w", err)
	}
	return generateSandboxEnv(
		instanceGenDir, shapeTokens(tokens, infos), staticResolved)
}

// runCredentialRefresh is an internal host-side companion for bwrap. The
// launcher gives it a parent-death signal, so it cannot outlive the sandbox
// session whose mounted credential environment it renews.
func runCredentialRefresh(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr,
			"Usage: adev _credential-refresh <work-dir> <instance-dir>")
		os.Exit(2)
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential refresh: resolving adev: %v\n", err)
		os.Exit(1)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential refresh: resolving adev: %v\n", err)
		os.Exit(1)
	}
	scriptDir := filepath.Dir(filepath.Dir(exe))
	workDir := args[0]
	instanceGenDir := args[1]

	ctx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(45 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := refreshSandboxCredentialEnv(
				workDir, scriptDir, instanceGenDir); err != nil {
				fmt.Fprintf(os.Stderr,
					"credential refresh failed: %v (current discharge remains usable until its expiry)\n",
					err)
			}
		}
	}
}

// sortDomains sorts domains so subdomains are grouped under their parent.
// e.g. github.com, api.github.com, api.stripe.com, stripe.com
func sortDomains(domains []string) {
	sort.Slice(domains, func(i, j int) bool {
		return reverseDomain(domains[i]) < reverseDomain(domains[j])
	})
}

// copyUpstreamMap returns a shallow copy of the upstream config map.
func copyUpstreamMap(m map[string]UpstreamConfig) map[string]UpstreamConfig {
	c := make(map[string]UpstreamConfig, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// upstreamChanged returns true if the transport, credential, or caveats differ.
func upstreamChanged(old, new UpstreamConfig) bool {
	if old.Scheme != new.Scheme || old.Port != new.Port || old.Address != new.Address || old.Network != new.Network || old.Env != new.Env || old.CredentialFile != new.CredentialFile {
		return true
	}
	if old.Credential != new.Credential || old.Policy != new.Policy {
		return true
	}
	if old.Authorization != new.Authorization || old.OmitHostCaveat != new.OmitHostCaveat || !reflect.DeepEqual(old.AuthorizationConstraint, new.AuthorizationConstraint) {
		return true
	}
	if !slices.Equal(old.Methods, new.Methods) {
		return true
	}
	if !slices.Equal(old.Paths, new.Paths) {
		return true
	}
	return false
}

// remintTokens detects credential/caveat changes and re-mints tokens for affected upstreams.
// Unchanged upstreams retain their existing tokens.
func remintTokens(newCfg ProjectConfig, scriptDir, instanceGenDir string, oldUpstreams map[string]UpstreamConfig) {
	authzDir := credentialAuthzDir(instanceGenDir)

	// Determine which hosts need re-minting
	remintSet := make(map[string]struct{})
	for host, newUp := range newCfg.Upstream {
		if !newUp.MintsToken() {
			continue
		}
		oldUp, existed := oldUpstreams[host]
		if !existed || upstreamChanged(oldUp, newUp) {
			remintSet[host] = struct{}{}
		}
	}
	for host, oldUp := range oldUpstreams {
		newUp, exists := newCfg.Upstream[host]
		if oldUp.MintsToken() && (!exists || !newUp.MintsToken() || upstreamChanged(oldUp, newUp)) {
			remintSet[host] = struct{}{}
		}
	}

	if len(remintSet) == 0 {
		// No credential changes — check if we still have credentialed upstreams for env regen
		return
	}

	// Delete old cache and re-mint for changed hosts
	for host := range remintSet {
		cachePath := filepath.Join(authzDir, host+".token")
		os.Remove(cachePath)
		fmt.Fprintf(os.Stderr, "  re-minting %s (config changed)\n", host)
	}

	// Re-mint all credentialed upstreams (changed ones lost their cache, unchanged use cache)
	var tokens []TokenEntry
	for host, upstream := range newCfg.Upstream {
		if !upstream.MintsToken() {
			continue
		}

		info, err := vaultSSHInfo(newCfg.Vault, upstream.Credential)
		if err != nil {
			continue
		}
		envVar := upstreamTokenEnv(upstream, info)
		if upstream.CredentialFile == "" && envVar == "" {
			continue
		}

		// Check cache (unchanged upstreams still have their cached token)
		cachePath := filepath.Join(authzDir, host+".token")
		var authzToken string
		if data, err := os.ReadFile(cachePath); err == nil {
			authzToken = strings.TrimSpace(string(data))
		}

		if authzToken == "" {
			authzToken, err = vaultSSHMint(newCfg.Vault, upstream.Credential, host, upstream.Methods, upstream.Paths, upstream.Authorization != "", upstream.OmitHostCaveat)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: re-mint %s failed: %v\n", host, err)
				continue
			}
			os.WriteFile(cachePath, []byte(authzToken+"\n"), 0600)
		}

		discharge, err := vaultSSHDischarge(newCfg.Vault, authzToken, upstream.AuthorizationConstraint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: discharge %s failed: %v\n", host, err)
			continue
		}

		entry, err := newTokenEntry(host, upstream, envVar, authzToken+","+discharge, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: materializing %s failed: %v\n", host, err)
			continue
		}
		tokens = append(tokens, entry)
	}

	if err := materializeCredentialFiles(instanceGenDir, tokens); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: hot-reload credential file update failed: %v\n", err)
	}

	// Regenerate sandbox.env
	infos := make(map[string]*CredentialInfo)
	for _, e := range tokens {
		if info, err := vaultSSHInfo(newCfg.Vault, newCfg.Upstream[e.Host].Credential); err == nil {
			infos[e.Host] = info
		}
	}
	shaped := shapeTokens(tokens, infos)

	vaultConfigYAML, _ := decryptVaultConfigYAML()
	staticResolved, err := resolveStaticEnvForConsole(newCfg.StaticEnv, vaultConfigYAML, scriptDir)
	if err != nil {
		staticResolved = make(map[string]string)
	}

	if err := generateSandboxEnv(instanceGenDir, shaped, staticResolved); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: hot-reload env update failed: %v\n", err)
	}
}

// denialEntry represents a denial from the vault API.
type denialEntry struct {
	Method string  `json:"method"`
	Host   string  `json:"host"`
	Path   string  `json:"path"`
	Reason *string `json:"reason,omitempty"`
}

// startDenialMonitor polls the vault HTTP API every 30 seconds for new denials
// and prints a warning when denials are detected. Stops when ctx is cancelled.
func startDenialMonitor(ctx context.Context, vault VaultConfig, upstreams map[string]UpstreamConfig) {
	baseURL := vault.HTTP
	if baseURL == "" {
		if vault.IsRemote() {
			baseURL = "https://" + vault.Host
		} else {
			baseURL = "http://localhost:8033"
		}
	}

	go func() {
		lastCheck := time.Now()
		client := &http.Client{Timeout: 5 * time.Second}

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}

			u, err := url.Parse(baseURL + "/api/denials")
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set("since", lastCheck.UTC().Format(time.RFC3339))
			u.RawQuery = q.Encode()
			now := time.Now()

			resp, err := client.Get(u.String())
			if err != nil {
				continue
			}

			var denials []denialEntry
			json.NewDecoder(resp.Body).Decode(&denials)
			resp.Body.Close()

			visible := denials[:0]
			for _, denial := range denials {
				if _, ok := upstreams[denial.Host]; ok {
					visible = append(visible, denial)
				}
			}

			if len(visible) > 0 {
				// Group by host+path+reason for concise output
				fmt.Fprintf(os.Stderr, "\n⚠ %d access denial(s):\n", len(visible))
				for _, d := range visible {
					reason := ""
					if d.Reason != nil {
						reason = " -- " + *d.Reason
					}
					fmt.Fprintf(os.Stderr, "  %s %s%s%s\n", d.Method, d.Host, d.Path, reason)
				}
			}

			lastCheck = now
		}
	}()
}

// reverseDomain reverses domain labels for sorting: "api.stripe.com" → "com.stripe.api"
func reverseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	return strings.Join(parts, ".")
}
