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

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: arun <command> [args...]")
		os.Exit(1)
	}

	// Get script directory (go up from bin/)
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe))

	// Generate unique instance name
	slug := fmt.Sprintf("arun-%d", os.Getpid())
	networkName := "adev-" + slug
	envoyName := "adev-" + slug + "-envoy"
	netName := "adev-" + slug + "-net"
	sandboxName := "adev-" + slug + "-sandbox"

	cleanup := func() {
		run("docker", "rm", "-f", sandboxName)
		run("docker", "rm", "-f", netName)
		run("docker", "rm", "-f", envoyName)
		run("docker", "network", "rm", networkName)
	}

	// Handle cleanup on interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cleanup()
		os.Exit(1)
	}()

	// Create network
	if err := run("docker", "network", "create", "--ipv6", networkName); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating network: %v\n", err)
		os.Exit(1)
	}

	// Start envoy
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
		fmt.Fprintf(os.Stderr, "Error starting envoy: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	// Connect envoy to authz network
	run("docker", "network", "connect", "agent-creds_agent-creds", envoyName)

	// Start sandbox-net
	if err := run("docker", "run", "-d", "--rm",
		"--name", netName,
		"--network", networkName,
		"--cap-add=NET_ADMIN",
		"sandbox-net"); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting sandbox-net: %v\n", err)
		cleanup()
		os.Exit(1)
	}

	time.Sleep(500 * time.Millisecond)

	// Build sandbox args
	workDir, _ := os.Getwd()
	args := []string{"run", "--rm",
		"--name", sandboxName,
		"--network=container:" + netName,
		"-v", workDir + ":/workspace",
		"-w", "/workspace",
	}

	// Mount creds if available
	credsDir := filepath.Join(scriptDir, "creds")
	if _, err := os.Stat(credsDir); err == nil {
		args = append(args, "--mount", "type=bind,source="+credsDir+",target=/creds,readonly,bind-propagation=rslave")
	}

	// Add TTY flags if available
	stdinInfo, _ := os.Stdin.Stat()
	stdinIsTTY := (stdinInfo.Mode() & os.ModeCharDevice) != 0
	stdoutInfo, _ := os.Stdout.Stat()
	stdoutIsTTY := (stdoutInfo.Mode() & os.ModeCharDevice) != 0
	if stdinIsTTY && stdoutIsTTY {
		args = append(args, "-it")
	} else if stdinIsTTY {
		args = append(args, "-i")
	}

	args = append(args, "sandbox")
	args = append(args, os.Args[1:]...)

	// Run command
	cmd := exec.Command("docker", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	cleanup()
	os.Exit(exitCode)
}
