package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runSSH(cfg ProjectConfig, args []string) {
	addr := cfg.Vault.SSHAddr()
	if addr == "" {
		// Default to localhost:2222 for local dev
		addr = "localhost:2222"
	}

	host := addr
	port := "22"
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		host = addr[:idx]
		port = addr[idx+1:]
	}

	sshArgs := []string{
		"-o", "StrictHostKeyChecking=no",
		"-p", port,
		host,
	}
	sshArgs = append(sshArgs, args...)

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
		os.Exit(1)
	}
}
