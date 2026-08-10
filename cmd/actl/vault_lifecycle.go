package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const localVaultHealthURL = "http://127.0.0.1:8033/health"

func runVaultLifecycle(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "start":
		secretsStart(args[1:], false)
	case "stop":
		secretsStop(args[1:])
	case "restart":
		secretsStart(args[1:], true)
	default:
		return false
	}
	return true
}

func secretsStart(args []string, restart bool) {
	command := "start"
	if restart {
		command = "restart"
	}
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "Usage: actl vault %s\n", command)
		os.Exit(1)
	}
	if !restart && localVaultHealthy() {
		fmt.Println("Vault is already running and healthy.")
		return
	}

	config, err := runSops("--decrypt", vaultYAMLPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}
	composeArgs := []string{
		"up", "-d", "--build", "--quiet-pull", "--force-recreate", "vault",
	}
	if err := runVaultCompose(config, composeArgs...); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Vault: %v\n", err)
		os.Exit(1)
	}
	if err := waitForLocalVault(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Vault: %v\n", err)
		os.Exit(1)
	}
	if restart {
		fmt.Println("Vault restarted and healthy.")
	} else {
		fmt.Println("Vault started and healthy.")
	}
}

func secretsStop(args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "Usage: actl vault stop")
		os.Exit(1)
	}
	if err := runVaultCompose(nil, "stop", "vault"); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping Vault: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Vault stopped.")
}

func runVaultCompose(config []byte, args ...string) error {
	root, err := agentCredsRoot()
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Dir = root
	cmd.Env = os.Environ()
	if config != nil {
		cmd.Env = replaceEnvironment(
			cmd.Env, "AGENT_CREDS_VAULT_CONFIG", string(config))
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func agentCredsRoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("AGENT_CREDS_ROOT")); configured != "" {
		if fileExists(filepath.Join(configured, "docker-compose.yml")) {
			return configured, nil
		}
		return "", fmt.Errorf(
			"AGENT_CREDS_ROOT has no docker-compose.yml: %s", configured)
	}
	if executable, err := os.Executable(); err == nil {
		if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
			executable = resolved
		}
		candidate := filepath.Dir(filepath.Dir(executable))
		if fileExists(filepath.Join(candidate, "docker-compose.yml")) {
			return candidate, nil
		}
	}
	candidate, err := os.Getwd()
	if err == nil {
		for {
			if fileExists(filepath.Join(candidate, "docker-compose.yml")) {
				return candidate, nil
			}
			parent := filepath.Dir(candidate)
			if parent == candidate {
				break
			}
			candidate = parent
		}
	}
	return "", fmt.Errorf("cannot locate the agent-creds checkout")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func replaceEnvironment(environment []string, name, value string) []string {
	prefix := name + "="
	result := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}

func localVaultHealthy() bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	response, err := client.Get(localVaultHealthURL)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func waitForLocalVault() error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if localVaultHealthy() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	root, rootErr := agentCredsRoot()
	if rootErr != nil {
		return fmt.Errorf("Vault did not become healthy: %w", rootErr)
	}
	cmd := exec.Command("docker", "compose", "logs", "--tail=80", "vault")
	cmd.Dir = root
	logs, err := cmd.CombinedOutput()
	if err == nil && len(logs) > 0 {
		return fmt.Errorf("Vault did not become healthy\n%s", strings.TrimSpace(string(logs)))
	}
	return fmt.Errorf("Vault did not become healthy")
}
