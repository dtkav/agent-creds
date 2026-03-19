package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// EndpointInfo describes an allowed endpoint from credential capabilities.
type EndpointInfo struct {
	Methods     []string `json:"methods"`
	Paths       []string `json:"paths"`
	Description string   `json:"description,omitempty"`
}

// CredentialInfo holds metadata returned by vault-ssh info command.
type CredentialInfo struct {
	Type      string         `json:"type"`
	EnvVars   []string       `json:"env_vars,omitempty"`
	Hosts     []string       `json:"hosts,omitempty"`
	Endpoints []EndpointInfo `json:"endpoints,omitempty"`
}

// vaultSSHAddr returns the SSH address for the vault.
// Uses VaultConfig.SSH if set, otherwise defaults to localhost:2222.
func vaultSSHAddr(cfg VaultConfig) string {
	if cfg.SSH != "" {
		return cfg.SSH
	}
	return "localhost:2222"
}

// vaultSSHClient creates an SSH client connection to vault-ssh.
func vaultSSHClient(cfg VaultConfig) (*ssh.Client, error) {
	keyPath := "generated/sandbox-key"
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key %s: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key %s: %w", keyPath, err)
	}

	config := &ssh.ClientConfig{
		User: "agent",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := vaultSSHAddr(cfg)
	// Add default port if not specified
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":2222"
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("connecting to vault-ssh at %s: %w", addr, err)
	}

	return client, nil
}

// vaultSSHRun executes a command on vault-ssh and returns the output.
func vaultSSHRun(cfg VaultConfig, args ...string) (string, error) {
	client, err := vaultSSHClient(cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("creating SSH session: %w", err)
	}
	defer session.Close()

	cmd := strings.Join(args, " ")
	output, err := session.CombinedOutput(cmd)
	result := strings.TrimSpace(string(output))

	if err != nil {
		return "", fmt.Errorf("vault-ssh command %q failed: %s", cmd, result)
	}

	return result, nil
}

// vaultSSHMint mints an authorization token for the given host with optional method/path caveats.
func vaultSSHMint(cfg VaultConfig, host string, methods, paths []string) (string, error) {
	args := []string{"mint", host, "--require-attestation"}
	if len(methods) > 0 {
		args = append(args, "--methods", strings.Join(methods, ","))
	}
	if len(paths) > 0 {
		args = append(args, "--paths", strings.Join(paths, ","))
	}

	output, err := vaultSSHRun(cfg, args...)
	if err != nil {
		return "", err
	}

	// Output should be a single token line
	if strings.HasPrefix(output, "Error:") {
		return "", fmt.Errorf("vault-ssh mint: %s", output)
	}

	return output, nil
}

// vaultSSHDischarge gets a discharge token for an authorization token.
func vaultSSHDischarge(cfg VaultConfig, authzToken string) (string, error) {
	output, err := vaultSSHRun(cfg, "discharge", authzToken)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(output, "Error:") {
		return "", fmt.Errorf("vault-ssh discharge: %s", output)
	}

	return output, nil
}

// vaultSSHInfo gets credential metadata for a credential path.
func vaultSSHInfo(cfg VaultConfig, credPath string) (*CredentialInfo, error) {
	output, err := vaultSSHRun(cfg, "info", credPath)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(output, "Error:") {
		return nil, fmt.Errorf("vault-ssh info: %s", output)
	}

	var info CredentialInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		return nil, fmt.Errorf("parsing info response: %w", err)
	}

	return &info, nil
}
