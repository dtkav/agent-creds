package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func decryptVaultConfigYAML() ([]byte, error) {
	cmd := exec.Command("actl", "vault", "show")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, commandError(err, stderr.Bytes())
	}
	return out, nil
}

func exportLegacyVaultEnv() bool {
	out, err := exec.Command("actl", "vault", "export").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k != "" {
			os.Setenv(k, v)
		}
	}
	return os.Getenv("MACAROON_SIGNING_KEY") != ""
}

func setVaultComposeSecret(vaultYAML []byte) {
	if len(vaultYAML) == 0 {
		os.Setenv("AGENT_CREDS_VAULT_CONFIG", "credentials: {}\n")
		return
	}
	os.Setenv("AGENT_CREDS_VAULT_CONFIG", string(vaultYAML))
}

func validateVaultStartupConfig(vaultYAML []byte) error {
	if len(vaultYAML) == 0 {
		return validateSigningKey(os.Getenv("MACAROON_SIGNING_KEY"), "MACAROON_SIGNING_KEY")
	}

	signingKey, err := vaultSigningKey(vaultYAML)
	if err != nil {
		return err
	}
	if signingKey == "" {
		return validateSigningKey(os.Getenv("MACAROON_SIGNING_KEY"), "MACAROON_SIGNING_KEY")
	}
	return validateSigningKey(signingKey, "signing_key")
}

func vaultSigningKey(vaultYAML []byte) (string, error) {
	var doc struct {
		Secrets    map[string]map[string]string `yaml:"secrets"`
		SigningKey yaml.Node                    `yaml:"signing_key"`
	}
	if err := yaml.Unmarshal(vaultYAML, &doc); err != nil {
		return "", fmt.Errorf("parsing vault config: %w", err)
	}
	return resolveVaultScalar(doc.SigningKey, doc.Secrets, "signing_key")
}

func resolveVaultScalar(node yaml.Node, secrets map[string]map[string]string, name string) (string, error) {
	switch node.Kind {
	case 0:
		return "", nil
	case yaml.ScalarNode:
		return strings.TrimSpace(node.Value), nil
	case yaml.MappingNode:
		if len(node.Content) == 2 && node.Content[0].Value == "$secret" {
			val, err := lookupVaultSecret(node.Content[1].Value, secrets)
			if err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			return strings.TrimSpace(val), nil
		}
	}
	return "", fmt.Errorf("%s must be a string or $secret reference", name)
}

func validateSigningKey(value, name string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is empty", name)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s is not valid base64", name)
	}
	if len(decoded) < 32 {
		return fmt.Errorf("%s must decode to at least 32 bytes", name)
	}
	return nil
}

func resolveStaticEnvForConsole(staticEnv map[string]interface{}, vaultYAML []byte, scriptDir string) (map[string]string, error) {
	if len(vaultYAML) > 0 {
		return resolveStaticEnvFromYAML(staticEnv, vaultYAML)
	}
	return resolveStaticEnv(staticEnv, filepath.Join(scriptDir, "generated", "vault.yaml"))
}

func runWithOutput(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return commandError(err, out)
	}
	return nil
}

func commandError(err error, output []byte) error {
	msg := strings.TrimSpace(string(output))
	if msg == "" {
		return err
	}
	return fmt.Errorf("%w\n%s", err, msg)
}

func vaultHTTPHealthy(url string) bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	return vaultHTTPHealthyWithClient(client, url)
}

func vaultHTTPHealthyWithClient(client *http.Client, url string) bool {
	response, err := client.Get(url)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func vaultHealthURL(url string) string {
	url = strings.TrimRight(url, "/")
	if strings.HasSuffix(url, "/health") {
		return url
	}
	return url + "/health"
}

func waitForVaultRunning(healthURL string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if vaultHTTPHealthy(healthURL) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	logs, err := exec.Command("docker", "compose", "logs", "--tail=80", "vault").CombinedOutput()
	if err == nil && len(logs) > 0 {
		return fmt.Errorf("vault is not running after startup\n%s", strings.TrimSpace(string(logs)))
	}
	return fmt.Errorf("vault is not running after startup")
}

// reloadLocalVaultConfig streams the already-decrypted configuration through
// docker exec stdin to Vault's loopback-only control plane. No plaintext
// config is written to disk or placed in process arguments.
func reloadLocalVaultConfig(vaultYAML []byte) error {
	if len(vaultYAML) == 0 {
		return nil
	}
	containerOutput, err := exec.Command("docker", "compose", "ps", "-q", "vault").Output()
	if err != nil {
		return fmt.Errorf("finding local Vault container: %w", err)
	}
	containerID := strings.TrimSpace(string(containerOutput))
	if containerID == "" || strings.Contains(containerID, "\n") {
		return fmt.Errorf("expected one running local Vault container")
	}
	cmd := exec.Command("docker", "exec", "-i", containerID, "/app/vaultctl", "reload")
	cmd.Stdin = bytes.NewReader(vaultYAML)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return commandError(err, output)
	}
	return nil
}
