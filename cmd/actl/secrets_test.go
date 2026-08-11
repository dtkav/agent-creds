package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCredentialShowConfigAcceptsSecretReference(t *testing.T) {
	var cfg credentialShowConfig
	if err := yaml.Unmarshal([]byte("type: bearer\ntoken:\n  $secret: '/path/to/auth.env#TOKEN'\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := string(cfg.Token); got != "$secret:/path/to/auth.env#TOKEN" {
		t.Fatalf("token reference = %q", got)
	}
}

func TestValidateVaultYAMLRejectsUnpairedBasicEnvFields(t *testing.T) {
	config := []byte(`signing_key: test-signing-key
credentials:
  github/example:
    type: basic
    env_user: GITHUB_USER
`)

	err := validateVaultYAML(config)
	if err == nil {
		t.Fatal("validateVaultYAML accepted an unpaired env_user")
	}
	if !strings.Contains(err.Error(), "env_user and env_pass must both be set or both absent") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateVaultYAMLAcceptsPairedBasicEnvFields(t *testing.T) {
	config := []byte(`signing_key: test-signing-key
credentials:
  github/example:
    type: basic
    env_user: GITHUB_USER
    env_pass: GITHUB_PASSWORD
`)

	if err := validateVaultYAML(config); err != nil {
		t.Fatalf("validateVaultYAML rejected a valid config: %v", err)
	}
}

func TestSaveVaultYAMLLeavesEncryptedFileUntouchedWhenInvalid(t *testing.T) {
	yamlPath := filepath.Join(t.TempDir(), "vault.yaml")
	original := []byte("existing encrypted document")
	if err := os.WriteFile(yamlPath, original, 0600); err != nil {
		t.Fatal(err)
	}

	invalid := []byte("signing_key: ''\ncredentials: {}\n")
	if err := saveVaultYAML(yamlPath, invalid); err == nil {
		t.Fatal("saveVaultYAML accepted an invalid config")
	}
	got, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("saveVaultYAML modified the encrypted file after validation failed")
	}
}

func TestVaultTemplateSeparatesSigningAndEncryptionKeys(t *testing.T) {
	var cfg struct {
		Secrets       map[string]map[string]string `yaml:"secrets"`
		SigningKey    map[string]string            `yaml:"signing_key"`
		EncryptionKey map[string]string            `yaml:"encryption_key"`
	}
	if err := yaml.Unmarshal([]byte(vaultTemplate("signing", "encryption")), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Secrets["vault"]["SIGNING_KEY"]; got != "signing" {
		t.Fatalf("signing secret = %q", got)
	}
	if got := cfg.Secrets["vault"]["ENCRYPTION_KEY"]; got != "encryption" {
		t.Fatalf("encryption secret = %q", got)
	}
	if got := cfg.SigningKey["$secret"]; got != "vault#SIGNING_KEY" {
		t.Fatalf("signing key reference = %q", got)
	}
	if got := cfg.EncryptionKey["$secret"]; got != "vault#ENCRYPTION_KEY" {
		t.Fatalf("encryption key reference = %q", got)
	}
}
