package main

import (
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
