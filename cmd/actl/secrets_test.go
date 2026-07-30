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
