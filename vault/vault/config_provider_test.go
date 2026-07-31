package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCustomProviderReceivesInlineOptions(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "vault.yaml")
	source := `
signing_key: test-key
secrets:
  oidc:
    AUDIENCE: private-api
credentials:
  service.example.com:
    type: custom_oidc
    policy: service-read
    audience:
      $secret: oidc#AUDIENCE
    command_config: /private/config.toml
policies:
  service-read:
    type: example_policy
    service: records
`
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	credential := config.Credentials["service.example.com"]
	if credential.Type != "custom_oidc" {
		t.Fatalf("type = %q, want custom_oidc", credential.Type)
	}
	options := credential.ProviderConfig()
	if options["audience"] != "private-api" {
		t.Fatalf("audience = %#v, want private-api", options["audience"])
	}
	if options["command_config"] != "/private/config.toml" {
		t.Fatalf("command_config = %#v", options["command_config"])
	}
	if credential.Policy != "service-read" {
		t.Fatalf("policy = %q, want service-read", credential.Policy)
	}
	policy := config.Policies["service-read"]
	if policy.Type != "example_policy" || policy.Config()["service"] != "records" {
		t.Fatalf("unexpected policy config: %#v", policy)
	}
	if _, err := config.Validate(); err != nil {
		t.Fatalf("validating provider and policy config: %v", err)
	}
}

func TestCredentialPolicyMustResolveToConfiguredRelativeName(t *testing.T) {
	config := Config{
		SigningKey: "test-key",
		Credentials: map[string]CredentialConfig{
			"service.example": {Type: "bearer", Token: "token", Policy: "/"},
		},
	}
	if _, err := config.Validate(); err == nil {
		t.Fatal("empty absolute policy path was accepted")
	}

	config.Credentials["service.example"] = CredentialConfig{
		Type: "bearer", Token: "token", Policy: "/service/read",
	}
	config.Policies = map[string]PolicyConfig{
		"/service/read": {Type: "example"},
	}
	if _, err := config.Validate(); err == nil {
		t.Fatal("absolute policy map key was accepted")
	}
}
