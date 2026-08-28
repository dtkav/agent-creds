package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	vaultcfg "vault/vault"
)

func TestRuntimeInventoryContainsPointersButNotResolvedSecrets(t *testing.T) {
	config, err := vaultcfg.LoadBytes([]byte(`
secrets:
  records:
    TOKEN: resolved-secret-that-must-not-leak
signing_key: test-signing-key
encryption_key: test-encryption-key
credentials:
  records/prod:
    type: bearer
    token:
      $secret: records#TOKEN
    env: RECORDS_TOKEN
    capabilities:
      hosts: [records.example.com]
      endpoints:
        - methods: [GET]
          paths: [/v1/**]
`))
	if err != nil {
		t.Fatal(err)
	}
	store := newTestRuntimeStore(t, config)
	credential := config.Credentials["records/prod"]
	credential.Policy = "records-read"
	config.Credentials["records/prod"] = credential
	config.Policies = map[string]vaultcfg.PolicyConfig{
		"records-read": {Type: "records_policy"},
	}
	inventory, err := runtimeInventory(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "resolved-secret-that-must-not-leak") {
		t.Fatal("runtime inventory exposed resolved secret material")
	}
	if !strings.Contains(text, `"reference":"records#TOKEN"`) {
		t.Fatalf("runtime inventory omitted secret pointer: %s", text)
	}
	if len(inventory.Credentials) != 1 || inventory.Credentials[0].Name != "/records/prod" {
		t.Fatalf("credentials = %#v", inventory.Credentials)
	}
	if len(inventory.Policies) != 1 || inventory.Policies[0].Name != "records-read" {
		t.Fatalf("policies = %#v", inventory.Policies)
	}
}
