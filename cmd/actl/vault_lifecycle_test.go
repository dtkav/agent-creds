package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceEnvironmentReplacesVaultSecretWithoutDuplicates(t *testing.T) {
	got := replaceEnvironment(
		[]string{"PATH=/bin", "AGENT_CREDS_VAULT_CONFIG=stale", "HOME=/tmp"},
		"AGENT_CREDS_VAULT_CONFIG",
		"credentials:\n  example: current\n",
	)
	count := 0
	for _, item := range got {
		if strings.HasPrefix(item, "AGENT_CREDS_VAULT_CONFIG=") {
			count++
			if item != "AGENT_CREDS_VAULT_CONFIG=credentials:\n  example: current\n" {
				t.Fatalf("unexpected Vault environment: %q", item)
			}
		}
	}
	if count != 1 {
		t.Fatalf("Vault environment entries = %d, want 1", count)
	}
}

func TestAgentCredsRootHonorsValidatedOverride(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "docker-compose.yml"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_CREDS_ROOT", root)
	got, err := agentCredsRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Fatalf("agentCredsRoot() = %q, want %q", got, root)
	}
}
