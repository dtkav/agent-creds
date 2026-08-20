package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeProjectStateRepairsEmptyGeneratedState(t *testing.T) {
	root := t.TempDir()
	scriptDir := filepath.Join(root, "agent-creds")
	instanceDir := filepath.Join(scriptDir, "generated", "instances", "review")
	sharedPath := filepath.Join(
		scriptDir, "claude-dev", "claude-config", ".claude.json")
	if err := os.MkdirAll(filepath.Dir(sharedPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedPath, []byte(`{"userID":"shared-user"}`), 0600); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(instanceDir, "home", ".claude.json")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}

	path, err := prepareClaudeProjectState(
		scriptDir, instanceDir, "/workspace",
		ProjectConfig{Sandbox: SandboxConfig{Agent: "claude"}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("repaired state is not valid JSON: %v", err)
	}
	if state["userID"] != "shared-user" {
		t.Fatalf("shared state was not retained: %#v", state)
	}
	project := state["projects"].(map[string]any)["/workspace"].(map[string]any)
	if project["hasTrustDialogAccepted"] != true {
		t.Fatalf("workspace trust was not rebuilt: %#v", project)
	}
}
