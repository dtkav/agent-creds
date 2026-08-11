package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeProjectStateIsInstanceScopedAndTrustsDeclaredMounts(t *testing.T) {
	root := t.TempDir()
	scriptDir := filepath.Join(root, "agent-creds")
	instanceDir := filepath.Join(scriptDir, "generated", "instances", "review")
	sharedPath := filepath.Join(
		scriptDir, "claude-dev", "claude-config", ".claude.json")
	if err := os.MkdirAll(filepath.Dir(sharedPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedPath, []byte(`{
  "userID": "shared-user",
  "projects": {
    "/someone/elses/worktree": {"hasTrustDialogAccepted": true}
  }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := ProjectConfig{
		Sandbox: SandboxConfig{Agent: "claude"},
		Mounts: []MountConfig{
			{Source: "/host/review", Target: "/work/review", Trusted: true},
			{Source: "/host/input", Target: "/work/untrusted"},
		},
	}

	path, err := prepareClaudeProjectState(
		scriptDir, instanceDir, "/workspace", cfg)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state["userID"] != "shared-user" {
		t.Fatalf("shared non-project state was not retained: %#v", state)
	}
	projects, ok := state["projects"].(map[string]any)
	if !ok {
		t.Fatalf("projects = %#v", state["projects"])
	}
	for _, trusted := range []string{"/workspace", "/work/review"} {
		project, ok := projects[trusted].(map[string]any)
		if !ok || project["hasTrustDialogAccepted"] != true {
			t.Errorf("project %q is not trusted: %#v", trusted, project)
		}
	}
	for _, absent := range []string{"/someone/elses/worktree", "/work/untrusted"} {
		if _, ok := projects[absent]; ok {
			t.Errorf("untrusted project %q leaked into instance state", absent)
		}
	}
}

func TestClaudeProjectStatePreservesInstanceProjectState(t *testing.T) {
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
	instancePath := filepath.Join(instanceDir, "home", ".claude.json")
	if err := os.MkdirAll(filepath.Dir(instancePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(instancePath, []byte(`{
  "projects": {"/workspace": {"custom": "preserved"}}
}`), 0600); err != nil {
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
		t.Fatal(err)
	}
	project := state["projects"].(map[string]any)["/workspace"].(map[string]any)
	if project["custom"] != "preserved" || project["hasTrustDialogAccepted"] != true {
		t.Fatalf("instance project state was not merged: %#v", project)
	}
}
