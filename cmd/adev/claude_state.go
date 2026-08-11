package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// prepareClaudeProjectState separates per-sandbox project decisions from the
// shared Claude login/session directory. The caller explicitly chose the
// sandbox workspace, and mounts may opt into the same trust contract. Other
// mounted content remains untrusted.
func prepareClaudeProjectState(
	scriptDir, instanceGenDir, workspace string, cfg ProjectConfig,
) (string, error) {
	sharedPath := filepath.Join(
		scriptDir, "claude-dev", "claude-config", ".claude.json")
	shared := map[string]any{}
	if data, err := os.ReadFile(sharedPath); err == nil {
		if err := json.Unmarshal(data, &shared); err != nil {
			return "", fmt.Errorf("reading shared Claude project state: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading shared Claude project state: %w", err)
	}
	// Project entries carry trust and other workspace-local decisions. Never
	// clone them from another identity into a new sandbox.
	delete(shared, "projects")

	instancePath := filepath.Join(instanceGenDir, "home", ".claude.json")
	instance := map[string]any{}
	if data, err := os.ReadFile(instancePath); err == nil {
		if err := json.Unmarshal(data, &instance); err != nil {
			return "", fmt.Errorf("reading instance Claude project state: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading instance Claude project state: %w", err)
	}
	projects, _ := instance["projects"].(map[string]any)
	if projects == nil {
		projects = map[string]any{}
	}
	shared["projects"] = projects

	if cfg.Sandbox.Agent == "" || cfg.Sandbox.Agent == "claude" {
		trusted := []string{workspace}
		for _, mount := range cfg.Mounts {
			if mount.Trusted {
				if !filepath.IsAbs(mount.Target) {
					return "", fmt.Errorf(
						"trusted mount target must be absolute: %q", mount.Target)
				}
				trusted = append(trusted, mount.Target)
			}
		}
		for _, path := range trusted {
			path = filepath.Clean(path)
			project, _ := projects[path].(map[string]any)
			if project == nil {
				project = map[string]any{}
			}
			project["hasTrustDialogAccepted"] = true
			projects[path] = project
		}
	}

	if err := os.MkdirAll(filepath.Dir(instancePath), 0700); err != nil {
		return "", fmt.Errorf("creating instance Claude state directory: %w", err)
	}
	data, err := json.MarshalIndent(shared, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding instance Claude project state: %w", err)
	}
	temporary := instancePath + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0600); err != nil {
		return "", fmt.Errorf("writing instance Claude project state: %w", err)
	}
	if err := os.Rename(temporary, instancePath); err != nil {
		return "", fmt.Errorf("publishing instance Claude project state: %w", err)
	}
	return instancePath, nil
}
