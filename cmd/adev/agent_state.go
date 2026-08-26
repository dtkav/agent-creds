package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type agentStateMount struct {
	source string
	target string
}

type agentState struct {
	mounts     []agentStateMount
	homeSource string
	homeTarget string
}

// prepareAgentState initializes and returns only the persistent state used by
// the configured agent. A sandbox must not see another agent's login or
// project state merely because adev supports that agent.
func prepareAgentState(
	scriptDir, instanceGenDir, workspace, homeDir string, cfg ProjectConfig,
) (agentState, error) {
	state := agentState{
		homeSource: filepath.Join(instanceGenDir, "home"),
		homeTarget: homeDir,
	}
	if cfg.Sandbox.Agent != "claude" {
		if _, err := migrateLegacyClaudeProjectState(scriptDir, instanceGenDir); err != nil {
			return agentState{}, err
		}
	}

	stateDir := func(name string) (string, error) {
		path := filepath.Join(scriptDir, "claude-dev", name+"-config")
		if err := os.MkdirAll(path, 0755); err != nil {
			return "", fmt.Errorf("creating %s state directory: %w", name, err)
		}
		return path, nil
	}

	switch cfg.Sandbox.Agent {
	case "claude":
		configDir, err := stateDir("claude")
		if err != nil {
			return agentState{}, err
		}
		sharedProjectState := filepath.Join(configDir, ".claude.json")
		if _, err := os.Stat(sharedProjectState); os.IsNotExist(err) {
			if err := os.WriteFile(sharedProjectState, []byte("{}"), 0600); err != nil {
				return agentState{}, fmt.Errorf("creating shared Claude project state: %w", err)
			}
		} else if err != nil {
			return agentState{}, fmt.Errorf("checking shared Claude project state: %w", err)
		}
		instanceProjectState, err := prepareClaudeProjectState(
			scriptDir, instanceGenDir, workspace, cfg,
		)
		if err != nil {
			return agentState{}, err
		}
		state.mounts = []agentStateMount{
			{source: configDir, target: filepath.Join(homeDir, ".claude")},
			{source: instanceProjectState, target: filepath.Join(homeDir, ".claude.json")},
		}
		return state, nil
	case "codex":
		configDir, err := stateDir("codex")
		if err != nil {
			return agentState{}, err
		}
		state.mounts = []agentStateMount{
			{source: configDir, target: filepath.Join(homeDir, ".codex")},
		}
		return state, nil
	case "pi":
		configDir, err := stateDir("pi")
		if err != nil {
			return agentState{}, err
		}
		state.mounts = []agentStateMount{
			{source: configDir, target: filepath.Join(homeDir, ".pi")},
		}
		return state, nil
	default:
		return state, nil
	}
}

func (s agentState) dockerArgs() []string {
	args := make([]string, 0, len(s.mounts)*2)
	for _, mount := range s.mounts {
		args = append(args, "-v", mount.source+":"+mount.target)
	}
	return args
}

func (s agentState) bwrapArgs() []string {
	args := make([]string, 0, len(s.mounts)*3)
	for _, mount := range s.mounts {
		args = append(args, "--bind", mount.source, mount.target)
	}
	return args
}

// ensureTargetDirectory creates a nested mount point in the persistent state
// backing the configured agent. Skill overlays are applied after the parent
// state bind, so both Docker and bwrap require this directory to exist there.
func (s agentState) ensureTargetDirectory(target string) error {
	for _, mount := range s.mounts {
		rel, err := filepath.Rel(mount.target, target)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		info, err := os.Stat(mount.source)
		if err != nil || !info.IsDir() {
			continue
		}
		if err := os.MkdirAll(filepath.Join(mount.source, rel), 0755); err != nil {
			return fmt.Errorf("creating agent state mount point: %w", err)
		}
		return nil
	}
	if s.homeSource != "" && s.homeTarget != "" {
		rel, err := filepath.Rel(s.homeTarget, target)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			if err := os.MkdirAll(filepath.Join(s.homeSource, rel), 0755); err != nil {
				return fmt.Errorf("creating instance home mount point: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("target %s is outside the configured agent state", target)
}
