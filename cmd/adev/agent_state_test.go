package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPrepareAgentStateOnlyInitializesSelectedAgent(t *testing.T) {
	tests := []struct {
		name        string
		agent       string
		wantConfigs []string
		wantTargets []string
	}{
		{
			name:        "Claude",
			agent:       "claude",
			wantConfigs: []string{"claude-config"},
			wantTargets: []string{".claude", ".claude.json"},
		},
		{
			name:        "Codex",
			agent:       "codex",
			wantConfigs: []string{"codex-config"},
			wantTargets: []string{".codex"},
		},
		{
			name:        "Pi",
			agent:       "pi",
			wantConfigs: []string{"pi-config"},
			wantTargets: []string{".pi"},
		},
		{name: "unconfigured shell"},
		{name: "custom agent", agent: "custom-agent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			scriptDir := filepath.Join(root, "agent-creds")
			instanceDir := filepath.Join(scriptDir, "generated", "instances", "review")
			homeDir := "/home/devuser"
			state, err := prepareAgentState(
				scriptDir, instanceDir, "/workspace", homeDir,
				ProjectConfig{Sandbox: SandboxConfig{Agent: tt.agent}},
			)
			if err != nil {
				t.Fatal(err)
			}

			var targets []string
			for _, mount := range state.mounts {
				targets = append(targets, filepath.Base(mount.target))
			}
			if !slices.Equal(targets, tt.wantTargets) {
				t.Fatalf("mount targets = %q, want %q", targets, tt.wantTargets)
			}

			for _, config := range []string{"claude-config", "codex-config", "pi-config"} {
				path := filepath.Join(scriptDir, "claude-dev", config)
				_, err := os.Stat(path)
				want := slices.Contains(tt.wantConfigs, config)
				if want && err != nil {
					t.Errorf("selected state directory %s was not initialized: %v", config, err)
				}
				if !want && !os.IsNotExist(err) {
					t.Errorf("unselected state directory %s was initialized: %v", config, err)
				}
			}

			dockerArgs := strings.Join(state.dockerArgs(), "\x00")
			bwrapArgs := strings.Join(state.bwrapArgs(), "\x00")
			for _, mount := range state.mounts {
				if !strings.Contains(dockerArgs, "-v\x00"+mount.source+":"+mount.target) {
					t.Errorf("Docker args do not mount selected state: %q", dockerArgs)
				}
				if !strings.Contains(bwrapArgs, "--bind\x00"+mount.source+"\x00"+mount.target) {
					t.Errorf("bwrap args do not mount selected state: %q", bwrapArgs)
				}
			}
		})
	}
}

func TestCodexStateMigratesLegacyClaudeStateOutOfHome(t *testing.T) {
	root := t.TempDir()
	scriptDir := filepath.Join(root, "agent-creds")
	instanceDir := filepath.Join(scriptDir, "generated", "instances", "review")
	legacyPath := filepath.Join(instanceDir, "home", ".claude.json")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0700); err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"projects":{"/workspace":{"custom":"preserved"}}}`)
	if err := os.WriteFile(legacyPath, want, 0600); err != nil {
		t.Fatal(err)
	}

	state, err := prepareAgentState(
		scriptDir, instanceDir, "/workspace", "/home/devuser",
		ProjectConfig{Sandbox: SandboxConfig{Agent: "codex"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy Claude state remains visible in Codex home: %v", err)
	}
	got, err := os.ReadFile(claudeProjectStatePath(scriptDir, instanceDir))
	if err != nil {
		t.Fatalf("preserved Claude state: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("preserved Claude state changed")
	}
	if len(state.mounts) != 1 || filepath.Base(state.mounts[0].target) != ".codex" {
		t.Fatalf("Codex mounts = %#v", state.mounts)
	}
}
