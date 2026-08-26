package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryHonorsXDGConfigHome(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	bundled := t.TempDir()
	project := t.TempDir()

	globalPlugin := filepath.Join(configHome, "agent-creds", "plugins", "global.toml")
	if err := os.MkdirAll(filepath.Dir(globalPlugin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalPlugin, []byte("name = \"global\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plugins := DiscoverPlugins(project, bundled)
	if plugins["global"] != globalPlugin {
		t.Fatalf("global plugin = %q, want %q", plugins["global"], globalPlugin)
	}
}

func TestBundledAgentsLoad(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	agents := DiscoverAgents(repoRoot, repoRoot)

	for _, name := range []string{"claude", "codex", "pi"} {
		path, ok := agents[name]
		if !ok {
			t.Fatalf("bundled agent %q not discovered", name)
		}
		agent, err := LoadAgent(path)
		if err != nil {
			t.Fatalf("loading agent %q: %v", name, err)
		}
		if agent.Name != name {
			t.Fatalf("agent %q loaded with name %q", name, agent.Name)
		}
		if agent.SkillDir == "" {
			t.Fatalf("agent %q does not declare its native skill directory", name)
		}
	}
}
