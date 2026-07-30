package main

import (
	"path/filepath"
	"testing"
)

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
	}
}
