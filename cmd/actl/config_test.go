package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeActlProjectConfig(t *testing.T, dir, name, sandboxName string) {
	t.Helper()
	contents := "[sandbox]\nname = \"" + sandboxName + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProjectConfigNames(t *testing.T) {
	for _, tc := range []struct {
		name     string
		filename string
	}{
		{name: "current", filename: "sandbox.toml"},
		{name: "legacy", filename: "agent-creds.toml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeActlProjectConfig(t, dir, tc.filename, tc.name)
			cfg, err := LoadProjectConfig(dir)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Sandbox.Name != tc.name {
				t.Fatalf("sandbox name = %q, want %q", cfg.Sandbox.Name, tc.name)
			}
		})
	}
}

func TestLoadProjectConfigRejectsBothNames(t *testing.T) {
	dir := t.TempDir()
	writeActlProjectConfig(t, dir, "sandbox.toml", "current")
	writeActlProjectConfig(t, dir, "agent-creds.toml", "legacy")
	_, err := LoadProjectConfig(dir)
	if err == nil || !strings.Contains(err.Error(), "both sandbox.toml and agent-creds.toml exist") {
		t.Fatalf("error = %v, want ambiguous config error", err)
	}
}
