package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProjectConfigFile(t *testing.T, dir, name, sandboxName string) {
	t.Helper()
	contents := "[sandbox]\nname = \"" + sandboxName + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProjectConfigUsesSandboxToml(t *testing.T) {
	dir := t.TempDir()
	writeProjectConfigFile(t, dir, projectConfigFilename, "current")

	cfg, err := LoadProjectConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.Name != "current" {
		t.Fatalf("sandbox name = %q, want current", cfg.Sandbox.Name)
	}
}

func TestLoadProjectConfigFallsBackToLegacyFilename(t *testing.T) {
	dir := t.TempDir()
	writeProjectConfigFile(t, dir, legacyProjectConfigFilename, "legacy")

	cfg, err := LoadProjectConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.Name != "legacy" {
		t.Fatalf("sandbox name = %q, want legacy", cfg.Sandbox.Name)
	}
}

func TestLoadProjectConfigRejectsAmbiguousFilenames(t *testing.T) {
	dir := t.TempDir()
	writeProjectConfigFile(t, dir, projectConfigFilename, "current")
	writeProjectConfigFile(t, dir, legacyProjectConfigFilename, "legacy")

	_, err := LoadProjectConfig(dir)
	if err == nil || !strings.Contains(err.Error(), "both sandbox.toml and agent-creds.toml exist") {
		t.Fatalf("error = %v, want ambiguous config error", err)
	}
}

func TestSetupWritesSandboxTomlByDefault(t *testing.T) {
	dir := t.TempDir()
	model := setupModel{projectDir: dir}
	if err := model.writeConfig(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, projectConfigFilename)); err != nil {
		t.Fatalf("sandbox.toml was not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, legacyProjectConfigFilename)); !os.IsNotExist(err) {
		t.Fatalf("legacy config unexpectedly created: %v", err)
	}
}

func TestSetupKeepsLegacyFilenameWhenMigratingInPlace(t *testing.T) {
	dir := t.TempDir()
	writeProjectConfigFile(t, dir, legacyProjectConfigFilename, "legacy")
	model := setupModel{projectDir: dir}
	if err := model.writeConfig(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, legacyProjectConfigFilename)); err != nil {
		t.Fatalf("legacy config was not updated in place: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, projectConfigFilename)); !os.IsNotExist(err) {
		t.Fatalf("sandbox.toml unexpectedly created beside legacy config: %v", err)
	}
}
