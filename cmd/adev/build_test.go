package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSandboxEnvAvailableRequiresCompleteClosure(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	envPath := "/nix/store/cccccccccccccccccccccccccccccccc-sandbox-env"
	depPath := "/nix/store/dddddddddddddddddddddddddddddddd-rust-man"
	privateStore := filepath.Join(configHome, "agent-creds", "nix", "store")
	if err := os.MkdirAll(
		filepath.Join(privateStore, filepath.Base(envPath)), 0755,
	); err != nil {
		t.Fatal(err)
	}
	closure := sandboxEnvClosureFile(envPath)
	if err := os.MkdirAll(filepath.Dir(closure), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		closure, []byte(envPath+"\n"+depPath+"\n"), 0600,
	); err != nil {
		t.Fatal(err)
	}

	if sandboxEnvAvailable(envPath) {
		t.Fatal("incomplete closure was accepted as an available sandbox env")
	}
	if err := os.MkdirAll(
		filepath.Join(privateStore, filepath.Base(depPath)), 0755,
	); err != nil {
		t.Fatal(err)
	}
	if !sandboxEnvAvailable(envPath) {
		t.Fatal("complete closure was rejected as unavailable")
	}
}
