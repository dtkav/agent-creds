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

func TestSandboxEnvPrivateStoreMountsAsLogicalNixStore(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	envPath := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sandbox-env"
	key := "0123456789abcdef"
	store := filepath.Join(configHome, "agent-creds", "nix", "envs", key, "nix", "store")
	if err := os.MkdirAll(store, 0755); err != nil {
		t.Fatal(err)
	}
	// A top-level absolute symlink is valid once the complete private store is
	// mounted at /nix/store; host-side Stat must not be required.
	if err := os.Symlink(
		"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-env-target",
		filepath.Join(store, filepath.Base(envPath)),
	); err != nil {
		t.Fatal(err)
	}
	manifest := sandboxEnvStoreFile(envPath)
	if err := os.MkdirAll(filepath.Dir(manifest), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if !sandboxEnvAvailable(envPath) {
		t.Fatal("directly built private store was rejected as unavailable")
	}
	mounts, err := sandboxEnvClosureMounts(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].Source != store || mounts[0].Target != "/nix/store" {
		t.Fatalf("mounts = %#v, want private store mounted at /nix/store", mounts)
	}
}

func TestSandboxEnvPrivateStoreRejectsUnsafeKey(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	envPath := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sandbox-env"
	manifest := sandboxEnvStoreFile(envPath)
	if err := os.MkdirAll(filepath.Dir(manifest), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("../../outside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if sandboxEnvAvailable(envPath) {
		t.Fatal("unsafe private store key was accepted")
	}
}
