package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCopyNixSourceExcludesRuntimeState(t *testing.T) {
	sourceDir := t.TempDir()
	workspaceDir := t.TempDir()

	for path, contents := range map[string]string{
		"flake.nix":              "{}",
		"dirty-source.txt":       "included",
		".git/config":            "excluded",
		"generated/packages.nix": "included",
		"generated/skills.nix":   "excluded",
		"generated/harness.nix":  "excluded",
		"generated/runtime.log":  "excluded",
	} {
		fullPath := filepath.Join(sourceDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}

	socketPath := filepath.Join(sourceDir, "generated", "admin.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	script := filepath.Join("..", "..", "scripts", "copy-nix-source.sh")
	out, err := exec.Command(script, sourceDir, workspaceDir).CombinedOutput()
	if err != nil {
		t.Fatalf("copy-nix-source.sh: %v\n%s", err, out)
	}

	for _, path := range []string{"flake.nix", "dirty-source.txt", "generated/packages.nix"} {
		if _, err := os.Stat(filepath.Join(workspaceDir, path)); err != nil {
			t.Errorf("expected %s in workspace: %v", path, err)
		}
	}
	for _, path := range []string{".git", "generated/skills.nix", "generated/harness.nix", "generated/runtime.log", "generated/admin.sock"} {
		if _, err := os.Lstat(filepath.Join(workspaceDir, path)); !os.IsNotExist(err) {
			t.Errorf("runtime path %s was copied", path)
		}
	}
}

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

func TestCachedSandboxEnvReturnsValidatedSnapshot(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cfg := ProjectConfig{}
	scriptDir := t.TempDir()
	envPath := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sandbox-env"
	key := "0123456789abcdef"
	store := filepath.Join(configHome, "agent-creds", "nix", "envs", key, "nix", "store")
	if err := os.MkdirAll(store, 0755); err != nil {
		t.Fatal(err)
	}
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
	if err := saveEnvHash(cfg, scriptDir, envPath); err != nil {
		t.Fatal(err)
	}

	got, available := cachedSandboxEnv(cfg, scriptDir)
	if !available || got != envPath {
		t.Fatalf("cachedSandboxEnv() = %q, %v; want %q, true", got, available, envPath)
	}
}

func TestCachedSandboxEnvTreatsRemovedCacheAsRebuild(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cfg := ProjectConfig{}
	if got, available := cachedSandboxEnv(cfg, t.TempDir()); available || got != "" {
		t.Fatalf("cachedSandboxEnv() = %q, %v; want empty, false", got, available)
	}
}
