package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// nixDir returns the persistent host Nix store directory.
func nixDir() string {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".config")
	}
	return filepath.Join(configDir, "agent-creds", "nix")
}

// NixStoreMount maps one canonical /nix/store path to the host location from
// which a confined runtime should bind it. Local Docker builds copy closures
// into agent-creds' private store; native host builds may already live at the
// canonical path.
type NixStoreMount struct {
	Source string
	Target string
}

func sandboxEnvClosureFile(envPath string) string {
	return filepath.Join(
		nixDir(), "var", "nix", "closures", filepath.Base(envPath)+".paths",
	)
}

func sandboxEnvStoreFile(envPath string) string {
	return filepath.Join(
		nixDir(), "var", "nix", "stores", filepath.Base(envPath)+".store",
	)
}

// sandboxEnvPrivateStore resolves the physical store built for one logical
// sandbox environment. The manifest contains only the validated env cache key,
// never an arbitrary host path.
func sandboxEnvPrivateStore(envPath string) (string, error) {
	data, err := os.ReadFile(sandboxEnvStoreFile(envPath))
	if err != nil {
		return "", fmt.Errorf("reading sandbox env store: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if len(key) != 16 || filepath.Base(key) != key {
		return "", fmt.Errorf("invalid sandbox env store key %q", key)
	}
	for _, char := range key {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return "", fmt.Errorf("invalid sandbox env store key %q", key)
		}
	}
	store := filepath.Join(nixDir(), "envs", key, "nix", "store")
	if info, err := os.Stat(store); err != nil || !info.IsDir() {
		return "", fmt.Errorf("sandbox env store is unavailable: %s", store)
	}
	physicalEnv := filepath.Join(store, filepath.Base(envPath))
	if _, err := os.Lstat(physicalEnv); err != nil {
		return "", fmt.Errorf("sandbox env is unavailable: %s", envPath)
	}
	return store, nil
}

func sandboxEnvHostPath(envPath string) string {
	if fileExists(envPath) {
		return envPath
	}
	if store, err := sandboxEnvPrivateStore(envPath); err == nil {
		return filepath.Join(store, filepath.Base(envPath))
	}
	return filepath.Join(nixDir(), "store", filepath.Base(envPath))
}

func sandboxEnvAvailable(envPath string) bool {
	if fileExists(sandboxEnvStoreFile(envPath)) {
		_, err := sandboxEnvPrivateStore(envPath)
		return err == nil
	}
	if !fileExists(sandboxEnvHostPath(envPath)) ||
		!fileExists(sandboxEnvClosureFile(envPath)) {
		return false
	}
	// The private store is not registered with the host Nix daemon, so one
	// path can disappear without invalidating the environment root or its
	// persisted manifest. Treat the cache as usable only when the complete
	// recorded closure can still be mounted.
	_, err := sandboxEnvClosureMounts(envPath)
	return err == nil
}

// sandboxEnvClosureMounts resolves Nix's recorded closure into explicit bind
// mounts. Targets remain canonical so store references embedded in binaries
// and scripts continue to resolve inside bwrap.
func sandboxEnvClosureMounts(envPath string) ([]NixStoreMount, error) {
	if fileExists(sandboxEnvStoreFile(envPath)) {
		store, err := sandboxEnvPrivateStore(envPath)
		if err != nil {
			return nil, err
		}
		return []NixStoreMount{{Source: store, Target: "/nix/store"}}, nil
	}

	data, err := os.ReadFile(sandboxEnvClosureFile(envPath))
	if err != nil {
		return nil, fmt.Errorf("reading sandbox env closure: %w", err)
	}

	seen := make(map[string]bool)
	var mounts []NixStoreMount
	for _, line := range strings.Split(string(data), "\n") {
		target := filepath.Clean(strings.TrimSpace(line))
		if target == "." || target == "" {
			continue
		}
		if filepath.Dir(target) != "/nix/store" {
			return nil, fmt.Errorf("invalid Nix closure path %q", line)
		}
		if seen[target] {
			continue
		}
		seen[target] = true

		source := filepath.Join(nixDir(), "store", filepath.Base(target))
		if !fileExists(source) {
			if fileExists(target) {
				source = target
			} else {
				return nil, fmt.Errorf("Nix closure path is unavailable: %s", target)
			}
		}
		mounts = append(mounts, NixStoreMount{Source: source, Target: target})
	}
	if len(mounts) == 0 {
		return nil, fmt.Errorf("sandbox env closure is empty: %s", envPath)
	}
	sort.Slice(mounts, func(i, j int) bool {
		return mounts[i].Target < mounts[j].Target
	})
	return mounts, nil
}

// baseImageHash returns a hash of inputs that affect the base Docker image.
// This changes rarely — only when flake.nix structure or claude-dev/ scripts change.
func baseImageHash(scriptDir string) string {
	h := sha256.New()

	// Hash flake.nix
	if data, err := os.ReadFile(filepath.Join(scriptDir, "flake.nix")); err == nil {
		h.Write(data)
	}

	// Hash claude-dev/ files (entrypoint, bashrc, etc.)
	claudeDevDir := filepath.Join(scriptDir, "claude-dev")
	entries, _ := os.ReadDir(claudeDevDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if data, err := os.ReadFile(filepath.Join(claudeDevDir, e.Name())); err == nil {
			h.Write([]byte(e.Name()))
			h.Write(data)
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// envHash returns a hash of inputs that affect the sandbox env (packages).
// This changes when plugins add/remove packages, nix expressions, or basePackages in flake.nix.
func envHash(cfg ProjectConfig, scriptDir string) string {
	h := sha256.New()

	// Hash flake.nix (basePackages are defined there)
	if data, err := os.ReadFile(filepath.Join(scriptDir, "flake.nix")); err == nil {
		h.Write(data)
	}

	// Hash agent name
	h.Write([]byte(cfg.Sandbox.Agent))

	// Hash the exact generated package expression. This catches changes to
	// package composition itself (for example, Python withPackages semantics),
	// even when the declarative package names did not change.
	h.Write([]byte(renderPackagesNix(cfg)))

	// Hash Nix package sets (sorted for determinism)
	for prefix, pkgSet := range cfg.NixPackageSets {
		var names []string
		for name, enabled := range pkgSet {
			if enabled {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			h.Write([]byte(prefix + "." + name))
		}
	}

	// Hash inline nix expressions
	for _, expr := range cfg.NixExprs {
		h.Write([]byte(expr))
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// needsBaseRebuild checks if the base image needs to be rebuilt.
func needsBaseRebuild(scriptDir string) bool {
	hashFile := filepath.Join(scriptDir, "generated", ".base-hash")
	currentHash := baseImageHash(scriptDir)

	stored, err := os.ReadFile(hashFile)
	if err != nil {
		return true
	}

	if strings.TrimSpace(string(stored)) != currentHash {
		return true
	}

	// Also check that the image exists
	return !imageExists("sandbox-base")
}

// needsEnvRebuild checks if the sandbox env needs to be rebuilt.
// Each distinct env hash gets its own cache file in nixDir(), so switching
// between projects with different package sets doesn't trigger rebuilds.
func needsEnvRebuild(cfg ProjectConfig, scriptDir string) bool {
	_, available := cachedSandboxEnv(cfg, scriptDir)
	return !available
}

// cachedSandboxEnv reads and validates one cache snapshot. Callers must use
// the returned path rather than checking the cache and reopening it later:
// cache maintenance or a concurrent environment build may replace the file
// between those operations.
func cachedSandboxEnv(cfg ProjectConfig, scriptDir string) (string, bool) {
	cacheFile := filepath.Join(nixDir(), "env-"+envHash(cfg, scriptDir))
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return "", false
	}
	envPath := strings.TrimSpace(string(data))
	if envPath == "" || !sandboxEnvAvailable(envPath) {
		return "", false
	}
	return envPath, true
}

// saveBaseHash saves the base image hash after successful build.
func saveBaseHash(scriptDir string) error {
	hashFile := filepath.Join(scriptDir, "generated", ".base-hash")
	return os.WriteFile(hashFile, []byte(baseImageHash(scriptDir)), 0644)
}

// saveEnvHash saves the env hash → env path mapping after successful build.
func saveEnvHash(cfg ProjectConfig, scriptDir, envPath string) error {
	currentHash := envHash(cfg, scriptDir)
	cacheFile := filepath.Join(nixDir(), "env-"+currentHash)
	return os.WriteFile(cacheFile, []byte(envPath), 0644)
}

// buildGoBinaries builds the Go binaries needed for the sandbox image.
func buildGoBinaries(scriptDir string) error {
	binaries := []struct {
		src string
		out string
	}{
		{"cmd/aenv", "generated/aenv"},
		{"cmd/cdp-proxy", "generated/cdp-proxy"},
		{"cmd/tcp-bridge", "generated/tcp-bridge"},
		{"cmd/dns-responder", "generated/dns-responder"},
	}

	for _, b := range binaries {
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", filepath.Join(scriptDir, b.out), ".")
		cmd.Dir = filepath.Join(scriptDir, b.src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0") // static binary required for Nix image
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("building %s: %w", b.src, err)
		}
	}
	return nil
}

// ensureBaseImage builds the base Docker image if needed.
func ensureBaseImage(scriptDir string, spinner *Spinner) error {
	if !needsBaseRebuild(scriptDir) {
		return nil
	}

	spinner.Status("building Go binaries...")
	if err := buildGoBinaries(scriptDir); err != nil {
		return fmt.Errorf("building Go binaries: %w", err)
	}

	spinner.Status("building base image (this may take a while on first run)...")

	buildScript := filepath.Join(scriptDir, "scripts", "build-nix.sh")
	cmd := exec.Command(buildScript, "base", "sandbox-base")
	cmd.Dir = scriptDir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("building base image: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	if err := saveBaseHash(scriptDir); err != nil {
		return fmt.Errorf("saving base hash: %w", err)
	}

	return nil
}

// ensureSandboxEnv builds the sandbox env if needed.
// Returns the env store path (e.g. /nix/store/xxx-sandbox-env).
func ensureSandboxEnv(cfg ProjectConfig, scriptDir string, spinner *Spinner) (string, error) {
	if envPath, available := cachedSandboxEnv(cfg, scriptDir); available {
		return envPath, nil
	}

	spinner.Status("generating packages.nix...")

	// Generate packages.nix
	outputPath := filepath.Join(scriptDir, "generated", "packages.nix")
	if err := GeneratePackagesNix(cfg, outputPath); err != nil {
		return "", fmt.Errorf("generating packages.nix: %w", err)
	}

	spinner.Status("building sandbox env (this may take a while on first run)...")

	buildScript := filepath.Join(scriptDir, "scripts", "build-nix.sh")
	cmd := exec.Command(buildScript, "env", envHash(cfg, scriptDir))
	cmd.Dir = scriptDir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("building sandbox env: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	// The last line of output is the env path
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	envPath := lines[len(lines)-1]

	if !strings.HasPrefix(envPath, "/nix/store/") {
		return "", fmt.Errorf("unexpected env path: %s", envPath)
	}
	if !sandboxEnvAvailable(envPath) {
		return "", fmt.Errorf("sandbox env was not built into its private store: %s", envPath)
	}
	if _, err := sandboxEnvClosureMounts(envPath); err != nil {
		return "", fmt.Errorf("sandbox env store was not exported: %w", err)
	}

	if err := saveEnvHash(cfg, scriptDir, envPath); err != nil {
		return "", fmt.Errorf("saving env hash: %w", err)
	}

	// Also write current-env for backward compat (used by build-nix.sh)
	if err := os.WriteFile(filepath.Join(nixDir(), "current-env"), []byte(envPath), 0644); err != nil {
		return "", fmt.Errorf("writing current-env: %w", err)
	}

	return envPath, nil
}
