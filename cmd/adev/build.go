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
	currentHash := envHash(cfg, scriptDir)
	envFile := filepath.Join(nixDir(), "env-"+currentHash)
	if !fileExists(envFile) {
		return true
	}
	// Verify the stored path still exists on disk
	data, err := os.ReadFile(envFile)
	if err != nil {
		return true
	}
	envPath := strings.TrimSpace(string(data))
	return !fileExists(envPath)
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
		cmd := exec.Command("go", "build", "-o", filepath.Join(scriptDir, b.out), ".")
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
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("building base image: %w", err)
	}

	if err := saveBaseHash(scriptDir); err != nil {
		return fmt.Errorf("saving base hash: %w", err)
	}

	return nil
}

// ensureSandboxEnv builds the sandbox env if needed.
// Returns the env store path (e.g. /nix/store/xxx-sandbox-env).
func ensureSandboxEnv(cfg ProjectConfig, scriptDir string, spinner *Spinner) (string, error) {
	if !needsEnvRebuild(cfg, scriptDir) {
		// Read cached env path for this hash
		cacheFile := filepath.Join(nixDir(), "env-"+envHash(cfg, scriptDir))
		data, err := os.ReadFile(cacheFile)
		if err != nil {
			return "", fmt.Errorf("reading cached env path: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	spinner.Status("generating packages.nix...")

	// Generate packages.nix
	outputPath := filepath.Join(scriptDir, "generated", "packages.nix")
	if err := GeneratePackagesNix(cfg, outputPath); err != nil {
		return "", fmt.Errorf("generating packages.nix: %w", err)
	}

	spinner.Status("building sandbox env (this may take a while on first run)...")

	buildScript := filepath.Join(scriptDir, "scripts", "build-nix.sh")
	cmd := exec.Command(buildScript, "env")
	cmd.Dir = scriptDir
	cmd.Stderr = nil

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("building sandbox env: %w", err)
	}

	// The last line of output is the env path
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	envPath := lines[len(lines)-1]

	if !strings.HasPrefix(envPath, "/nix/store/") {
		return "", fmt.Errorf("unexpected env path: %s", envPath)
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