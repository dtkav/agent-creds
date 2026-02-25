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

// configHash returns a hash of the current config (agent + plugins + packages).
// Used to detect when rebuild is needed.
func configHash(cfg ProjectConfig) string {
	h := sha256.New()

	// Hash agent name
	h.Write([]byte(cfg.Sandbox.Agent))

	// Hash packages (sorted for determinism)
	pkgs := make([]string, len(cfg.Packages))
	copy(pkgs, cfg.Packages)
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		h.Write([]byte(pkg))
	}

	// Hash inline nix expressions
	for _, expr := range cfg.NixExprs {
		h.Write([]byte(expr))
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// needsRebuild checks if the sandbox image needs to be rebuilt.
func needsRebuild(cfg ProjectConfig, scriptDir string) bool {
	hashFile := filepath.Join(scriptDir, "generated", ".config-hash")
	currentHash := configHash(cfg)

	// Read stored hash
	stored, err := os.ReadFile(hashFile)
	if err != nil {
		return true // No hash file = needs build
	}

	return strings.TrimSpace(string(stored)) != currentHash
}

// saveConfigHash saves the current config hash after successful build.
func saveConfigHash(cfg ProjectConfig, scriptDir string) error {
	hashFile := filepath.Join(scriptDir, "generated", ".config-hash")
	return os.WriteFile(hashFile, []byte(configHash(cfg)), 0644)
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

// ensureSandboxImage builds the sandbox image if needed.
func ensureSandboxImage(cfg ProjectConfig, scriptDir string, spinner *Spinner) error {
	if !needsRebuild(cfg, scriptDir) {
		return nil // Image is up to date
	}

	spinner.Status("generating packages.nix...")

	// Generate packages.nix
	outputPath := filepath.Join(scriptDir, "generated", "packages.nix")
	if err := GeneratePackagesNix(cfg, outputPath); err != nil {
		return fmt.Errorf("generating packages.nix: %w", err)
	}

	spinner.Status("building Go binaries...")
	if err := buildGoBinaries(scriptDir); err != nil {
		return fmt.Errorf("building Go binaries: %w", err)
	}

	spinner.Status("building sandbox image (this may take a while on first run)...")

	// Run the Nix build script
	buildScript := filepath.Join(scriptDir, "scripts", "build-nix.sh")
	cmd := exec.Command(buildScript, "sandbox-local")
	cmd.Dir = scriptDir
	cmd.Stdout = nil // Suppress output during spinner
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("building sandbox image: %w", err)
	}

	// Save hash on success
	if err := saveConfigHash(cfg, scriptDir); err != nil {
		return fmt.Errorf("saving config hash: %w", err)
	}

	return nil
}
