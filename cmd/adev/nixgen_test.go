package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePackagesNixBuildsImportablePythonEnvironment(t *testing.T) {
	cfg := ProjectConfig{}
	cfg.NixPackageSets = map[string]map[string]bool{
		"": {"git": true, "python3": true},
		"python3Packages": {
			"websockets": true,
			"click":      true,
			"pyyaml":     true,
			"requests":   true,
		},
	}
	output := filepath.Join(t.TempDir(), "packages.nix")
	if err := GeneratePackagesNix(cfg, output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"pkgs.git",
		"pkgs.python3.withPackages",
		"ps.click",
		"ps.pyyaml",
		"ps.requests",
		"ps.websockets",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated Nix is missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"  pkgs.python3\n", "pkgs.python3Packages.click"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("generated Nix contains standalone Python package %q:\n%s", unwanted, got)
		}
	}
	if strings.Index(got, "ps.click") > strings.Index(got, "ps.websockets") {
		t.Errorf("Python packages are not sorted:\n%s", got)
	}
}
