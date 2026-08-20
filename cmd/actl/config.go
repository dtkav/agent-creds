package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

type SandboxConfig struct {
	Name string `toml:"name"`
}

type VaultConfig struct {
	Host string `toml:"host"` // bare hostname, implies https:443 + ssh:22
	HTTP string `toml:"http"` // explicit URL for local dev (e.g. http://localhost:8033)
	SSH  string `toml:"ssh"`  // explicit ssh address (e.g. localhost:2222)
}

// SSHAddr returns the SSH address for the vault.
func (v VaultConfig) SSHAddr() string {
	if v.SSH != "" {
		return v.SSH
	}
	if v.Host != "" {
		return v.Host + ":22"
	}
	return ""
}

// HTTPAddr returns the HTTP URL for the vault API.
func (v VaultConfig) HTTPAddr() string {
	if v.HTTP != "" {
		return v.HTTP
	}
	if v.Host != "" {
		return "https://" + v.Host
	}
	return "http://localhost:8033"
}

// IsRemote returns true when vault is a remote service.
func (v VaultConfig) IsRemote() bool {
	return v.Host != ""
}

type ProjectConfig struct {
	Sandbox SandboxConfig `toml:"sandbox"`
	Vault   VaultConfig   `toml:"vault"`
}

func projectConfigPath(dir string) (string, bool, error) {
	current := filepath.Join(dir, "sandbox.toml")
	legacy := filepath.Join(dir, "agent-creds.toml")
	currentExists := fileExists(current)
	legacyExists := fileExists(legacy)
	if currentExists && legacyExists {
		return "", false, fmt.Errorf(
			"both sandbox.toml and agent-creds.toml exist; keep only sandbox.toml")
	}
	if currentExists {
		return current, true, nil
	}
	if legacyExists {
		return legacy, true, nil
	}
	return current, false, nil
}

// LoadProjectConfig reads sandbox.toml, falling back to agent-creds.toml for
// existing projects. Returns a zero-value config if neither file exists.
func LoadProjectConfig(dir string) (ProjectConfig, error) {
	var cfg ProjectConfig
	path, exists, err := projectConfigPath(dir)
	if err != nil {
		return cfg, err
	}
	if !exists {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// Slug sanitizes a name for use in Docker container names.
func Slug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "default"
	}
	return s
}
