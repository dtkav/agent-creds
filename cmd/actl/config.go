package main

import (
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
	HTTP string `toml:"http"` // explicit URL for local dev (e.g. http://localhost:8080)
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

// HTTPAddr returns the HTTP URL for the authz API.
func (v VaultConfig) HTTPAddr() string {
	if v.HTTP != "" {
		return v.HTTP
	}
	if v.Host != "" {
		return "https://" + v.Host
	}
	return "http://localhost:8080"
}

// IsRemote returns true when authz is a remote service.
func (v VaultConfig) IsRemote() bool {
	return v.Host != ""
}

type ProjectConfig struct {
	Sandbox SandboxConfig `toml:"sandbox"`
	Vault   VaultConfig   `toml:"vault"`
}

// LoadProjectConfig reads agent-creds.toml from dir if it exists.
// Returns a zero-value config (not an error) if the file is absent.
func LoadProjectConfig(dir string) (ProjectConfig, error) {
	var cfg ProjectConfig
	path := filepath.Join(dir, "agent-creds.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
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
