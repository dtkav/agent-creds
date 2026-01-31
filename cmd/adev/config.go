package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

type SandboxConfig struct {
	Name           string `toml:"name"`
	Image          string `toml:"image"`
	UseHostBrowser    *bool `toml:"use_host_browser"`     // default true
	UseHostBrowserCDP *bool `toml:"use_host_browser_cdp"` // default true
}

func (s SandboxConfig) UseHostBrowserEnabled() bool    { return s.UseHostBrowser == nil || *s.UseHostBrowser }
func (s SandboxConfig) UseHostBrowserCDPEnabled() bool { return s.UseHostBrowserCDP == nil || *s.UseHostBrowserCDP }

type VaultConfig struct {
	Host string `toml:"host"` // bare hostname, implies https:443 + ssh:22
	DNS  string `toml:"dns"`  // optional DNS server for resolving host (e.g. for private networks)
	HTTP string `toml:"http"` // explicit URL for local dev (e.g. http://localhost:8080)
	SSH  string `toml:"ssh"`  // explicit ssh address (e.g. localhost:2222)
}

// VaultAddr returns the host and port for the vault gRPC service.
// Remote: host on port 443. Local: "vault" on port 9001.
func (v VaultConfig) VaultAddr() (host string, port int) {
	if v.Host != "" {
		return v.Host, 443
	}
	return "vault", 9001
}

// IsRemote returns true when vault is a remote service (not local docker-compose).
func (v VaultConfig) IsRemote() bool {
	return v.Host != ""
}

type UpstreamConfig struct {
	// Empty for now - domains are just listed, auth is handled by vault.toml
}

type ProjectConfig struct {
	Sandbox  SandboxConfig              `toml:"sandbox"`
	Vault    VaultConfig                `toml:"vault"`
	Upstream map[string]UpstreamConfig  `toml:"upstream"`
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
