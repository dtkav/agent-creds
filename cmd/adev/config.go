package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// CDPPort handles both boolean and integer values for use_host_browser_cdp.
// false or omitted = 0 (disabled), true = 9222 (default), integer = custom port.
type CDPPort int

func (c *CDPPort) UnmarshalTOML(data any) error {
	switch v := data.(type) {
	case bool:
		if v {
			*c = 9222
		} else {
			*c = 0
		}
	case int64:
		*c = CDPPort(v)
	}
	return nil
}

type SandboxConfig struct {
	Name              string   `toml:"name"`
	Image             string   `toml:"image"`
	Runtime           string   `toml:"runtime"` // "runc" or "gvisor" (default: gvisor)
	UseHostBrowser    *bool    `toml:"use_host_browser"`     // default true
	UseHostBrowserCDP CDPPort  `toml:"use_host_browser_cdp"` // 0=disabled, port number=enabled
	Agent             string   `toml:"agent"`                // agent to use (e.g., "claude")
	Plugins           []string `toml:"plugins"`              // additional plugins to enable
	DisabledPlugins   []string `toml:"disabled_plugins"`     // plugins to disable
}

func (s SandboxConfig) UseHostBrowserEnabled() bool    { return s.UseHostBrowser == nil || *s.UseHostBrowser }
func (s SandboxConfig) UseHostBrowserCDPEnabled() bool { return s.UseHostBrowserCDP > 0 }

// RuntimeArg returns the --runtime flag value for docker.
// Default is gVisor (runsc), explicit "runc" uses docker default.
func (s SandboxConfig) RuntimeArg() string {
	if s.Runtime == "runc" {
		return "" // use docker default
	}
	return "runsc" // gvisor is default
}

// UsesHostNetfilter returns true if the runtime requires host-side iptables.
// gVisor can't share network namespace, so sandbox-net runs with --network=host.
// Only runc can share network namespace with sandbox-net container.
func (s SandboxConfig) UsesHostNetfilter() bool {
	return s.Runtime != "runc"
}

type VaultConfig struct {
	Host string `toml:"host"` // bare hostname, implies https:443 + ssh:22
	DNS  string `toml:"dns"`  // optional DNS server for resolving host (e.g. for private networks)
	HTTP string `toml:"http"` // explicit URL for local dev (e.g. http://localhost:8033)
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
	Methods []string `toml:"methods"` // allowed HTTP methods (empty = all)
	Paths   []string `toml:"paths"`   // allowed path patterns with glob support (empty = all)
}

// CDPTargetConfig defines an allowed CDP target pattern.
// All specified fields must match (empty = match any).
type CDPTargetConfig struct {
	Type  string `toml:"type"`  // glob pattern matching target type (page, background_page, service_worker, etc.)
	Title string `toml:"title"` // glob pattern matching target title
	URL   string `toml:"url"`   // glob pattern matching target URL
}

// BrowserTargetConfig defines an allowed URL pattern for browser forwarding.
type BrowserTargetConfig struct {
	URL string `toml:"url"` // glob pattern matching URL to open
}

// MountConfig defines a bind mount from host to container.
type MountConfig struct {
	Source   string `toml:"source"`   // host path (~ expanded, ./ relative to project)
	Target   string `toml:"target"`   // container path
	Readonly bool   `toml:"readonly"` // default: false
}

// EnvConfig defines an environment variable to set in the container.
type EnvConfig struct {
	Name  string `toml:"name"`  // environment variable name
	Value string `toml:"value"` // literal value or "from-file:path"
}

// PluginConfig represents a plugin's configuration.
type PluginConfig struct {
	Name           string                     `toml:"name"`
	Description    string                     `toml:"description"`
	Packages       []string                   `toml:"packages"`      // system packages to install
	Nix            string                     `toml:"nix"`           // inline nix expression (list of derivations, pkgs in scope)
	Upstream       map[string]UpstreamConfig  `toml:"upstream"`
	BrowserTargets []BrowserTargetConfig      `toml:"browser_target"`
	CDPTargets     []CDPTargetConfig          `toml:"cdp_target"`
	Mounts         []MountConfig              `toml:"mount"`
	Env            []EnvConfig                `toml:"env"`
}

// AgentConfig represents an agent's configuration.
// Agents are like plugins but also define entrypoint and can require plugins.
type AgentConfig struct {
	Name           string                     `toml:"name"`
	Description    string                     `toml:"description"`
	Entrypoint     string                     `toml:"entrypoint"`    // command to run
	Packages       []string                   `toml:"packages"`      // system packages to install
	Nix            string                     `toml:"nix"`           // inline nix expression (list of derivations, pkgs in scope)
	Plugins        []string                   `toml:"plugins"`       // plugins this agent requires
	Upstream       map[string]UpstreamConfig  `toml:"upstream"`
	BrowserTargets []BrowserTargetConfig      `toml:"browser_target"`
	CDPTargets     []CDPTargetConfig          `toml:"cdp_target"`
	Mounts         []MountConfig              `toml:"mount"`
	Env            []EnvConfig                `toml:"env"`
}

type ProjectConfig struct {
	Sandbox        SandboxConfig              `toml:"sandbox"`
	Vault          VaultConfig                `toml:"vault"`
	Entrypoint     string                     // set by agent
	Packages       []string                   // aggregated from agent + plugins
	NixExprs       []string                   // inline nix expressions from plugins/agents
	Upstream       map[string]UpstreamConfig  `toml:"upstream"`
	CDPTargets     []CDPTargetConfig          `toml:"cdp_target"`
	BrowserTargets []BrowserTargetConfig      `toml:"browser_target"`
	Mounts         []MountConfig              `toml:"mount"`
	Env            []EnvConfig                `toml:"env"`
}

// MatchGlob performs simple glob matching where * matches any characters.
// Pattern must match the entire string (anchored). Empty pattern matches anything.
func MatchGlob(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	re := regexp.QuoteMeta(pattern)
	re = strings.ReplaceAll(re, `\*`, `.*`)
	re = "^" + re + "$"
	matched, _ := regexp.MatchString(re, value)
	return matched
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

// LoadProjectConfigWithPlugins loads the project config, agent, and plugins.
// projectDir is where agent-creds.toml lives, scriptDir is the agent-creds installation.
func LoadProjectConfigWithPlugins(projectDir, scriptDir string) (ProjectConfig, error) {
	cfg, err := LoadProjectConfig(projectDir)
	if err != nil {
		return cfg, err
	}

	// Collect plugins to enable (agent plugins + explicit plugins)
	var agentPlugins []string

	// Load agent if specified
	if cfg.Sandbox.Agent != "" {
		agents := DiscoverAgents(projectDir, scriptDir)
		agentPath, ok := agents[cfg.Sandbox.Agent]
		if !ok {
			return cfg, fmt.Errorf("agent %q not found", cfg.Sandbox.Agent)
		}
		agent, err := LoadAgent(agentPath)
		if err != nil {
			return cfg, fmt.Errorf("loading agent %s: %w", cfg.Sandbox.Agent, err)
		}
		// Merge agent config
		MergeAgent(&cfg, agent, projectDir)
		// Collect agent's required plugins
		agentPlugins = agent.Plugins
	}

	// Discover all plugins
	discovered := DiscoverPlugins(projectDir, scriptDir)

	// Auto-include project-local plugins (if you put it in your plugins/ dir, you want it)
	projectPluginDir := filepath.Join(projectDir, "plugins")
	var projectPlugins []string
	for name, path := range discovered {
		if strings.HasPrefix(path, projectPluginDir+string(filepath.Separator)) {
			projectPlugins = append(projectPlugins, name)
		}
	}

	// Combine agent plugins + explicit plugins + project-local plugins
	allPlugins := append(agentPlugins, cfg.Sandbox.Plugins...)
	allPlugins = append(allPlugins, projectPlugins...)

	// Filter: if no explicit list, use agent plugins only (not all discovered)
	var enabled []string
	if len(allPlugins) > 0 {
		for _, name := range allPlugins {
			if _, ok := discovered[name]; ok {
				if !sliceContains(cfg.Sandbox.DisabledPlugins, name) && !sliceContains(enabled, name) {
					enabled = append(enabled, name)
				}
			}
		}
	}

	// Merge enabled plugins
	if err := MergePlugins(&cfg, discovered, enabled, projectDir); err != nil {
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
