package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

type SandboxConfig struct {
	Name              string   `toml:"name"`
	Image             string   `toml:"image"`
	Runtime           string   `toml:"runtime"`              // "runc" or "gvisor" (default: gvisor)
	Memory            string   `toml:"memory"`               // docker --memory limit (e.g., "8g", "512m")
	CPUs              string   `toml:"cpus"`                 // docker --cpus limit (e.g., "4", "1.5")
	UseHostBrowser    *bool    `toml:"use_host_browser"`     // default true
	UseHostBrowserCDP bool     `toml:"use_host_browser_cdp"` // enable CDP forwarding
	Agent             string   `toml:"agent"`                // agent to use (e.g., "claude")
	Entrypoint        string   `toml:"entrypoint"`           // console session command; outranks the agent profile's
	Plugins           []string `toml:"plugins"`              // additional plugins to enable
	DisabledPlugins   []string `toml:"disabled_plugins"`     // plugins to disable
}

func (s SandboxConfig) UseHostBrowserEnabled() bool {
	return s.UseHostBrowser == nil || *s.UseHostBrowser
}
func (s SandboxConfig) UseHostBrowserCDPEnabled() bool { return s.UseHostBrowserCDP }

// ValidateRuntime checks the configured sandbox runtime is a known backend.
func (s SandboxConfig) ValidateRuntime() error {
	switch s.Runtime {
	case "", "gvisor", "runc", "bwrap":
		return nil
	}
	return fmt.Errorf("sandbox runtime %q: must be gvisor, runc, or bwrap", s.Runtime)
}

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
	Credential   string   `toml:"credential,omitempty"`    // vault credential path (e.g., /stripe/live)
	Mode         string   `toml:"mode,omitempty"`          // "credential" (default) or "identity"
	Scheme       string   `toml:"scheme,omitempty"`        // "https" (default) or "http"
	Port         int      `toml:"port,omitempty"`          // defaults to 443 for https, 80 for http
	Address      string   `toml:"address,omitempty"`       // fixed upstream origin (default: public host)
	Network      string   `toml:"network,omitempty"`       // extra Docker network attached to Envoy only
	ForwardToken bool     `toml:"forward_token,omitempty"` // caller supplies macaroon; do not mint/expose env token
	Methods      []string `toml:"methods"`                 // allowed HTTP methods (empty = all)
	Paths        []string `toml:"paths"`                   // allowed path patterns with glob support (empty = all)
}

func (u UpstreamConfig) MintsToken() bool {
	return u.Credential != "" && !u.ForwardToken
}

func (u UpstreamConfig) AddressValue(host string) string {
	if u.Address == "" {
		return host
	}
	return u.Address
}

func (u UpstreamConfig) ModeValue() string {
	if u.Mode == "" {
		return "credential"
	}
	return u.Mode
}

func (u UpstreamConfig) SchemeValue() string {
	if u.Scheme == "" {
		return "https"
	}
	return u.Scheme
}

func (u UpstreamConfig) PortValue() int {
	if u.Port != 0 {
		return u.Port
	}
	if u.SchemeValue() == "http" {
		return 80
	}
	return 443
}

// CDPTargetConfig defines an allowed CDP target pattern.
// All specified fields must match (empty = match any).
type CDPTargetConfig struct {
	Port  int    `toml:"port"`  // Chrome CDP port (default 9222 if 0)
	Type  string `toml:"type"`  // glob pattern matching target type (page, background_page, service_worker, etc.)
	Title string `toml:"title"` // glob pattern matching target title
	URL   string `toml:"url"`   // glob pattern matching target URL
}

// CDPPorts returns the deduplicated sorted list of Chrome CDP ports from targets.
// Ports of 0 are treated as the default (9222).
func CDPPorts(targets []CDPTargetConfig) []int {
	seen := make(map[int]bool)
	for _, t := range targets {
		p := t.Port
		if p == 0 {
			p = 9222
		}
		seen[p] = true
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
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
	Name           string                    `toml:"name"`
	Description    string                    `toml:"description"`
	Nix            string                    `toml:"nix"` // inline nix expression (list of derivations, pkgs in scope)
	NixPkgFields                             // embedded Nix package set fields ([packages], [python3Packages], etc.)
	Upstream       map[string]UpstreamConfig `toml:"upstream"`
	BrowserTargets []BrowserTargetConfig     `toml:"browser_target"`
	CDPTargets     []CDPTargetConfig         `toml:"cdp_target"`
	Mounts         []MountConfig             `toml:"mount"`
	Env            []EnvConfig               `toml:"env"`
}

// AgentConfig represents an agent's configuration.
// Agents are like plugins but also define entrypoint and can require plugins.
type AgentConfig struct {
	Name           string                    `toml:"name"`
	Description    string                    `toml:"description"`
	Entrypoint     string                    `toml:"entrypoint"` // command to run
	Nix            string                    `toml:"nix"`        // inline nix expression (list of derivations, pkgs in scope)
	Plugins        []string                  `toml:"plugins"`    // plugins this agent requires
	NixPkgFields                             // embedded Nix package set fields ([packages], [python3Packages], etc.)
	Upstream       map[string]UpstreamConfig `toml:"upstream"`
	BrowserTargets []BrowserTargetConfig     `toml:"browser_target"`
	CDPTargets     []CDPTargetConfig         `toml:"cdp_target"`
	Mounts         []MountConfig             `toml:"mount"`
	Env            []EnvConfig               `toml:"env"`
}

type ProjectConfig struct {
	Sandbox        SandboxConfig             `toml:"sandbox"`
	Vault          VaultConfig               `toml:"vault"`
	Entrypoint     string                    // set by agent
	NixExprs       []string                  // inline nix expressions from plugins/agents
	NixPkgFields                             // embedded Nix package set fields
	Upstream       map[string]UpstreamConfig `toml:"upstream"`
	CDPTargets     []CDPTargetConfig         `toml:"cdp_target"`
	BrowserTargets []BrowserTargetConfig     `toml:"browser_target"`
	Mounts         []MountConfig             `toml:"mount"`
	Env            []EnvConfig               `toml:"-"`
	StaticEnv      map[string]interface{}    `toml:"-"`
}

// NixPkgFields holds Nix package set fields shared by PluginConfig, AgentConfig, and ProjectConfig.
// Each field maps to a TOML section like [python3Packages] with boolean entries.
// To add a new Nix namespace: add a field here and an entry in nixPkgSets().
type NixPkgFields struct {
	NixPackages     map[string]bool            `toml:"packages"` // top-level pkgs.*
	Python3Packages map[string]bool            `toml:"python3Packages"`
	NodePackages    map[string]bool            `toml:"nodePackages"`
	LuaPackages     map[string]bool            `toml:"luaPackages"`
	PerlPackages    map[string]bool            `toml:"perlPackages"`
	HaskellPackages map[string]bool            `toml:"haskellPackages"`
	RubyPackages    map[string]bool            `toml:"rubyPackages"`
	EmacsPackages   map[string]bool            `toml:"emacsPackages"`
	PhpPackages     map[string]bool            `toml:"phpPackages"`
	OcamlPackages   map[string]bool            `toml:"ocamlPackages"`
	RPackages       map[string]bool            `toml:"rPackages"`
	BeamPackages    map[string]bool            `toml:"beamPackages"`
	NixPackageSets  map[string]map[string]bool // aggregated; not from TOML directly
}

// nixPkgSets returns all package set fields as prefix→map pairs.
// "" prefix means top-level pkgs.* (no dot prefix).
func (n *NixPkgFields) nixPkgSets() []nixPkgSet {
	return []nixPkgSet{
		{"", n.NixPackages},
		{"python3Packages", n.Python3Packages},
		{"nodePackages", n.NodePackages},
		{"luaPackages", n.LuaPackages},
		{"perlPackages", n.PerlPackages},
		{"haskellPackages", n.HaskellPackages},
		{"rubyPackages", n.RubyPackages},
		{"emacsPackages", n.EmacsPackages},
		{"phpPackages", n.PhpPackages},
		{"ocamlPackages", n.OcamlPackages},
		{"rPackages", n.RPackages},
		{"beamPackages", n.BeamPackages},
	}
}

// collectNixPackageSets gathers explicit Nix package set fields into the generic map.
func collectNixPackageSets(dst map[string]map[string]bool, sets ...nixPkgSet) {
	for _, s := range sets {
		if len(s.pkgs) == 0 {
			continue
		}
		if dst[s.prefix] == nil {
			dst[s.prefix] = make(map[string]bool)
		}
		for name, enabled := range s.pkgs {
			if enabled {
				dst[s.prefix][name] = true
			}
		}
	}
}

type nixPkgSet struct {
	prefix string
	pkgs   map[string]bool
}

// mergeNixPackageSets merges src package sets into dst.
func mergeNixPackageSets(dst, src map[string]map[string]bool) map[string]map[string]bool {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]map[string]bool)
	}
	for prefix, pkgs := range src {
		if dst[prefix] == nil {
			dst[prefix] = make(map[string]bool)
		}
		for name, enabled := range pkgs {
			if enabled {
				dst[prefix][name] = true
			}
		}
	}
	return dst
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

// ValidateUpstreams checks credential references on upstream configs.
// Returns an error for invalid credential paths, and prints warnings to stderr
// for upstreams that have methods/paths caveats but no credential.
func ValidateUpstreams(upstreams map[string]UpstreamConfig) error {
	for host, u := range upstreams {
		if mode := u.ModeValue(); mode != "credential" && mode != "identity" {
			return fmt.Errorf("upstream %q: mode %q must be credential or identity", host, mode)
		}
		if u.ModeValue() == "identity" && u.Credential != "" {
			return fmt.Errorf("upstream %q: identity mode cannot inject credential %q", host, u.Credential)
		}
		if u.ForwardToken && u.Credential == "" {
			return fmt.Errorf("upstream %q: forward_token requires a credential path", host)
		}
		if scheme := u.SchemeValue(); scheme != "http" && scheme != "https" {
			return fmt.Errorf("upstream %q: scheme %q must be http or https", host, scheme)
		}
		if u.Port < 0 || u.Port > 65535 {
			return fmt.Errorf("upstream %q: port %d is outside 1-65535", host, u.Port)
		}
		if u.Credential != "" {
			if !strings.HasPrefix(u.Credential, "/") {
				return fmt.Errorf("upstream %q: credential path %q must start with /", host, u.Credential)
			}
		} else if u.ModeValue() != "identity" {
			if len(u.Methods) > 0 || len(u.Paths) > 0 {
				fmt.Fprintf(os.Stderr, "Warning: upstream %q has methods/paths caveats but no credential; caveats will have no effect\n", host)
			}
		}
	}
	return nil
}

// LoadProjectConfig reads agent-creds.toml from dir if it exists.
// Returns a zero-value config (not an error) if the file is absent.
func LoadProjectConfig(dir string) (ProjectConfig, error) {
	path := filepath.Join(dir, "agent-creds.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ProjectConfig{}, nil
		}
		return ProjectConfig{}, err
	}

	// Project configs support either a static [env] map or [[env]] entries
	// (including from-file values). Decode the section as a Primitive so the
	// two TOML shapes do not compete for the same struct tag.
	var decoded struct {
		ProjectConfig
		Env toml.Primitive `toml:"env"`
	}
	md, err := toml.Decode(string(data), &decoded)
	if err != nil {
		return ProjectConfig{}, err
	}
	cfg := decoded.ProjectConfig
	switch md.Type("env") {
	case "":
	case "Hash":
		if err := md.PrimitiveDecode(decoded.Env, &cfg.StaticEnv); err != nil {
			return ProjectConfig{}, fmt.Errorf("decoding [env]: %w", err)
		}
	case "ArrayHash":
		if err := md.PrimitiveDecode(decoded.Env, &cfg.Env); err != nil {
			return ProjectConfig{}, fmt.Errorf("decoding [[env]]: %w", err)
		}
	default:
		return ProjectConfig{}, fmt.Errorf("env must be a table or array of tables")
	}
	if err := cfg.Sandbox.ValidateRuntime(); err != nil {
		return cfg, err
	}
	if err := ValidateUpstreams(cfg.Upstream); err != nil {
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

	// Precedence: a project's [sandbox] entrypoint outranks the agent
	// profile's. Every backend runs cfg.Entrypoint as its session
	// command, so entrypoint = "bash -l" gives a plain confined shell
	// regardless of agent.
	if cfg.Sandbox.Entrypoint != "" {
		cfg.Entrypoint = cfg.Sandbox.Entrypoint
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
