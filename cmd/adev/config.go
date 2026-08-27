package main

import (
	"encoding/json"
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
	Skills            []string `toml:"skills"`               // registered Agent Skills to install
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

// HTTPAddr returns the HTTP URL for the Vault API.
func (v VaultConfig) HTTPAddr() string {
	if v.HTTP != "" {
		return v.HTTP
	}
	if v.Host != "" {
		return "https://" + v.Host
	}
	return "http://localhost:8033"
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
	Credential     string   `toml:"credential,omitempty"`      // vault credential path (e.g., /stripe/live)
	Env            string   `toml:"env,omitempty"`             // client-facing env var override for the minted capability
	CredentialFile string   `toml:"credential_file,omitempty"` // basename projected under /run/credentials instead of an env var
	Policy         string   `toml:"policy,omitempty"`          // vault upstream policy path
	Scheme         string   `toml:"scheme,omitempty"`          // "https" (default) or "http"
	Port           int      `toml:"port,omitempty"`            // defaults to 443 for https, 80 for http
	Address        string   `toml:"address,omitempty"`         // fixed upstream origin (default: public host)
	Network        string   `toml:"network,omitempty"`         // extra Docker network attached to Envoy only
	Methods        []string `toml:"methods"`                   // allowed HTTP methods (empty = all)
	Paths          []string `toml:"paths"`                     // allowed path patterns with glob support (empty = all)

	// Authorization is populated after named [authorization.<name>] sections
	// are bound to their upstreams. These fields are runtime policy, not part
	// of the legacy [upstream] TOML shape.
	Authorization           string         `toml:"-"`
	AuthorizationNamespace  string         `toml:"-"`
	AuthorizationConstraint map[string]any `toml:"-"`
	OmitHostCaveat          bool           `toml:"-"`
}

func (u UpstreamConfig) MintsToken() bool {
	return u.Credential != "" || u.Authorization != ""
}

func (u UpstreamConfig) AddressValue(host string) string {
	if u.Address == "" {
		return host
	}
	return u.Address
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
	Trusted  bool   `toml:"trusted"`  // agent may trust code/config loaded from this directory
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
	Skills         []string                  `toml:"skills"`
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
	Skills         []string                  `toml:"skills"`     // registered skills this agent requires
	SkillDir       string                    `toml:"skill_dir"`  // agent-native skill directory, relative to home
	NixPkgFields                             // embedded Nix package set fields ([packages], [python3Packages], etc.)
	Upstream       map[string]UpstreamConfig `toml:"upstream"`
	BrowserTargets []BrowserTargetConfig     `toml:"browser_target"`
	CDPTargets     []CDPTargetConfig         `toml:"cdp_target"`
	Mounts         []MountConfig             `toml:"mount"`
	Env            []EnvConfig               `toml:"env"`
}

type ProjectConfig struct {
	Sandbox        SandboxConfig                  `toml:"sandbox"`
	Vault          VaultConfig                    `toml:"vault"`
	TapEnabled     bool                           `toml:"-"` // derived from the global tap config
	Entrypoint     string                         // set by agent
	NixExprs       []string                       // inline nix expressions from plugins/agents
	SkillNames     []string                       `toml:"-"` // unresolved names requested by sandbox/plugins/agent
	Skills         map[string]SkillConfig         `toml:"-"` // selected registered skills
	SkillDir       string                         `toml:"-"` // agent-native skill directory, relative to home
	NixPkgFields                                  // embedded Nix package set fields
	Upstream       map[string]UpstreamConfig      `toml:"upstream"`
	Authorization  map[string]AuthorizationConfig `toml:"-"`
	CDPTargets     []CDPTargetConfig              `toml:"cdp_target"`
	BrowserTargets []BrowserTargetConfig          `toml:"browser_target"`
	Mounts         []MountConfig                  `toml:"mount"`
	Env            []EnvConfig                    `toml:"-"`
	StaticEnv      map[string]interface{}         `toml:"-"`
}

// AuthorizationConfig binds a named application attestation to one or more
// routes. With a credential, its registered macaroon namespace and schema are
// used. Without one, Namespace is explicit and the selected upstream policy
// owns the arbitrary body semantics.
type AuthorizationConfig struct {
	Upstreams      []string
	Credential     string
	Namespace      string
	Env            string
	CredentialFile string
	HostCaveat     bool
	Methods        []string
	Paths          []string
	Constraint     map[string]any
}

type authorizationCommonFields struct {
	Upstreams      []string `toml:"upstreams"`
	Credential     string   `toml:"credential"`
	Namespace      string   `toml:"namespace"`
	Env            string   `toml:"env"`
	CredentialFile string   `toml:"credential_file"`
	HostCaveat     *bool    `toml:"host_caveat"`
	Methods        []string `toml:"methods"`
	Paths          []string `toml:"paths"`
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
	credentialFiles := make(map[string]string)
	for host, u := range upstreams {
		if u.CredentialFile != "" {
			if u.Env != "" {
				return fmt.Errorf("upstream %q: env and credential_file are mutually exclusive", host)
			}
			if !u.MintsToken() {
				return fmt.Errorf("upstream %q: credential_file requires a minted credential", host)
			}
			if !validCredentialFilename(u.CredentialFile) {
				return fmt.Errorf("upstream %q: credential_file %q must be a safe basename", host, u.CredentialFile)
			}
			if existingHost, duplicate := credentialFiles[u.CredentialFile]; duplicate {
				return fmt.Errorf("upstreams %q and %q use the same credential_file %q", existingHost, host, u.CredentialFile)
			}
			credentialFiles[u.CredentialFile] = host
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
		}
		if u.Policy != "" && !strings.HasPrefix(u.Policy, "/") {
			return fmt.Errorf("upstream %q: policy path %q must start with /", host, u.Policy)
		}
		if u.Policy == "/" {
			return fmt.Errorf("upstream %q: policy path must name a policy", host)
		}
	}
	return nil
}

func decodeAuthorizations(md toml.MetaData, encoded map[string]toml.Primitive) (map[string]AuthorizationConfig, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	result := make(map[string]AuthorizationConfig, len(encoded))
	for name, primitive := range encoded {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
			return nil, fmt.Errorf("authorization name %q must be non-empty without surrounding whitespace", name)
		}
		var common authorizationCommonFields
		if err := md.PrimitiveDecode(primitive, &common); err != nil {
			return nil, fmt.Errorf("decoding authorization.%s: %w", name, err)
		}
		var raw map[string]any
		if err := md.PrimitiveDecode(primitive, &raw); err != nil {
			return nil, fmt.Errorf("decoding authorization.%s application fields: %w", name, err)
		}
		for _, key := range []string{"upstreams", "credential", "namespace", "env", "credential_file", "host_caveat", "methods", "paths"} {
			delete(raw, key)
		}
		if _, err := json.Marshal(raw); err != nil {
			return nil, fmt.Errorf("authorization.%s application fields must be JSON-compatible: %w", name, err)
		}
		hostCaveat := true
		if common.HostCaveat != nil {
			hostCaveat = *common.HostCaveat
		}
		result[name] = AuthorizationConfig{
			Upstreams:      common.Upstreams,
			Credential:     common.Credential,
			Namespace:      common.Namespace,
			Env:            common.Env,
			CredentialFile: common.CredentialFile,
			HostCaveat:     hostCaveat,
			Methods:        common.Methods,
			Paths:          common.Paths,
			Constraint:     raw,
		}
	}
	return result, nil
}

// BindAuthorizations attaches each named authorization to its declared route.
// Plugin and harness profiles may provide the route, but only the project
// policy may attach a credential or application attestation.
func BindAuthorizations(cfg *ProjectConfig) error {
	if len(cfg.Authorization) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Authorization))
	for name := range cfg.Authorization {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		authorization := cfg.Authorization[name]
		if len(authorization.Upstreams) == 0 {
			return fmt.Errorf("authorization.%s: upstreams must be a non-empty array", name)
		}
		if authorization.Credential == "" {
			if strings.TrimSpace(authorization.Namespace) != authorization.Namespace || authorization.Namespace == "" {
				return fmt.Errorf("authorization.%s: namespace must be non-empty without surrounding whitespace when credential is omitted", name)
			}
			if authorization.Env == "" && authorization.CredentialFile == "" {
				return fmt.Errorf("authorization.%s: env or credential_file is required when credential is omitted", name)
			}
		} else {
			if !strings.HasPrefix(authorization.Credential, "/") || authorization.Credential == "/" {
				return fmt.Errorf("authorization.%s: credential path %q must name an absolute Vault credential", name, authorization.Credential)
			}
			if authorization.Namespace != "" {
				return fmt.Errorf("authorization.%s: namespace is derived from credential %q and must be omitted", name, authorization.Credential)
			}
		}
		seen := make(map[string]struct{}, len(authorization.Upstreams))
		for _, host := range authorization.Upstreams {
			if strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host {
				return fmt.Errorf("authorization.%s: upstream %q must be non-empty without surrounding whitespace", name, host)
			}
			if _, duplicate := seen[host]; duplicate {
				return fmt.Errorf("authorization.%s: upstream %q is listed more than once", name, host)
			}
			seen[host] = struct{}{}
			upstream, exists := cfg.Upstream[host]
			if !exists {
				return fmt.Errorf("authorization.%s: upstream %q is not configured", name, host)
			}
			if upstream.Authorization != "" {
				return fmt.Errorf("upstream %q is claimed by both authorization.%s and authorization.%s", host, upstream.Authorization, name)
			}
			if upstream.Credential != "" || len(upstream.Methods) > 0 || len(upstream.Paths) > 0 || upstream.Env != "" || upstream.CredentialFile != "" {
				return fmt.Errorf("authorization.%s: upstream %q also declares fields owned by the named authorization; keep credential, env, credential_file, methods, and paths in the authorization table", name, host)
			}
			if authorization.Credential == "" && upstream.Policy == "" {
				return fmt.Errorf("authorization.%s: policy-only upstream %q must select a policy", name, host)
			}
			upstream.Credential = authorization.Credential
			upstream.Env = authorization.Env
			upstream.CredentialFile = authorization.CredentialFile
			upstream.Methods = append([]string(nil), authorization.Methods...)
			upstream.Paths = append([]string(nil), authorization.Paths...)
			upstream.Authorization = name
			upstream.AuthorizationNamespace = authorization.Namespace
			upstream.AuthorizationConstraint = cloneAnyMap(authorization.Constraint)
			upstream.OmitHostCaveat = !authorization.HostCaveat
			cfg.Upstream[host] = upstream
		}
	}
	return nil
}

func cloneAnyMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	encoded, _ := json.Marshal(source)
	var cloned map[string]any
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
}

const (
	projectConfigFilename       = "sandbox.toml"
	legacyProjectConfigFilename = "agent-creds.toml"
)

// projectConfigPath returns the configured project policy path. sandbox.toml
// is the current name; agent-creds.toml remains a compatibility fallback.
// Keeping both is rejected so a launch cannot silently read the wrong policy.
func projectConfigPath(dir string) (string, bool, error) {
	current := filepath.Join(dir, projectConfigFilename)
	legacy := filepath.Join(dir, legacyProjectConfigFilename)
	currentExists := fileExists(current)
	legacyExists := fileExists(legacy)
	if currentExists && legacyExists {
		return "", false, fmt.Errorf(
			"both %s and %s exist; keep only %s",
			projectConfigFilename, legacyProjectConfigFilename, projectConfigFilename)
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
	path, exists, err := projectConfigPath(dir)
	if err != nil {
		return ProjectConfig{}, err
	}
	if !exists {
		return ProjectConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ProjectConfig{}, err
	}

	// Project configs support either a static [env] map or [[env]] entries
	// (including from-file values). Decode the section as a Primitive so the
	// two TOML shapes do not compete for the same struct tag.
	var decoded struct {
		ProjectConfig
		Env           toml.Primitive            `toml:"env"`
		Authorization map[string]toml.Primitive `toml:"authorization"`
	}
	md, err := toml.Decode(string(data), &decoded)
	if err != nil {
		return ProjectConfig{}, err
	}
	cfg := decoded.ProjectConfig
	cfg.Authorization, err = decodeAuthorizations(md, decoded.Authorization)
	if err != nil {
		return cfg, err
	}
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
// projectDir contains sandbox.toml (or the legacy agent-creds.toml), while
// scriptDir is the sandbox tooling installation.
func LoadProjectConfigWithPlugins(projectDir, scriptDir string) (ProjectConfig, error) {
	cfg, err := LoadProjectConfig(projectDir)
	if err != nil {
		return cfg, err
	}
	cfg.SkillNames = append(cfg.SkillNames, cfg.Sandbox.Skills...)

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
	if err := ResolveSkills(&cfg, DiscoverSkills(projectDir, scriptDir)); err != nil {
		return cfg, err
	}
	if err := BindAuthorizations(&cfg); err != nil {
		return cfg, err
	}
	if err := ValidateUpstreams(cfg.Upstream); err != nil {
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
