package vault

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the vault.yaml configuration
type Config struct {
	Secrets       map[string]map[string]string `yaml:"secrets,omitempty"`
	SigningKey    string                       `yaml:"signing_key"`
	EncryptionKey string                       `yaml:"encryption_key,omitempty"`
	Credentials   map[string]CredentialConfig  `yaml:"credentials"`
	Policies      map[string]PolicyConfig      `yaml:"policies,omitempty"`
}

// CredentialConfig defines how to inject credentials for a domain. Built-in
// providers have typed fields below; JavaScript providers receive any
// additional inline fields through Options.
type CredentialConfig struct {
	Type     string `yaml:"type"`
	Token    string `yaml:"token,omitempty"`
	Header   string `yaml:"header,omitempty"`
	Value    string `yaml:"value,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Policy   string `yaml:"policy,omitempty"`

	// Environment variable name fields for credential resolution
	Env     string `yaml:"env,omitempty"`      // env var holding a token-shaped capability
	EnvUser string `yaml:"env_user,omitempty"` // env var holding basic auth username
	EnvPass string `yaml:"env_pass,omitempty"` // env var holding basic auth password

	// SigV4 fields
	Region          string `yaml:"region,omitempty"`
	Service         string `yaml:"service,omitempty"`
	AccessKeyID     string `yaml:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty"`

	// OAuth 2.0 refresh-token fields
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	RefreshToken string `yaml:"refresh_token,omitempty"`
	TokenURL     string `yaml:"token_url,omitempty"`

	// Capabilities (optional)
	Capabilities *CapabilitiesConfig `yaml:"capabilities,omitempty"`

	Options map[string]any `yaml:",inline"`
}

// PolicyConfig selects a trusted deployment policy implementation and passes
// it opaque application-owned configuration.
type PolicyConfig struct {
	Type    string         `yaml:"type"`
	Options map[string]any `yaml:",inline"`
}

func (c PolicyConfig) Config() map[string]any {
	result := make(map[string]any, len(c.Options))
	for key, value := range c.Options {
		result[key] = value
	}
	return result
}

// EndpointCap defines allowed methods and path patterns for an endpoint
type EndpointCap struct {
	Methods     []string `yaml:"methods"`
	Paths       []string `yaml:"paths"`
	Description string   `yaml:"description,omitempty"`
}

// CapabilitiesConfig defines what a credential is allowed to access
type CapabilitiesConfig struct {
	Hosts     []string      `yaml:"hosts,omitempty"`
	Endpoints []EndpointCap `yaml:"endpoints,omitempty"`
}

// Load reads and parses a vault.yaml file, resolving $secret references.
//
// $secret uses path#KEY syntax:
//
//	token:
//	  $secret: '/home/user/project/auth.env#API_KEY'
//
// The path before # is a key in the secrets map (populated by actl vault import).
// The fragment after # is the env var name within that group.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault config: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes parses a vault configuration and resolves $secret references.
// It is the in-memory counterpart to Load, used by the live reload control
// path so decrypted configuration never needs a temporary plaintext file.
func LoadBytes(data []byte) (*Config, error) {

	// First pass: extract the secrets map
	var raw struct {
		Secrets map[string]map[string]string `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse vault config: %w", err)
	}

	// Second pass: resolve $secret refs in the YAML tree
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse vault config: %w", err)
	}

	if len(raw.Secrets) > 0 && len(doc.Content) > 0 {
		resolveSecretRefs(doc.Content[0], raw.Secrets)
	}

	// Marshal resolved tree and unmarshal into Config
	resolved, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize resolved config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(resolved, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse resolved config: %w", err)
	}

	return &cfg, nil
}

// resolveSecretRefs walks a YAML mapping node, replacing $secret nodes with
// resolved scalar values. A $secret node is a mapping with a single key "$secret"
// whose value is "path#KEY".
func resolveSecretRefs(node *yaml.Node, secrets map[string]map[string]string) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content)-1; i += 2 {
			val := node.Content[i+1]
			if isSecretRef(val) {
				ref := val.Content[1].Value
				resolved := lookupSecret(ref, secrets)
				node.Content[i+1] = &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: resolved,
				}
			} else {
				resolveSecretRefs(val, secrets)
			}
		}
	} else if node.Kind == yaml.SequenceNode {
		for _, child := range node.Content {
			resolveSecretRefs(child, secrets)
		}
	}
}

// isSecretRef returns true if the node is a mapping like {$secret: "path#KEY"}.
func isSecretRef(node *yaml.Node) bool {
	return node.Kind == yaml.MappingNode &&
		len(node.Content) == 2 &&
		node.Content[0].Value == "$secret"
}

// lookupSecret resolves a "path#KEY" reference against the secrets map.
func lookupSecret(ref string, secrets map[string]map[string]string) string {
	path, key, ok := strings.Cut(ref, "#")
	if !ok {
		return ""
	}
	group, exists := secrets[path]
	if !exists {
		return ""
	}
	return group[key]
}

// Validate checks that the config is well-formed and all credentials have required fields.
// Returns a list of warnings (e.g. empty values) and an error for structural problems.
func (c *Config) Validate() (warnings []string, err error) {
	if c.SigningKey == "" {
		return nil, fmt.Errorf("signing_key is required")
	}

	for domain, cc := range c.Credentials {
		w, e := cc.validate(domain)
		warnings = append(warnings, w...)
		if e != nil {
			return warnings, fmt.Errorf("credentials.%s: %w", domain, e)
		}
		// Validate capability hosts against the credential's configured host (map key)
		if cc.Capabilities != nil {
			capWarnings := cc.Capabilities.validate(domain)
			warnings = append(warnings, capWarnings...)
		}
		if cc.Policy != "" {
			if strings.TrimSpace(cc.Policy) != cc.Policy {
				return warnings, fmt.Errorf("credentials.%s: upstream policy must not have surrounding whitespace", domain)
			}
			name := strings.TrimPrefix(cc.Policy, "/")
			if name == "" {
				return warnings, fmt.Errorf("credentials.%s: upstream policy must name a policy", domain)
			}
			if _, ok := c.Policies[name]; !ok {
				return warnings, fmt.Errorf("credentials.%s: upstream policy %q is not configured", domain, cc.Policy)
			}
		}
	}
	for name, configuredPolicy := range c.Policies {
		if strings.TrimSpace(name) == "" {
			return warnings, fmt.Errorf("policy name must not be empty")
		}
		if strings.TrimSpace(name) != name || strings.HasPrefix(name, "/") {
			return warnings, fmt.Errorf("policy name %q must be a relative path without surrounding whitespace", name)
		}
		if strings.TrimSpace(configuredPolicy.Type) == "" {
			return warnings, fmt.Errorf("policies.%s: 'type' is required", name)
		}
	}
	return warnings, nil
}

func (cc *CredentialConfig) validate(domain string) (warnings []string, err error) {
	// Validate env field consistency: EnvUser and EnvPass must both be set or both absent
	if (cc.EnvUser == "") != (cc.EnvPass == "") {
		return nil, fmt.Errorf("env_user and env_pass must both be set or both absent")
	}

	switch cc.Type {
	case "bearer":
		if cc.Token == "" && cc.Env == "" {
			warnings = append(warnings, fmt.Sprintf("%s: token is empty and no env var configured", domain))
		}
	case "header":
		if strings.TrimSpace(cc.Header) == "" {
			return nil, fmt.Errorf("header requires 'header'")
		}
		if cc.Value == "" {
			return nil, fmt.Errorf("header requires 'value'")
		}
	case "basic":
		if cc.Username == "" && cc.EnvUser == "" {
			warnings = append(warnings, fmt.Sprintf("%s: username is empty and no env_user configured", domain))
		}
		if cc.Password == "" && cc.EnvPass == "" {
			warnings = append(warnings, fmt.Sprintf("%s: password is empty and no env_pass configured", domain))
		}
	case "oauth2":
		if cc.ClientID == "" {
			return nil, fmt.Errorf("oauth2 requires 'client_id'")
		}
		if cc.ClientSecret == "" {
			return nil, fmt.Errorf("oauth2 requires 'client_secret'")
		}
		if cc.RefreshToken == "" {
			return nil, fmt.Errorf("oauth2 requires 'refresh_token'")
		}
		if cc.TokenURL == "" {
			return nil, fmt.Errorf("oauth2 requires 'token_url'")
		}
	case "sigv4":
		if cc.Region == "" {
			return nil, fmt.Errorf("sigv4 requires 'region'")
		}
		if cc.Service == "" {
			return nil, fmt.Errorf("sigv4 requires 'service'")
		}
		if cc.AccessKeyID == "" {
			warnings = append(warnings, fmt.Sprintf("%s: access_key_id is empty", domain))
		}
		if cc.SecretAccessKey == "" {
			warnings = append(warnings, fmt.Sprintf("%s: secret_access_key is empty", domain))
		}
	case "":
		return nil, fmt.Errorf("'type' is required")
	default:
		// JavaScript providers validate their own opaque inline options before
		// the provider runtime is activated.
	}
	return warnings, nil
}

// ProviderConfig returns the provider-specific configuration passed to a
// CredentialProvider factory or JavaScript provider.
func (cc CredentialConfig) ProviderConfig() map[string]any {
	switch cc.Type {
	case "bearer":
		return map[string]any{"token": cc.Token}
	case "header":
		return map[string]any{
			"header": cc.Header,
			"value":  cc.Value,
		}
	case "basic":
		return map[string]any{
			"username": cc.Username,
			"password": cc.Password,
		}
	case "oauth2":
		return map[string]any{
			"client_id":     cc.ClientID,
			"client_secret": cc.ClientSecret,
			"refresh_token": cc.RefreshToken,
			"token_url":     cc.TokenURL,
		}
	case "sigv4":
		return map[string]any{
			"region":            cc.Region,
			"service":           cc.Service,
			"access_key_id":     cc.AccessKeyID,
			"secret_access_key": cc.SecretAccessKey,
		}
	default:
		result := make(map[string]any, len(cc.Options)+13)
		for key, value := range cc.Options {
			result[key] = value
		}
		copyNonEmpty := func(key, value string) {
			if value != "" {
				result[key] = value
			}
		}
		copyNonEmpty("token", cc.Token)
		copyNonEmpty("header", cc.Header)
		copyNonEmpty("value", cc.Value)
		copyNonEmpty("username", cc.Username)
		copyNonEmpty("password", cc.Password)
		copyNonEmpty("region", cc.Region)
		copyNonEmpty("service", cc.Service)
		copyNonEmpty("access_key_id", cc.AccessKeyID)
		copyNonEmpty("secret_access_key", cc.SecretAccessKey)
		copyNonEmpty("client_id", cc.ClientID)
		copyNonEmpty("client_secret", cc.ClientSecret)
		copyNonEmpty("refresh_token", cc.RefreshToken)
		copyNonEmpty("token_url", cc.TokenURL)
		return result
	}
}

// validate checks that capability hosts include the credential's configured host.
func (cap *CapabilitiesConfig) validate(domain string) []string {
	var warnings []string
	if len(cap.Hosts) == 0 {
		return warnings
	}
	found := false
	for _, h := range cap.Hosts {
		if h == domain {
			found = true
			break
		}
	}
	if !found {
		warnings = append(warnings, fmt.Sprintf(
			"%s: capability hosts %v do not include the credential host %q",
			domain, cap.Hosts, domain))
	}
	return warnings
}
