package vault

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the vault.toml configuration
type Config struct {
	Credentials map[string]CredentialConfig `toml:"credentials"`
}

// CredentialConfig defines how to inject credentials for a domain
type CredentialConfig struct {
	Type     string          `toml:"type"` // "bearer" or "basic"
	Token    *ProviderConfig `toml:"token,omitempty"`
	Username *ProviderConfig `toml:"username,omitempty"`
	Password *ProviderConfig `toml:"password,omitempty"`
}

// ProviderConfig defines where a credential value comes from
type ProviderConfig struct {
	Provider string `toml:"provider"` // "env" for now
	Name     string `toml:"name"`     // env var name, file path, etc.
}

// Credential holds a resolved credential ready for injection
type Credential struct {
	Type       string // "bearer" or "basic"
	HeaderName string // "Authorization"
	Value      string // The full header value
}

// Load reads and parses a vault.toml file
func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vault.toml: %w", err)
	}
	return &cfg, nil
}

// Resolve resolves all credentials from their providers
func (c *Config) Resolve() (map[string]*Credential, error) {
	credentials := make(map[string]*Credential)

	for domain, cc := range c.Credentials {
		cred, err := cc.Resolve()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve credentials for %s: %w", domain, err)
		}
		if cred != nil {
			credentials[domain] = cred
		}
	}

	return credentials, nil
}

// Resolve resolves a single credential config into a usable credential
func (cc *CredentialConfig) Resolve() (*Credential, error) {
	switch cc.Type {
	case "bearer":
		return cc.resolveBearer()
	case "basic":
		return cc.resolveBasic()
	default:
		return nil, fmt.Errorf("unknown credential type: %s", cc.Type)
	}
}

func (cc *CredentialConfig) resolveBearer() (*Credential, error) {
	if cc.Token == nil {
		return nil, fmt.Errorf("bearer credentials require 'token' field")
	}

	token, err := cc.Token.GetValue()
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil // No credential configured
	}

	return &Credential{
		Type:       "bearer",
		HeaderName: "authorization",
		Value:      "Bearer " + token,
	}, nil
}

func (cc *CredentialConfig) resolveBasic() (*Credential, error) {
	if cc.Username == nil || cc.Password == nil {
		return nil, fmt.Errorf("basic credentials require 'username' and 'password' fields")
	}

	username, err := cc.Username.GetValue()
	if err != nil {
		return nil, err
	}
	password, err := cc.Password.GetValue()
	if err != nil {
		return nil, err
	}
	if username == "" || password == "" {
		return nil, nil // No credential configured
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return &Credential{
		Type:       "basic",
		HeaderName: "authorization",
		Value:      "Basic " + encoded,
	}, nil
}

// GetValue retrieves the value from the configured provider
func (pc *ProviderConfig) GetValue() (string, error) {
	switch pc.Provider {
	case "env":
		return os.Getenv(pc.Name), nil
	default:
		return "", fmt.Errorf("unknown provider: %s", pc.Provider)
	}
}
