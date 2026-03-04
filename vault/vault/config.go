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
	Type     string          `toml:"type"` // "bearer", "basic", "sigv4", or "pocketbase"
	Token    *ProviderConfig `toml:"token,omitempty"`
	Username *ProviderConfig `toml:"username,omitempty"`
	Password *ProviderConfig `toml:"password,omitempty"`

	// SigV4 fields
	Region         string          `toml:"region,omitempty"`
	Service        string          `toml:"service,omitempty"`
	AccessKeyID    *ProviderConfig `toml:"access_key_id,omitempty"`
	SecretAccessKey *ProviderConfig `toml:"secret_access_key,omitempty"`

	// PocketBase fields
	URL        string          `toml:"url,omitempty"`
	Collection string          `toml:"collection,omitempty"`
	Email      *ProviderConfig `toml:"email,omitempty"`
}

// ProviderConfig defines where a credential value comes from
type ProviderConfig struct {
	Provider string `toml:"provider"` // "env" for now
	Name     string `toml:"name"`     // env var name, file path, etc.
}

// SigV4ResolvedConfig holds resolved SigV4 credentials
type SigV4ResolvedConfig struct {
	Region         string
	Service        string
	AccessKeyID    string
	SecretAccessKey string
}

// PocketBaseResolvedConfig holds resolved PocketBase credentials
type PocketBaseResolvedConfig struct {
	URL        string
	Collection string
	Email      string
	Password   string
}

// Credential holds a resolved credential ready for injection
type Credential struct {
	Type       string // "bearer", "basic", "sigv4", or "pocketbase"
	HeaderName string // "Authorization"
	Value      string // The full header value (for bearer/basic)

	SigV4Config      *SigV4ResolvedConfig      // populated for sigv4
	PocketBaseConfig *PocketBaseResolvedConfig  // populated for pocketbase
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
	case "sigv4":
		return cc.resolveSigV4()
	case "pocketbase":
		return cc.resolvePocketBase()
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

func (cc *CredentialConfig) resolveSigV4() (*Credential, error) {
	if cc.AccessKeyID == nil || cc.SecretAccessKey == nil {
		return nil, fmt.Errorf("sigv4 credentials require 'access_key_id' and 'secret_access_key' fields")
	}
	if cc.Region == "" {
		return nil, fmt.Errorf("sigv4 credentials require 'region' field")
	}
	if cc.Service == "" {
		return nil, fmt.Errorf("sigv4 credentials require 'service' field")
	}

	accessKeyID, err := cc.AccessKeyID.GetValue()
	if err != nil {
		return nil, err
	}
	secretAccessKey, err := cc.SecretAccessKey.GetValue()
	if err != nil {
		return nil, err
	}
	if accessKeyID == "" || secretAccessKey == "" {
		return nil, nil
	}

	return &Credential{
		Type:       "sigv4",
		HeaderName: "authorization",
		SigV4Config: &SigV4ResolvedConfig{
			Region:         cc.Region,
			Service:        cc.Service,
			AccessKeyID:    accessKeyID,
			SecretAccessKey: secretAccessKey,
		},
	}, nil
}

func (cc *CredentialConfig) resolvePocketBase() (*Credential, error) {
	if cc.Email == nil || cc.Password == nil {
		return nil, fmt.Errorf("pocketbase credentials require 'email' and 'password' fields")
	}
	if cc.URL == "" {
		return nil, fmt.Errorf("pocketbase credentials require 'url' field")
	}
	if cc.Collection == "" {
		return nil, fmt.Errorf("pocketbase credentials require 'collection' field")
	}

	email, err := cc.Email.GetValue()
	if err != nil {
		return nil, err
	}
	password, err := cc.Password.GetValue()
	if err != nil {
		return nil, err
	}
	if email == "" || password == "" {
		return nil, nil
	}

	return &Credential{
		Type:       "pocketbase",
		HeaderName: "authorization",
		PocketBaseConfig: &PocketBaseResolvedConfig{
			URL:        cc.URL,
			Collection: cc.Collection,
			Email:      email,
			Password:   password,
		},
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
