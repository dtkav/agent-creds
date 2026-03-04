package vault

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the vault.yaml configuration
type Config struct {
	Secrets       map[string]string            `yaml:"secrets,omitempty"`
	SigningKey    string                       `yaml:"signing_key"`
	EncryptionKey string                      `yaml:"encryption_key,omitempty"`
	Credentials  map[string]CredentialConfig  `yaml:"credentials"`
}

// CredentialConfig defines how to inject credentials for a domain
type CredentialConfig struct {
	Type     string `yaml:"type"` // "bearer", "basic", "sigv4", or "pocketbase"
	Token    string `yaml:"token,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`

	// SigV4 fields
	Region         string `yaml:"region,omitempty"`
	Service        string `yaml:"service,omitempty"`
	AccessKeyID    string `yaml:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty"`

	// PocketBase fields
	URL        string `yaml:"url,omitempty"`
	Collection string `yaml:"collection,omitempty"`
	Email      string `yaml:"email,omitempty"`
}

// Credential holds a resolved credential ready for injection
type Credential struct {
	Type       string // "bearer", "basic", "sigv4", or "pocketbase"
	HeaderName string // "authorization"
	Value      string // The full header value (for bearer/basic)

	SigV4Config      *SigV4ResolvedConfig
	PocketBaseConfig *PocketBaseResolvedConfig
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

// Load reads and parses a vault.yaml file, resolving ${...} secret references.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vault config: %w", err)
	}

	// Resolve ${...} references from secrets map
	cfg.resolveRefs()
	return &cfg, nil
}

// resolveRefs expands ${SECRET_NAME} references using the secrets map.
func (c *Config) resolveRefs() {
	if len(c.Secrets) == 0 {
		return
	}

	resolve := func(s string) string {
		if !strings.Contains(s, "${") {
			return s
		}
		for k, v := range c.Secrets {
			s = strings.ReplaceAll(s, "${"+k+"}", v)
		}
		return s
	}

	c.SigningKey = resolve(c.SigningKey)
	c.EncryptionKey = resolve(c.EncryptionKey)

	for domain, cc := range c.Credentials {
		cc.Token = resolve(cc.Token)
		cc.Username = resolve(cc.Username)
		cc.Password = resolve(cc.Password)
		cc.AccessKeyID = resolve(cc.AccessKeyID)
		cc.SecretAccessKey = resolve(cc.SecretAccessKey)
		cc.Email = resolve(cc.Email)
		c.Credentials[domain] = cc
	}
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
	}
	return warnings, nil
}

func (cc *CredentialConfig) validate(domain string) (warnings []string, err error) {
	switch cc.Type {
	case "bearer":
		if cc.Token == "" {
			warnings = append(warnings, fmt.Sprintf("%s: token is empty", domain))
		}
	case "basic":
		if cc.Username == "" {
			warnings = append(warnings, fmt.Sprintf("%s: username is empty", domain))
		}
		if cc.Password == "" {
			warnings = append(warnings, fmt.Sprintf("%s: password is empty", domain))
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
	case "pocketbase":
		if cc.URL == "" {
			return nil, fmt.Errorf("pocketbase requires 'url'")
		}
		if cc.Collection == "" {
			return nil, fmt.Errorf("pocketbase requires 'collection'")
		}
		if cc.Email == "" {
			warnings = append(warnings, fmt.Sprintf("%s: email is empty", domain))
		}
		if cc.Password == "" {
			warnings = append(warnings, fmt.Sprintf("%s: password is empty", domain))
		}
	case "":
		return nil, fmt.Errorf("'type' is required")
	default:
		return nil, fmt.Errorf("unknown credential type: %s", cc.Type)
	}
	return warnings, nil
}

// Resolve resolves all credentials into injection-ready form
func (c *Config) Resolve() (map[string]*Credential, error) {
	credentials := make(map[string]*Credential)

	for domain, cc := range c.Credentials {
		cred, err := cc.resolve()
		if err != nil {
			return nil, fmt.Errorf("credentials.%s: %w", domain, err)
		}
		if cred != nil {
			credentials[domain] = cred
		}
	}

	return credentials, nil
}

func (cc *CredentialConfig) resolve() (*Credential, error) {
	switch cc.Type {
	case "bearer":
		if cc.Token == "" {
			return nil, nil
		}
		return &Credential{
			Type:       "bearer",
			HeaderName: "authorization",
			Value:      "Bearer " + cc.Token,
		}, nil

	case "basic":
		if cc.Username == "" || cc.Password == "" {
			return nil, nil
		}
		encoded := basicAuth(cc.Username, cc.Password)
		return &Credential{
			Type:       "basic",
			HeaderName: "authorization",
			Value:      "Basic " + encoded,
		}, nil

	case "sigv4":
		if cc.AccessKeyID == "" || cc.SecretAccessKey == "" {
			return nil, nil
		}
		return &Credential{
			Type:       "sigv4",
			HeaderName: "authorization",
			SigV4Config: &SigV4ResolvedConfig{
				Region:         cc.Region,
				Service:        cc.Service,
				AccessKeyID:    cc.AccessKeyID,
				SecretAccessKey: cc.SecretAccessKey,
			},
		}, nil

	case "pocketbase":
		if cc.Email == "" || cc.Password == "" {
			return nil, nil
		}
		return &Credential{
			Type:       "pocketbase",
			HeaderName: "authorization",
			PocketBaseConfig: &PocketBaseResolvedConfig{
				URL:        cc.URL,
				Collection: cc.Collection,
				Email:      cc.Email,
				Password:   cc.Password,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown credential type: %s", cc.Type)
	}
}

func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}
