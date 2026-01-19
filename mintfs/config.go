package main

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config defines the mintfs configuration
type Config struct {
	// MountPoint is where to mount the filesystem
	MountPoint string `toml:"mount_point"`

	// Credentials defines the available credential files
	Credentials map[string]CredentialConfig `toml:"credentials"`
}

// CredentialConfig defines a single credential that can be attenuated
type CredentialConfig struct {
	// BaseToken is the macaroon token to attenuate
	BaseToken string `toml:"base_token"`

	// BaseTokenFile is an alternative to BaseToken - read token from file
	BaseTokenFile string `toml:"base_token_file"`

	// Expiry is how long the attenuated token should be valid
	Expiry Duration `toml:"expiry"`
}

// Duration is a wrapper for time.Duration that supports TOML unmarshaling
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	dur, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// LoadConfig loads configuration from a TOML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Resolve base tokens from files if specified
	for name, cred := range cfg.Credentials {
		if cred.BaseTokenFile != "" && cred.BaseToken == "" {
			token, err := os.ReadFile(cred.BaseTokenFile)
			if err != nil {
				return nil, fmt.Errorf("reading token file for %s: %w", name, err)
			}
			cred.BaseToken = string(token)
			cfg.Credentials[name] = cred
		}
		if cred.BaseToken == "" {
			return nil, fmt.Errorf("credential %s: base_token or base_token_file required", name)
		}
	}

	return &cfg, nil
}
