package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/superfly/macaroon"
)

const (
	agentCredentialPrefix = "acm_"
	hotCredentialTTL      = time.Hour
	hotCredentialSkew     = 30 * time.Second
)

var credentialFilenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func validCredentialFilename(name string) bool {
	return credentialFilenamePattern.MatchString(name) && name != "." && name != ".."
}

func credentialBrokerDir(instanceGenDir string) string {
	generatedDir := filepath.Dir(filepath.Dir(instanceGenDir))
	return filepath.Join(generatedDir, "credential-broker", filepath.Base(instanceGenDir))
}

func credentialAuthzDir(instanceGenDir string) string {
	return filepath.Join(credentialBrokerDir(instanceGenDir), "authz")
}

// prepareCredentialAuthzDir keeps stable primaries outside the directory that
// is projected into the sandbox. Older adev versions cached them below the
// instance directory, so migrate that cache before launching the sandbox.
func prepareCredentialAuthzDir(instanceGenDir string) (string, error) {
	authzDir := credentialAuthzDir(instanceGenDir)
	if err := os.MkdirAll(filepath.Dir(authzDir), 0700); err != nil {
		return "", fmt.Errorf("creating credential broker: %w", err)
	}

	legacyDir := filepath.Join(instanceGenDir, "authz")
	if _, err := os.Stat(legacyDir); err == nil {
		if _, err := os.Stat(authzDir); os.IsNotExist(err) {
			if err := os.Rename(legacyDir, authzDir); err != nil {
				return "", fmt.Errorf("migrating legacy token cache: %w", err)
			}
		} else if err != nil {
			return "", fmt.Errorf("checking credential broker cache: %w", err)
		} else {
			items, err := os.ReadDir(legacyDir)
			if err != nil {
				return "", fmt.Errorf("reading legacy token cache: %w", err)
			}
			for _, item := range items {
				if item.IsDir() {
					return "", fmt.Errorf("legacy token cache contains unexpected directory %q", item.Name())
				}
				source := filepath.Join(legacyDir, item.Name())
				destination := filepath.Join(authzDir, item.Name())
				if _, err := os.Stat(destination); err == nil {
					// The broker-private copy wins; the legacy copy must not
					// remain beneath the sandbox-visible instance directory.
					if err := os.Remove(source); err != nil {
						return "", fmt.Errorf("removing migrated token %q: %w", item.Name(), err)
					}
				} else if !os.IsNotExist(err) {
					return "", fmt.Errorf("checking migrated token %q: %w", item.Name(), err)
				} else if err := os.Rename(source, destination); err != nil {
					return "", fmt.Errorf("migrating token %q: %w", item.Name(), err)
				}
			}
			if err := os.Remove(legacyDir); err != nil {
				return "", fmt.Errorf("removing legacy token cache: %w", err)
			}
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("checking legacy token cache: %w", err)
	}

	if err := os.MkdirAll(authzDir, 0700); err != nil {
		return "", fmt.Errorf("creating token cache: %w", err)
	}
	if err := os.Chmod(authzDir, 0700); err != nil {
		return "", fmt.Errorf("protecting token cache: %w", err)
	}
	return authzDir, nil
}

func credentialProjectionDir(instanceGenDir string) string {
	return filepath.Join(instanceGenDir, "credentials")
}

func hasCredentialFileEntries(entries []TokenEntry) bool {
	for _, entry := range entries {
		if entry.CredentialFile != "" {
			return true
		}
	}
	return false
}

func (e TokenEntry) deliveryName() string {
	if e.CredentialFile != "" {
		return "/run/credentials/" + e.CredentialFile
	}
	return e.EnvVar
}

func newTokenEntry(host string, upstream UpstreamConfig, envVar, combined string, now time.Time) (TokenEntry, error) {
	entry := TokenEntry{
		EnvVar:         envVar,
		CredentialFile: upstream.CredentialFile,
		Combined:       combined,
		Host:           host,
	}
	if entry.CredentialFile == "" {
		return entry, nil
	}
	if !validCredentialFilename(entry.CredentialFile) {
		return TokenEntry{}, fmt.Errorf("invalid credential filename %q", entry.CredentialFile)
	}
	hot, err := attenuateAgentCredential(combined, now, hotCredentialTTL)
	if err != nil {
		return TokenEntry{}, err
	}
	entry.EnvVar = ""
	entry.Combined = hot
	return entry, nil
}

func decodeAgentCredential(encoded string) (*macaroon.Macaroon, error) {
	if !strings.HasPrefix(encoded, agentCredentialPrefix) {
		return nil, fmt.Errorf("credential does not use the %s prefix", agentCredentialPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, agentCredentialPrefix))
	if err != nil {
		return nil, fmt.Errorf("decode credential: %w", err)
	}
	return macaroon.Decode(raw)
}

func encodeAgentCredential(value *macaroon.Macaroon) (string, error) {
	raw, err := value.Encode()
	if err != nil {
		return "", err
	}
	return agentCredentialPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// attenuateAgentCredential derives a short-lived primary from a stable
// primary+discharge pair. Existing terminal validity on either token clamps
// the requested expiry; discharges remain byte-for-byte unchanged.
func attenuateAgentCredential(combined string, now time.Time, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("credential TTL must be positive")
	}
	parts := strings.Split(strings.TrimSpace(combined), ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "", fmt.Errorf("combined credential has no primary")
	}

	expiresAt := now.Add(ttl).Unix()
	for _, part := range parts {
		token, err := decodeAgentCredential(strings.TrimSpace(part))
		if err != nil {
			return "", err
		}
		for _, window := range macaroon.GetCaveats[*macaroon.ValidityWindow](&token.UnsafeCaveats) {
			if window.NotAfter > 0 && window.NotAfter < expiresAt {
				expiresAt = window.NotAfter
			}
		}
	}
	if expiresAt <= now.Unix() {
		return "", fmt.Errorf("stable credential is already expired")
	}

	primary, err := decodeAgentCredential(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", err
	}
	if err := primary.Add(&macaroon.ValidityWindow{
		NotBefore: now.Add(-hotCredentialSkew).Unix(),
		NotAfter:  expiresAt,
	}); err != nil {
		return "", fmt.Errorf("attenuate credential: %w", err)
	}
	parts[0], err = encodeAgentCredential(primary)
	if err != nil {
		return "", fmt.Errorf("encode attenuated credential: %w", err)
	}
	return strings.Join(parts, ","), nil
}

func materializeCredentialFiles(instanceGenDir string, entries []TokenEntry) error {
	dir := credentialProjectionDir(instanceGenDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating credential projection: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("protecting credential projection: %w", err)
	}
	wanted := make(map[string]struct{})
	for _, entry := range entries {
		if entry.CredentialFile == "" {
			continue
		}
		if !validCredentialFilename(entry.CredentialFile) {
			return fmt.Errorf("invalid credential filename %q", entry.CredentialFile)
		}
		if _, duplicate := wanted[entry.CredentialFile]; duplicate {
			return fmt.Errorf("duplicate credential filename %q", entry.CredentialFile)
		}
		wanted[entry.CredentialFile] = struct{}{}
	}

	for _, entry := range entries {
		if entry.CredentialFile == "" {
			continue
		}
		temporaryFile, err := os.CreateTemp(dir, "."+entry.CredentialFile+".tmp-")
		if err != nil {
			return fmt.Errorf("creating temporary credential %q: %w", entry.CredentialFile, err)
		}
		temporary := temporaryFile.Name()
		published := false
		defer func() {
			if !published {
				_ = os.Remove(temporary)
			}
		}()
		final := filepath.Join(dir, entry.CredentialFile)
		if _, err := temporaryFile.WriteString(entry.Combined + "\n"); err != nil {
			_ = temporaryFile.Close()
			return fmt.Errorf("writing credential %q: %w", entry.CredentialFile, err)
		}
		if err := temporaryFile.Chmod(0400); err != nil {
			_ = temporaryFile.Close()
			return fmt.Errorf("protecting credential %q: %w", entry.CredentialFile, err)
		}
		if err := temporaryFile.Close(); err != nil {
			return fmt.Errorf("closing credential %q: %w", entry.CredentialFile, err)
		}
		if err := os.Rename(temporary, final); err != nil {
			return fmt.Errorf("publishing credential %q: %w", entry.CredentialFile, err)
		}
		published = true
	}

	existing, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("listing credential projection: %w", err)
	}
	for _, item := range existing {
		if item.IsDir() || strings.HasPrefix(item.Name(), ".") {
			continue
		}
		if _, keep := wanted[item.Name()]; !keep {
			if err := os.Remove(filepath.Join(dir, item.Name())); err != nil {
				return fmt.Errorf("removing stale credential %q: %w", item.Name(), err)
			}
		}
	}
	return nil
}
