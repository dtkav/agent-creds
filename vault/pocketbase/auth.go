package pocketbase

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds the resolved PocketBase authentication configuration
type Config struct {
	URL        string // e.g. "https://auth.system3.md"
	Collection string // e.g. "bots"
	Email      string
	Password   string
}

// CachedToken holds a PB JWT token with its expiration
type CachedToken struct {
	Token     string
	ExpiresAt time.Time
}

// IsValid checks if the cached token is still valid (with 60s buffer)
func (t *CachedToken) IsValid() bool {
	return t.Token != "" && time.Now().Add(60*time.Second).Before(t.ExpiresAt)
}

// TokenManager handles PocketBase authentication and token caching
type TokenManager struct {
	mu     sync.RWMutex
	cache  map[string]*CachedToken // keyed by host
	client *http.Client
}

// NewTokenManager creates a new PocketBase token manager
func NewTokenManager() *TokenManager {
	return &TokenManager{
		cache: make(map[string]*CachedToken),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetToken returns a valid PB session token, authenticating if necessary
func (m *TokenManager) GetToken(host string, config *Config) (string, error) {
	// Check cache first (read lock)
	m.mu.RLock()
	cached, ok := m.cache[host]
	m.mu.RUnlock()

	if ok && cached.IsValid() {
		return cached.Token, nil
	}

	// Need to authenticate (write lock)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := m.cache[host]; ok && cached.IsValid() {
		return cached.Token, nil
	}

	// Perform login
	token, expiresAt, err := m.login(config)
	if err != nil {
		return "", fmt.Errorf("pocketbase login failed: %w", err)
	}

	// Cache the token
	m.cache[host] = &CachedToken{
		Token:     token,
		ExpiresAt: expiresAt,
	}

	return token, nil
}

// authResponse is the PocketBase auth-with-password response
type authResponse struct {
	Token string `json:"token"`
}

// login authenticates with PocketBase and returns the JWT token and expiry
func (m *TokenManager) login(config *Config) (string, time.Time, error) {
	loginURL := fmt.Sprintf("%s/api/collections/%s/auth-with-password", config.URL, config.Collection)

	body := fmt.Sprintf(`{"identity":%q,"password":%q}`, config.Email, config.Password)
	req, err := http.NewRequest("POST", loginURL, strings.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("auth endpoint returned %d: %s", resp.StatusCode, string(respBody))
	}

	var authResp authResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse response: %w", err)
	}

	if authResp.Token == "" {
		return "", time.Time{}, fmt.Errorf("empty token in response")
	}

	// Parse JWT exp claim for cache TTL
	expiresAt := parseJWTExpiry(authResp.Token)

	return authResp.Token, expiresAt, nil
}

// parseJWTExpiry extracts the exp claim from a JWT without verification.
// Falls back to 1 hour from now if parsing fails.
func parseJWTExpiry(token string) time.Time {
	fallback := time.Now().Add(1 * time.Hour)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fallback
	}

	// Decode payload (part 1), adding padding if needed
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try standard encoding
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return fallback
		}
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return fallback
	}

	if claims.Exp == 0 {
		return fallback
	}

	return time.Unix(claims.Exp, 0)
}
