package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenResponse represents the OAuth2 token endpoint response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// CachedToken holds an access token with its expiration
type CachedToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

// IsValid checks if the cached token is still valid (with 60s buffer)
func (t *CachedToken) IsValid() bool {
	return t.AccessToken != "" && time.Now().Add(60*time.Second).Before(t.ExpiresAt)
}

// OAuth2Config holds configuration for token refresh
type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	TokenURL     string
}

// TokenManager handles OAuth2 token refresh and caching
type TokenManager struct {
	mu     sync.RWMutex
	cache  map[string]*CachedToken // keyed by host
	client *http.Client
}

// NewTokenManager creates a new token manager
func NewTokenManager() *TokenManager {
	return &TokenManager{
		cache: make(map[string]*CachedToken),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetAccessToken returns a valid access token, refreshing if necessary
func (m *TokenManager) GetAccessToken(host string, config *OAuth2Config) (string, error) {
	// Check cache first
	m.mu.RLock()
	cached, ok := m.cache[host]
	m.mu.RUnlock()

	if ok && cached.IsValid() {
		return cached.AccessToken, nil
	}

	// Need to refresh
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := m.cache[host]; ok && cached.IsValid() {
		return cached.AccessToken, nil
	}

	// Perform token refresh
	token, err := m.refreshToken(config)
	if err != nil {
		return "", fmt.Errorf("token refresh failed: %w", err)
	}

	// Cache the new token
	m.cache[host] = &CachedToken{
		AccessToken: token.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
	}

	return token.AccessToken, nil
}

// refreshToken performs the OAuth2 token refresh
func (m *TokenManager) refreshToken(config *OAuth2Config) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("refresh_token", config.RefreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequest("POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

// InvalidateCache removes a cached token for a host
func (m *TokenManager) InvalidateCache(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, host)
}
