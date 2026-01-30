package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an API client for the authz service
type Client struct {
	baseURL      string
	httpClient   *http.Client
	sessionToken string
}

// NewClient creates a new API client
func NewClient(baseURL string, insecureSkipVerify bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// SetSessionToken sets the session token for authenticated requests
func (c *Client) SetSessionToken(token string) {
	c.sessionToken = token
}

// GetSessionToken returns the current session token
func (c *Client) GetSessionToken() string {
	return c.sessionToken
}

// AuthChallengeResponse contains the challenge for FIDO2 authentication
type AuthChallengeResponse struct {
	SessionID     string   `json:"sessionId"`
	Challenge     string   `json:"challenge"`     // base64url encoded
	RPID          string   `json:"rpId"`
	CredentialIDs []string `json:"credentialIds"` // base64url encoded
	UserID        string   `json:"userId"`
}

// GetAuthChallenge requests an authentication challenge
func (c *Client) GetAuthChallenge(username string) (*AuthChallengeResponse, error) {
	body := map[string]string{"username": username}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(c.baseURL+"/api/auth/challenge", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result AuthChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// AuthVerifyRequest is the assertion verification request
type AuthVerifyRequest struct {
	SessionID         string `json:"sessionId"`
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// AuthVerifyResponse contains the session token
type AuthVerifyResponse struct {
	SessionToken string `json:"sessionToken"`
	ExpiresAt    int64  `json:"expiresAt"`
	UserID       string `json:"userId"`
	Username     string `json:"username"`
}

// VerifyAuth verifies a FIDO2 assertion and returns a session
func (c *Client) VerifyAuth(req *AuthVerifyRequest) (*AuthVerifyResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(c.baseURL+"/api/auth/verify", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result AuthVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	c.sessionToken = result.SessionToken
	return &result, nil
}

// TokenResponse represents a token
type TokenResponse struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
}

// HotTokenResponse contains a usable token
type HotTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

// ListTokens returns all tokens the user has access to
func (c *Client) ListTokens() ([]TokenResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/tokens", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.sessionToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result []TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// GetHotToken retrieves a hot token (with discharge if needed)
func (c *Client) GetHotToken(tokenID string) (*HotTokenResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/tokens/"+tokenID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.sessionToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result HotTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// parseError extracts error message from response
func (c *Client) parseError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return fmt.Errorf("%s: %s", resp.Status, errResp.Error)
	}
	return fmt.Errorf("%s: %s", resp.Status, string(body))
}

// DecodeChallenge decodes a base64url challenge to bytes
func DecodeChallenge(challenge string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(challenge)
}

// EncodeBytes encodes bytes to base64url
func EncodeBytes(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
