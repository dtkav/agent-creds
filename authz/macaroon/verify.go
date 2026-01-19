package macaroon

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
)

// VerifyResult contains the result of token verification
type VerifyResult struct {
	// Valid is true if the token signature and caveats are valid
	Valid bool

	// Error message if verification failed
	Error string

	// Caveats contains the validated caveat set (for logging/auditing)
	Caveats *macaroon.CaveatSet
}

// Verifier handles token verification
type Verifier struct {
	keyStore *KeyStore

	// Trusted3Ps maps third-party locations to their encryption keys
	// Populated when 3P caveats are enabled
	Trusted3Ps map[string][]macaroon.EncryptionKey
}

// NewVerifier creates a new token verifier
func NewVerifier(ks *KeyStore) *Verifier {
	return &Verifier{
		keyStore:   ks,
		Trusted3Ps: make(map[string][]macaroon.EncryptionKey),
	}
}

// VerifyRequest verifies a token against a request's Access
func (v *Verifier) VerifyRequest(authHeader string, access *Access) *VerifyResult {
	// Validate access structure first
	if err := access.Validate(); err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("invalid access: %v", err)}
	}

	// Extract token from Authorization header
	token, err := extractToken(authHeader)
	if err != nil {
		return &VerifyResult{Valid: false, Error: err.Error()}
	}

	// Decode the token
	m, err := DecodeToken(token)
	if err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("failed to decode token: %v", err)}
	}

	// Verify signature (no discharge tokens for now)
	caveats, err := m.Verify(v.keyStore.SigningKey, nil, v.Trusted3Ps)
	if err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("signature verification failed: %v", err)}
	}

	// Validate caveats against the access
	if err := caveats.Validate(access); err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("caveat validation failed: %v", err)}
	}

	return &VerifyResult{Valid: true, Caveats: caveats}
}

// extractToken extracts the token from an Authorization header
// Supports: "Bearer sk_xxx" or just "sk_xxx"
func extractToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	// Handle "Bearer <token>" format
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer "), nil
	}

	// Handle raw token
	if strings.HasPrefix(header, TokenPrefix) {
		return header, nil
	}

	return "", fmt.Errorf("invalid authorization header format")
}
