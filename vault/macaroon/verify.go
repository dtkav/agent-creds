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

// AttestationLocation is the third-party location for YubiKey attestation
const AttestationLocation = "yubikey-local"

// NewVerifier creates a new token verifier
func NewVerifier(ks *KeyStore) *Verifier {
	v := &Verifier{
		keyStore:   ks,
		Trusted3Ps: make(map[string][]macaroon.EncryptionKey),
	}

	// Register attestation location if encryption key is configured
	if len(ks.EncryptionKey) > 0 {
		v.AddTrusted3P(AttestationLocation, ks.EncryptionKey)
	}

	return v
}

// AddTrusted3P registers a trusted third-party location with its encryption key
func (v *Verifier) AddTrusted3P(location string, key macaroon.EncryptionKey) {
	v.Trusted3Ps[location] = append(v.Trusted3Ps[location], key)
}

// GetTokenPrefix returns the configured token prefix
func (v *Verifier) GetTokenPrefix() string {
	if v.keyStore != nil && v.keyStore.TokenPrefix != "" {
		return v.keyStore.TokenPrefix
	}
	return TokenPrefix
}

// VerifyRequest verifies a token against a request's Access
func (v *Verifier) VerifyRequest(authHeader string, access *Access) *VerifyResult {
	// Validate access structure first
	if err := access.Validate(); err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("invalid access: %v", err)}
	}

	// Extract main token and any discharge tokens from Authorization header
	mainToken, discharges, err := extractTokens(authHeader)
	if err != nil {
		return &VerifyResult{Valid: false, Error: err.Error()}
	}

	// Decode the main token
	m, err := DecodeToken(mainToken)
	if err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("failed to decode token: %v", err)}
	}

	// Decode discharge tokens
	var dischargeTokens []*macaroon.Macaroon
	for i, dt := range discharges {
		dm, err := DecodeToken(dt)
		if err != nil {
			return &VerifyResult{Valid: false, Error: fmt.Sprintf("failed to decode discharge token %d: %v", i, err)}
		}
		dischargeTokens = append(dischargeTokens, dm)
	}

	// Verify signature with discharge tokens
	caveats, err := m.VerifyParsed(v.keyStore.SigningKey, dischargeTokens, v.Trusted3Ps)
	if err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("signature verification failed: %v", err)}
	}

	// Validate caveats against the access
	if err := caveats.Validate(access); err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Sprintf("caveat validation failed: %v", err)}
	}

	return &VerifyResult{Valid: true, Caveats: caveats}
}

// extractTokens extracts the main token and any discharge tokens from an Authorization header
// Supports: "Bearer sk_main,sk_discharge1,sk_discharge2" or just "sk_main,sk_discharge"
// Returns: main token, slice of discharge tokens, error
func extractTokens(header string) (string, []string, error) {
	if header == "" {
		return "", nil, fmt.Errorf("missing authorization header")
	}

	var tokenStr string
	// Handle "Bearer <tokens>" format
	if strings.HasPrefix(header, "Bearer ") {
		tokenStr = strings.TrimPrefix(header, "Bearer ")
	} else if strings.HasPrefix(header, TokenPrefix) {
		tokenStr = header
	} else {
		return "", nil, fmt.Errorf("invalid authorization header format")
	}

	// Split by comma to get main token and discharges
	tokens := strings.Split(tokenStr, ",")
	if len(tokens) == 0 || tokens[0] == "" {
		return "", nil, fmt.Errorf("no token found")
	}

	mainToken := strings.TrimSpace(tokens[0])
	if !strings.HasPrefix(mainToken, TokenPrefix) {
		return "", nil, fmt.Errorf("invalid main token prefix")
	}

	var discharges []string
	for _, t := range tokens[1:] {
		t = strings.TrimSpace(t)
		if t != "" {
			if !strings.HasPrefix(t, TokenPrefix) {
				return "", nil, fmt.Errorf("invalid discharge token prefix")
			}
			discharges = append(discharges, t)
		}
	}

	return mainToken, discharges, nil
}

// extractToken extracts a single token from an Authorization header (legacy, for simple cases)
// Supports: "Bearer sk_xxx" or just "sk_xxx"
func extractToken(header string) (string, error) {
	main, _, err := extractTokens(header)
	return main, err
}

// IsMacaroonAuth checks if an Authorization header contains a macaroon token
// Returns true if the header is "Bearer <prefix>..." or just "<prefix>..."
func IsMacaroonAuth(header, prefix string) bool {
	if header == "" {
		return false
	}

	if prefix == "" {
		prefix = TokenPrefix
	}

	var tokenStr string
	if strings.HasPrefix(header, "Bearer ") {
		tokenStr = strings.TrimPrefix(header, "Bearer ")
	} else {
		tokenStr = header
	}

	// Check if the first token (before any comma) has the macaroon prefix
	if idx := strings.Index(tokenStr, ","); idx > 0 {
		tokenStr = tokenStr[:idx]
	}
	tokenStr = strings.TrimSpace(tokenStr)

	return strings.HasPrefix(tokenStr, prefix)
}
