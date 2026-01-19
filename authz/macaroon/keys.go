package macaroon

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/superfly/macaroon"
)

const (
	// TokenLocation identifies this service (used in macaroon location field)
	TokenLocation = "agent-creds"

	// TokenPrefix for encoded tokens
	TokenPrefix = "sk_"
)

// KeyStore manages signing keys for token minting and verification
type KeyStore struct {
	// SigningKey is the primary key for minting and verifying tokens
	SigningKey macaroon.SigningKey

	// EncryptionKey is for third-party caveat encryption (future use)
	EncryptionKey macaroon.EncryptionKey

	// KeyID identifies this key (stored in token for key rotation)
	KeyID []byte
}

// LoadKeyStore loads keys from environment variables
func LoadKeyStore() (*KeyStore, error) {
	// MACAROON_SIGNING_KEY: base64-encoded 32-byte key
	signingKeyB64 := os.Getenv("MACAROON_SIGNING_KEY")
	if signingKeyB64 == "" {
		return nil, fmt.Errorf("MACAROON_SIGNING_KEY environment variable required")
	}

	signingKey, err := base64.StdEncoding.DecodeString(signingKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid MACAROON_SIGNING_KEY: %w", err)
	}

	if len(signingKey) < 32 {
		return nil, fmt.Errorf("MACAROON_SIGNING_KEY must be at least 32 bytes")
	}

	// MACAROON_ENCRYPTION_KEY: optional, for 3P caveats
	var encryptionKey macaroon.EncryptionKey
	if encKeyB64 := os.Getenv("MACAROON_ENCRYPTION_KEY"); encKeyB64 != "" {
		encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
		if err != nil {
			return nil, fmt.Errorf("invalid MACAROON_ENCRYPTION_KEY: %w", err)
		}
		if len(encKey) != macaroon.EncryptionKeySize {
			return nil, fmt.Errorf("MACAROON_ENCRYPTION_KEY must be %d bytes", macaroon.EncryptionKeySize)
		}
		encryptionKey = macaroon.EncryptionKey(encKey)
	}

	// MACAROON_KEY_ID: optional key identifier (default: "primary")
	keyID := []byte(os.Getenv("MACAROON_KEY_ID"))
	if len(keyID) == 0 {
		keyID = []byte("primary")
	}

	return &KeyStore{
		SigningKey:    macaroon.SigningKey(signingKey),
		EncryptionKey: encryptionKey,
		KeyID:         keyID,
	}, nil
}

// NewToken creates a new root macaroon token
func (ks *KeyStore) NewToken() (*macaroon.Macaroon, error) {
	return macaroon.New(ks.KeyID, TokenLocation, ks.SigningKey)
}

// EncodeToken encodes a macaroon to a string with the sk_ prefix
func EncodeToken(m *macaroon.Macaroon) (string, error) {
	encoded, err := m.Encode()
	if err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// DecodeToken decodes a sk_ prefixed token string
func DecodeToken(token string) (*macaroon.Macaroon, error) {
	if len(token) < len(TokenPrefix) {
		return nil, fmt.Errorf("token too short")
	}

	if token[:len(TokenPrefix)] != TokenPrefix {
		return nil, fmt.Errorf("invalid token prefix (expected %s)", TokenPrefix)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token[len(TokenPrefix):])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	return macaroon.Decode(decoded)
}
