package main

import (
	"encoding/base64"
	"fmt"

	"github.com/superfly/macaroon"
)

const tokenPrefix = "sk_"

// decodeToken decodes a sk_ prefixed token string
func decodeToken(token string) (*macaroon.Macaroon, error) {
	if len(token) < len(tokenPrefix) {
		return nil, fmt.Errorf("token too short")
	}

	if token[:len(tokenPrefix)] != tokenPrefix {
		return nil, fmt.Errorf("invalid token prefix (expected %s)", tokenPrefix)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token[len(tokenPrefix):])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	return macaroon.Decode(decoded)
}

// encodeToken encodes a macaroon to a string with the sk_ prefix
func encodeToken(m *macaroon.Macaroon) (string, error) {
	encoded, err := m.Encode()
	if err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(encoded), nil
}
