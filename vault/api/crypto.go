package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// COSE key types and algorithms
const (
	coseKeyTypeOKP = 1 // Octet Key Pair (Ed25519)
	coseKeyTypeEC2 = 2 // Elliptic Curve (ECDSA)

	coseAlgES256  = -7  // ECDSA with SHA-256
	coseAlgEdDSA  = -8  // EdDSA
	coseAlgES384  = -35 // ECDSA with SHA-384
	coseAlgES512  = -36 // ECDSA with SHA-512

	// COSE key parameters
	coseKeyType = 1
	coseKeyAlg  = 3
	coseKeyX    = -2
	coseKeyY    = -3
	coseKeyCrv  = -1

	// EC curves
	coseCurveP256 = 1
	coseCurveP384 = 2
	coseCurveP521 = 3
)

// verifyAssertion verifies a WebAuthn assertion signature
func verifyAssertion(publicKey, authData, clientDataJSON, signature, challenge []byte) error {
	// Hash the client data
	clientDataHash := sha256.Sum256(clientDataJSON)

	// The signed data is authData || hash(clientDataJSON)
	signedData := make([]byte, len(authData)+32)
	copy(signedData, authData)
	copy(signedData[len(authData):], clientDataHash[:])

	// Parse the COSE public key and verify
	return verifyCOSESignature(publicKey, signedData, signature)
}

// verifyCOSESignature verifies a signature using a COSE-encoded public key
func verifyCOSESignature(coseKey, data, sig []byte) error {
	// Parse COSE key (simplified CBOR parsing)
	keyMap, err := parseCOSEKey(coseKey)
	if err != nil {
		return fmt.Errorf("failed to parse COSE key: %w", err)
	}

	keyType, ok := keyMap[coseKeyType].(int64)
	if !ok {
		return errors.New("invalid key type")
	}

	switch keyType {
	case coseKeyTypeEC2:
		return verifyEC2Signature(keyMap, data, sig)
	case coseKeyTypeOKP:
		return verifyOKPSignature(keyMap, data, sig)
	default:
		return fmt.Errorf("unsupported key type: %d", keyType)
	}
}

// verifyEC2Signature verifies an ECDSA signature
func verifyEC2Signature(keyMap map[int]interface{}, data, sig []byte) error {
	crv, ok := keyMap[coseKeyCrv].(int64)
	if !ok {
		return errors.New("missing curve")
	}

	var curve elliptic.Curve
	var hash crypto.Hash
	switch crv {
	case coseCurveP256:
		curve = elliptic.P256()
		hash = crypto.SHA256
	case coseCurveP384:
		curve = elliptic.P384()
		hash = crypto.SHA384
	case coseCurveP521:
		curve = elliptic.P521()
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported curve: %d", crv)
	}

	x, ok := keyMap[coseKeyX].([]byte)
	if !ok {
		return errors.New("missing x coordinate")
	}
	y, ok := keyMap[coseKeyY].([]byte)
	if !ok {
		return errors.New("missing y coordinate")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	// Parse the signature (could be DER or raw r||s)
	r, s, err := parseECDSASignature(sig, curve.Params().N.BitLen()/8)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Hash the data
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}

// verifyOKPSignature verifies an Ed25519 signature
func verifyOKPSignature(keyMap map[int]interface{}, data, sig []byte) error {
	x, ok := keyMap[coseKeyX].([]byte)
	if !ok {
		return errors.New("missing public key")
	}

	if len(x) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(x))
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: %d", len(sig))
	}

	if !ed25519.Verify(x, data, sig) {
		return errors.New("signature verification failed")
	}

	return nil
}

// parseECDSASignature parses an ECDSA signature from DER or raw format
func parseECDSASignature(sig []byte, keySize int) (*big.Int, *big.Int, error) {
	// Try DER format first
	var derSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &derSig); err == nil {
		return derSig.R, derSig.S, nil
	}

	// Try raw r||s format
	if len(sig) == keySize*2 {
		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])
		return r, s, nil
	}

	return nil, nil, errors.New("invalid signature format")
}

// parseCOSEKey parses a COSE key into a map
// This is a simplified CBOR parser that handles common WebAuthn key formats
func parseCOSEKey(data []byte) (map[int]interface{}, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short")
	}

	result := make(map[int]interface{})
	pos := 0

	// Expect a map (major type 5)
	majorType := data[pos] >> 5
	if majorType != 5 {
		return nil, fmt.Errorf("expected map, got major type %d", majorType)
	}

	// Get the number of pairs
	numPairs := int(data[pos] & 0x1f)
	if numPairs == 0x1f {
		return nil, errors.New("indefinite-length maps not supported")
	}
	pos++

	for i := 0; i < numPairs; i++ {
		if pos >= len(data) {
			return nil, errors.New("unexpected end of data")
		}

		// Parse key (expect negative or positive integer)
		key, newPos, err := parseCBORInt(data, pos)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key: %w", err)
		}
		pos = newPos

		// Parse value
		value, newPos, err := parseCBORValue(data, pos)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value: %w", err)
		}
		pos = newPos

		result[int(key)] = value
	}

	return result, nil
}

// parseCBORInt parses a CBOR integer (positive or negative)
func parseCBORInt(data []byte, pos int) (int64, int, error) {
	if pos >= len(data) {
		return 0, pos, errors.New("unexpected end of data")
	}

	majorType := data[pos] >> 5
	additionalInfo := data[pos] & 0x1f
	pos++

	var value uint64
	switch {
	case additionalInfo < 24:
		value = uint64(additionalInfo)
	case additionalInfo == 24:
		if pos >= len(data) {
			return 0, pos, errors.New("unexpected end of data")
		}
		value = uint64(data[pos])
		pos++
	case additionalInfo == 25:
		if pos+1 >= len(data) {
			return 0, pos, errors.New("unexpected end of data")
		}
		value = uint64(data[pos])<<8 | uint64(data[pos+1])
		pos += 2
	default:
		return 0, pos, fmt.Errorf("unsupported additional info: %d", additionalInfo)
	}

	switch majorType {
	case 0: // Positive integer
		return int64(value), pos, nil
	case 1: // Negative integer
		return -1 - int64(value), pos, nil
	default:
		return 0, pos, fmt.Errorf("expected integer, got major type %d", majorType)
	}
}

// parseCBORValue parses a CBOR value (integer or byte string)
func parseCBORValue(data []byte, pos int) (interface{}, int, error) {
	if pos >= len(data) {
		return nil, pos, errors.New("unexpected end of data")
	}

	majorType := data[pos] >> 5
	additionalInfo := data[pos] & 0x1f

	switch majorType {
	case 0, 1: // Integer
		return parseCBORInt(data, pos)
	case 2: // Byte string
		pos++
		var length int
		switch {
		case additionalInfo < 24:
			length = int(additionalInfo)
		case additionalInfo == 24:
			if pos >= len(data) {
				return nil, pos, errors.New("unexpected end of data")
			}
			length = int(data[pos])
			pos++
		case additionalInfo == 25:
			if pos+1 >= len(data) {
				return nil, pos, errors.New("unexpected end of data")
			}
			length = int(data[pos])<<8 | int(data[pos+1])
			pos += 2
		default:
			return nil, pos, fmt.Errorf("unsupported byte string length: %d", additionalInfo)
		}
		if pos+length > len(data) {
			return nil, pos, errors.New("byte string extends beyond data")
		}
		result := make([]byte, length)
		copy(result, data[pos:pos+length])
		return result, pos + length, nil
	default:
		return nil, pos, fmt.Errorf("unsupported major type: %d", majorType)
	}
}
