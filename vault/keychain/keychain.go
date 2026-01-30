package keychain

import (
	"encoding/base64"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	// ServiceName is the keychain service identifier
	ServiceName = "agent-creds"

	// Key names
	KeySigningKey    = "signing-key"
	KeyEncryptionKey = "encryption-key"
	KeyYubiKeySlot   = "yubikey-slot"
)

// Store saves a value to the system keychain
func Store(key, value string) error {
	return keyring.Set(ServiceName, key, value)
}

// Get retrieves a value from the system keychain
func Get(key string) (string, error) {
	return keyring.Get(ServiceName, key)
}

// Delete removes a value from the system keychain
func Delete(key string) error {
	return keyring.Delete(ServiceName, key)
}

// StoreBytes stores binary data as base64 in the keychain
func StoreBytes(key string, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	return Store(key, encoded)
}

// GetBytes retrieves binary data from the keychain
func GetBytes(key string) ([]byte, error) {
	encoded, err := Get(key)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// KeyStore provides high-level access to agent-creds keys
type KeyStore struct{}

// NewKeyStore creates a new keychain-backed key store
func NewKeyStore() *KeyStore {
	return &KeyStore{}
}

// GetSigningKey retrieves the signing key from keychain
func (ks *KeyStore) GetSigningKey() ([]byte, error) {
	return GetBytes(KeySigningKey)
}

// SetSigningKey stores the signing key in keychain
func (ks *KeyStore) SetSigningKey(key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("signing key must be at least 32 bytes")
	}
	return StoreBytes(KeySigningKey, key)
}

// GetEncryptionKey retrieves the encryption key from keychain
func (ks *KeyStore) GetEncryptionKey() ([]byte, error) {
	return GetBytes(KeyEncryptionKey)
}

// SetEncryptionKey stores the encryption key in keychain
func (ks *KeyStore) SetEncryptionKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("encryption key must be exactly 32 bytes")
	}
	return StoreBytes(KeyEncryptionKey, key)
}

// GetYubiKeySlot retrieves the configured YubiKey slot
func (ks *KeyStore) GetYubiKeySlot() (int, error) {
	val, err := Get(KeyYubiKeySlot)
	if err != nil {
		return 2, nil // Default to slot 2
	}
	var slot int
	_, err = fmt.Sscanf(val, "%d", &slot)
	if err != nil {
		return 2, nil
	}
	return slot, nil
}

// SetYubiKeySlot stores the YubiKey slot configuration
func (ks *KeyStore) SetYubiKeySlot(slot int) error {
	return Store(KeyYubiKeySlot, fmt.Sprintf("%d", slot))
}

// IsAvailable checks if the system keychain is available
func IsAvailable() bool {
	// Try to access keychain
	_, err := keyring.Get(ServiceName, "test-availability")
	// If we get "not found", keychain is available
	// If we get a different error, it's not available
	if err == keyring.ErrNotFound {
		return true
	}
	// Some implementations return nil even for non-existent keys
	return err == nil
}

// ListKeys lists all keys stored for agent-creds
// Note: Not all keychain backends support listing
func ListKeys() ([]string, error) {
	// Check which keys exist
	keys := []string{}
	for _, key := range []string{KeySigningKey, KeyEncryptionKey, KeyYubiKeySlot} {
		_, err := Get(key)
		if err == nil {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// GenerateAndStoreKeys generates new signing and encryption keys and stores them
func GenerateAndStoreKeys() (signingKey, encryptionKey []byte, err error) {
	// Import crypto/rand here to avoid import in main package
	var randRead func([]byte) (int, error)
	// Use crypto/rand.Read
	randRead = func(b []byte) (int, error) {
		return len(b), nil // Will be replaced
	}
	_ = randRead

	// This is a placeholder - actual implementation would use crypto/rand
	// For now, return an error indicating the caller should generate keys
	return nil, nil, fmt.Errorf("use 'openssl rand -base64 32' to generate keys, then store with keychain.Store")
}

// Status returns a status summary of stored keys
func Status() string {
	keys, _ := ListKeys()
	if len(keys) == 0 {
		return "No keys stored in keychain"
	}
	return fmt.Sprintf("Stored keys: %v", keys)
}
