package attestation

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/superfly/macaroon"

	tfmac "authz/macaroon"
)

// SessionManager manages attestation sessions
type SessionManager struct {
	// sessionKey is derived from YubiKey response, held in memory
	sessionKey []byte

	// encryptionKey is used to decrypt third-party caveat tickets
	encryptionKey macaroon.EncryptionKey

	// salt used in session key derivation
	salt []byte
}

// NewSessionManager creates a new session manager with YubiKey attestation
func NewSessionManager(encryptionKey macaroon.EncryptionKey) *SessionManager {
	return &SessionManager{
		encryptionKey: encryptionKey,
	}
}

// StartSession performs YubiKey attestation and derives a session key
func (s *SessionManager) StartSession(yk *YubiKey) error {
	// Generate random challenge
	challenge, err := GenerateChallenge()
	if err != nil {
		return err
	}

	// Prompt user and get YubiKey response
	fmt.Println("Touch your YubiKey to authenticate...")
	response, err := yk.ChallengeResponse(challenge)
	if err != nil {
		return err
	}

	// Generate salt for this session
	s.salt = make([]byte, 16)
	if _, err := rand.Read(s.salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive session key
	s.sessionKey = DeriveSessionKey(response, s.salt)

	return nil
}

// IsAuthenticated returns true if a valid session exists
func (s *SessionManager) IsAuthenticated() bool {
	return len(s.sessionKey) > 0
}

// ClearSession clears the session key
func (s *SessionManager) ClearSession() {
	// Zero out the key
	for i := range s.sessionKey {
		s.sessionKey[i] = 0
	}
	s.sessionKey = nil
	s.salt = nil
}

// CreateDischarge creates a discharge macaroon for a third-party caveat
// The akey file contains a macaroon with a 3P caveat; this creates the discharge
func (s *SessionManager) CreateDischarge(mainToken *macaroon.Macaroon) (*macaroon.Macaroon, error) {
	if !s.IsAuthenticated() {
		return nil, fmt.Errorf("not authenticated - call StartSession first")
	}

	// Get third-party caveats from the main token
	caveats := mainToken.UnsafeCaveats

	// Look for attestation 3P caveats
	for _, c := range caveats.Caveats {
		if tp, ok := c.(*macaroon.Caveat3P); ok {
			if tp.Location == tfmac.AttestationLocation {
				// Create discharge for this caveat
				discharge, err := s.createDischargeForTicket(tp)
				if err != nil {
					return nil, fmt.Errorf("failed to create discharge: %w", err)
				}
				return discharge, nil
			}
		}
	}

	return nil, fmt.Errorf("no attestation caveat found in token")
}

// createDischargeForTicket creates a discharge macaroon for a specific 3P caveat
func (s *SessionManager) createDischargeForTicket(caveat *macaroon.Caveat3P) (*macaroon.Macaroon, error) {
	// Discharge the third-party caveat
	// The session key serves as proof of YubiKey attestation
	// DischargeTicket returns ([]Caveat, *Macaroon, error)
	_, discharge, err := macaroon.DischargeTicket(s.encryptionKey, caveat.Location, caveat.Ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to discharge ticket: %w", err)
	}

	// Add validity window to discharge (short-lived)
	now := time.Now()
	if err := discharge.Add(&macaroon.ValidityWindow{
		NotBefore: now.Unix(),
		NotAfter:  now.Add(1 * time.Hour).Unix(),
	}); err != nil {
		return nil, fmt.Errorf("failed to add validity to discharge: %w", err)
	}

	return discharge, nil
}

// EncodeDischarge encodes a discharge macaroon to string
func EncodeDischarge(d *macaroon.Macaroon) (string, error) {
	return tfmac.EncodeToken(d)
}

// CombineTokens combines a main token and discharge into the format expected by authz
func CombineTokens(mainToken, discharge string) string {
	return mainToken + "," + discharge
}

// Add3PCaveat adds a third-party attestation caveat to a macaroon
// This is used when creating .akey files
func Add3PCaveat(m *macaroon.Macaroon, encryptionKey macaroon.EncryptionKey) error {
	// Generate random nonce for this caveat
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create an attestation caveat - the "ticket" data is just a nonce
	// that will be included in the discharge
	err := m.Add3P(encryptionKey, tfmac.AttestationLocation, &AttestationCaveat{
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return fmt.Errorf("failed to add 3P caveat: %w", err)
	}

	return nil
}

// AttestationCaveat is included in the 3P ticket
// It's validated by the discharge service
type AttestationCaveat struct {
	Nonce string `json:"nonce"`
}

// CaveatType returns the caveat type
func (c *AttestationCaveat) CaveatType() macaroon.CaveatType {
	return tfmac.CavAttestation
}

// Name returns the caveat name
func (c *AttestationCaveat) Name() string {
	return "Attestation"
}

// Prohibits checks if this caveat prohibits the access
func (c *AttestationCaveat) Prohibits(f macaroon.Access) error {
	// The attestation caveat is validated by the presence of a valid discharge
	// No additional checks needed here
	return nil
}

func init() {
	macaroon.RegisterCaveatType(&AttestationCaveat{})
}
