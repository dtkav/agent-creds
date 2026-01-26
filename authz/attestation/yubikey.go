package attestation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

// YubiKey handles YubiKey HMAC-SHA1 challenge-response operations
type YubiKey struct {
	// Slot for HMAC-SHA1 (usually 1 or 2)
	Slot int
}

// NewYubiKey creates a new YubiKey handler
func NewYubiKey(slot int) *YubiKey {
	if slot == 0 {
		slot = 2 // Default to slot 2 for HMAC-SHA1
	}
	return &YubiKey{Slot: slot}
}

// ChallengeResponse performs HMAC-SHA1 challenge-response with YubiKey touch
// Returns the HMAC response (20 bytes for HMAC-SHA1, used to derive session key)
func (y *YubiKey) ChallengeResponse(challenge []byte) ([]byte, error) {
	// Use ykchalresp command (from ykman or yubikey-personalization)
	challengeHex := hex.EncodeToString(challenge)

	// Try ykman first (newer), fall back to ykchalresp (older)
	var cmd *exec.Cmd
	cmd = exec.Command("ykchalresp", fmt.Sprintf("-%d", y.Slot), "-H", challengeHex)

	output, err := cmd.Output()
	if err != nil {
		// Try alternative: ykman
		cmd = exec.Command("ykman", "otp", "calculate", fmt.Sprintf("%d", y.Slot), challengeHex)
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("YubiKey challenge-response failed: %w (is YubiKey connected?)", err)
		}
	}

	// Parse hex response
	responseHex := strings.TrimSpace(string(output))
	response, err := hex.DecodeString(responseHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode YubiKey response: %w", err)
	}

	return response, nil
}

// GenerateChallenge creates a random challenge for YubiKey
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}

// DeriveSessionKey derives a 32-byte session key from YubiKey HMAC response
func DeriveSessionKey(yubikeyResponse []byte, salt []byte) []byte {
	h := hmac.New(sha256.New, yubikeyResponse)
	h.Write(salt)
	h.Write([]byte("agent-creds-session-key"))
	return h.Sum(nil)
}

// IsAvailable checks if YubiKey tools are available
func IsAvailable() bool {
	_, err := exec.LookPath("ykchalresp")
	if err == nil {
		return true
	}
	_, err = exec.LookPath("ykman")
	return err == nil
}

// SetupInfo provides information about YubiKey setup
func SetupInfo() string {
	return `YubiKey Setup for HMAC-SHA1 Challenge-Response:

1. Install yubikey-manager:
   - macOS: brew install ykman
   - Linux: apt install yubikey-manager

2. Configure HMAC-SHA1 on slot 2:
   ykman otp chalresp --touch 2

   This will:
   - Generate a random secret
   - Require touch for each operation
   - Store in slot 2

3. Test the setup:
   ykman otp calculate 2 "test"

Note: Touch is required for EACH challenge-response operation.
For mintfs, touch is only required at session start.
`
}
