package api

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
)

// handleRegisterBegin handles POST /api/webauthn/register/begin
func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req BeginRegistrationRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	resp, err := s.webauthn.BeginRegistration(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleRegisterFinish handles POST /api/webauthn/register/finish
func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req FinishRegistrationRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.webauthn.FinishRegistration(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// AuthChallengeRequest is the request for CLI authentication challenge
type AuthChallengeRequest struct {
	Username string `json:"username"`
}

// AuthChallengeResponse contains the challenge for CLI authentication
type AuthChallengeResponse struct {
	SessionID     string   `json:"sessionId"`
	Challenge     string   `json:"challenge"`     // base64url encoded
	RPID          string   `json:"rpId"`
	CredentialIDs []string `json:"credentialIds"` // base64url encoded credential IDs
	UserID        string   `json:"userId"`        // hex encoded
}

// handleAuthChallenge handles POST /api/auth/challenge
// This is used by CLI tools to get a challenge for FIDO2 authentication
func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req AuthChallengeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	// Use WebAuthn to begin authentication
	resp, err := s.webauthn.BeginAuthentication(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get user for response
	user, _ := s.db.GetUserByName(req.Username)
	userIDHex := ""
	if user != nil {
		userIDHex = hex.EncodeToString(user.ID)
	}

	// Convert credential IDs to base64url
	var credIDs []string
	for _, cred := range resp.Options.Response.AllowedCredentials {
		credIDs = append(credIDs, base64.RawURLEncoding.EncodeToString(cred.CredentialID))
	}

	writeJSON(w, http.StatusOK, AuthChallengeResponse{
		SessionID:     resp.SessionID,
		Challenge:     base64.RawURLEncoding.EncodeToString(resp.Options.Response.Challenge),
		RPID:          resp.Options.Response.RelyingPartyID,
		CredentialIDs: credIDs,
		UserID:        userIDHex,
	})
}

// AuthVerifyRequest is the assertion verification request from CLI
type AuthVerifyRequest struct {
	SessionID       string `json:"sessionId"`
	CredentialID    string `json:"credentialId"`    // base64url
	AuthenticatorData string `json:"authenticatorData"` // base64url
	ClientDataJSON  string `json:"clientDataJSON"`  // base64url
	Signature       string `json:"signature"`       // base64url
	UserHandle      string `json:"userHandle,omitempty"` // base64url
}

// handleAuthVerify handles POST /api/auth/verify
// This verifies the FIDO2 assertion from CLI and returns a session token
func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req AuthVerifyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Decode the assertion components
	credentialID, err := base64.RawURLEncoding.DecodeString(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credentialId")
		return
	}

	authenticatorData, err := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid authenticatorData")
		return
	}

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid clientDataJSON")
		return
	}

	signature, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	var userHandle []byte
	if req.UserHandle != "" {
		userHandle, err = base64.RawURLEncoding.DecodeString(req.UserHandle)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid userHandle")
			return
		}
	}

	// Get the stored challenge
	challenge, err := s.db.GetWebAuthnChallenge(req.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if challenge == nil {
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
		return
	}

	// Get the credential
	cred, err := s.db.GetCredential(credentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cred == nil {
		writeError(w, http.StatusBadRequest, "credential not found")
		return
	}

	// Verify the credential belongs to the challenged user
	if !bytesEqual(cred.UserID, challenge.UserID) {
		writeError(w, http.StatusBadRequest, "credential does not belong to user")
		return
	}

	// Get user
	user, err := s.db.GetUser(cred.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil || !user.Active {
		writeError(w, http.StatusBadRequest, "user not found or inactive")
		return
	}

	// Verify the signature
	if err := verifyAssertion(cred.PublicKey, authenticatorData, clientDataJSON, signature, challenge.Challenge); err != nil {
		writeError(w, http.StatusUnauthorized, "signature verification failed: "+err.Error())
		return
	}

	// Extract sign count from authenticator data and update
	signCount := extractSignCount(authenticatorData)
	if signCount > cred.SignCount {
		s.db.UpdateCredentialSignCount(credentialID, signCount)
	}

	// Create session
	session, err := s.db.CreateSession(user.ID, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, FinishAuthenticationResponse{
		SessionToken: session.ID,
		ExpiresAt:    session.ExpiresAt.Unix(),
		UserID:       hex.EncodeToString(user.ID),
		Username:     user.Name,
	})

	// Ignore userHandle for now - it's optional
	_ = userHandle
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// extractSignCount extracts the signature counter from authenticator data
func extractSignCount(authData []byte) uint32 {
	if len(authData) < 37 {
		return 0
	}
	// Sign count is at bytes 33-36 (big endian)
	return uint32(authData[33])<<24 | uint32(authData[34])<<16 | uint32(authData[35])<<8 | uint32(authData[36])
}
