package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"authz/db"
)

// WebAuthnHandler handles WebAuthn registration and authentication
type WebAuthnHandler struct {
	db       *db.DB
	webauthn *webauthn.WebAuthn
}

// webauthnUser implements webauthn.User interface
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnIcon() string                       { return "" }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// NewWebAuthnHandler creates a new WebAuthn handler
func NewWebAuthnHandler(database *db.DB, rpID, rpOrigin, rpName string) (*WebAuthnHandler, error) {
	if rpName == "" {
		rpName = "Agent Credentials"
	}

	wconfig := &webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Minute * 5,
				TimeoutUVD: time.Minute * 5,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Minute * 5,
				TimeoutUVD: time.Minute * 5,
			},
		},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn: %w", err)
	}

	return &WebAuthnHandler{
		db:       database,
		webauthn: wa,
	}, nil
}

// toWebAuthnUser converts a db.User to webauthnUser with credentials
func (h *WebAuthnHandler) toWebAuthnUser(user *db.User) (*webauthnUser, error) {
	creds, err := h.db.GetCredentialsByUser(user.ID)
	if err != nil {
		return nil, err
	}

	var waCreds []webauthn.Credential
	for _, c := range creds {
		waCreds = append(waCreds, webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: "",
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Name
	}

	return &webauthnUser{
		id:          user.ID,
		name:        user.Name,
		displayName: displayName,
		credentials: waCreds,
	}, nil
}

// BeginRegistrationRequest is the request to start registration
type BeginRegistrationRequest struct {
	Username string `json:"username"`
}

// BeginRegistrationResponse contains the options for navigator.credentials.create()
type BeginRegistrationResponse struct {
	Options   *protocol.CredentialCreation `json:"options"`
	SessionID string                       `json:"sessionId"`
}

// BeginRegistration starts the WebAuthn registration process
func (h *WebAuthnHandler) BeginRegistration(username string) (*BeginRegistrationResponse, error) {
	// Get user by username
	user, err := h.db.GetUserByName(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.Active {
		return nil, fmt.Errorf("user is not active")
	}

	waUser, err := h.toWebAuthnUser(user)
	if err != nil {
		return nil, err
	}

	// Begin registration
	options, session, err := h.webauthn.BeginRegistration(waUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.CrossPlatform,
			UserVerification:        protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store session in database
	// session.Challenge is already base64url encoded
	sessionID := string(session.Challenge)
	sessionData, err := encodeSessionData(session)
	if err != nil {
		return nil, err
	}

	err = h.db.CreateWebAuthnChallenge(sessionID, user.ID, sessionData, db.ChallengeTypeRegister, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	return &BeginRegistrationResponse{
		Options:   options,
		SessionID: sessionID,
	}, nil
}

// FinishRegistrationRequest contains the attestation response
type FinishRegistrationRequest struct {
	SessionID string `json:"sessionId"`
	// The raw attestation response from navigator.credentials.create()
	Response *protocol.CredentialCreationResponse `json:"response"`
}

// FinishRegistration completes the WebAuthn registration
func (h *WebAuthnHandler) FinishRegistration(req *FinishRegistrationRequest) error {
	// Get the stored challenge
	challenge, err := h.db.GetWebAuthnChallenge(req.SessionID)
	if err != nil {
		return fmt.Errorf("failed to get challenge: %w", err)
	}
	if challenge == nil {
		return fmt.Errorf("challenge not found or expired")
	}
	if challenge.Type != db.ChallengeTypeRegister {
		return fmt.Errorf("invalid challenge type")
	}

	// Get the user
	user, err := h.db.GetUser(challenge.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || !user.Active {
		return fmt.Errorf("user not found or inactive")
	}

	waUser, err := h.toWebAuthnUser(user)
	if err != nil {
		return err
	}

	// Decode session data
	session, err := decodeSessionData(challenge.Challenge)
	if err != nil {
		return err
	}

	// Parse the credential creation response
	parsedResponse, err := req.Response.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Finish registration
	credential, err := h.webauthn.CreateCredential(waUser, *session, parsedResponse)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	// Store the credential
	dbCred := &db.Credential{
		ID:        credential.ID,
		UserID:    user.ID,
		PublicKey: credential.PublicKey,
		SignCount: credential.Authenticator.SignCount,
		AAGUID:    credential.Authenticator.AAGUID,
	}

	if err := h.db.CreateCredential(dbCred); err != nil {
		return fmt.Errorf("failed to store credential: %w", err)
	}

	return nil
}

// BeginAuthenticationRequest is the request to start authentication
type BeginAuthenticationRequest struct {
	Username string `json:"username"`
}

// BeginAuthenticationResponse contains the options for navigator.credentials.get()
type BeginAuthenticationResponse struct {
	Options   *protocol.CredentialAssertion `json:"options"`
	SessionID string                        `json:"sessionId"`
}

// BeginAuthentication starts the WebAuthn authentication process
func (h *WebAuthnHandler) BeginAuthentication(username string) (*BeginAuthenticationResponse, error) {
	// Get user by username
	user, err := h.db.GetUserByName(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.Active {
		return nil, fmt.Errorf("user is not active")
	}

	waUser, err := h.toWebAuthnUser(user)
	if err != nil {
		return nil, err
	}

	if len(waUser.credentials) == 0 {
		return nil, fmt.Errorf("user has no registered credentials")
	}

	// Begin authentication
	options, session, err := h.webauthn.BeginLogin(waUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin authentication: %w", err)
	}

	// Store session in database
	// session.Challenge is already base64url encoded
	sessionID := string(session.Challenge)
	sessionData, err := encodeSessionData(session)
	if err != nil {
		return nil, err
	}

	err = h.db.CreateWebAuthnChallenge(sessionID, user.ID, sessionData, db.ChallengeTypeAuthenticate, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	return &BeginAuthenticationResponse{
		Options:   options,
		SessionID: sessionID,
	}, nil
}

// FinishAuthenticationRequest contains the assertion response
type FinishAuthenticationRequest struct {
	SessionID string `json:"sessionId"`
	// The raw assertion response from navigator.credentials.get()
	Response *protocol.CredentialAssertionResponse `json:"response"`
}

// FinishAuthenticationResponse contains the session token
type FinishAuthenticationResponse struct {
	SessionToken string `json:"sessionToken"`
	ExpiresAt    int64  `json:"expiresAt"`
	UserID       string `json:"userId"`
	Username     string `json:"username"`
}

// FinishAuthentication completes the WebAuthn authentication
func (h *WebAuthnHandler) FinishAuthentication(req *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error) {
	// Get the stored challenge
	challenge, err := h.db.GetWebAuthnChallenge(req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}
	if challenge == nil {
		return nil, fmt.Errorf("challenge not found or expired")
	}
	if challenge.Type != db.ChallengeTypeAuthenticate {
		return nil, fmt.Errorf("invalid challenge type")
	}

	// Get the user
	user, err := h.db.GetUser(challenge.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || !user.Active {
		return nil, fmt.Errorf("user not found or inactive")
	}

	waUser, err := h.toWebAuthnUser(user)
	if err != nil {
		return nil, err
	}

	// Decode session data
	session, err := decodeSessionData(challenge.Challenge)
	if err != nil {
		return nil, err
	}

	// Parse the assertion response
	parsedResponse, err := req.Response.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Finish authentication
	credential, err := h.webauthn.ValidateLogin(waUser, *session, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Update sign count
	if err := h.db.UpdateCredentialSignCount(credential.ID, credential.Authenticator.SignCount); err != nil {
		// Log but don't fail - the authentication was successful
		fmt.Printf("Warning: failed to update sign count: %v\n", err)
	}

	// Create session
	dbSession, err := h.db.CreateSession(user.ID, db.DefaultSessionDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &FinishAuthenticationResponse{
		SessionToken: dbSession.ID,
		ExpiresAt:    dbSession.ExpiresAt.Unix(),
		UserID:       base64.RawURLEncoding.EncodeToString(user.ID),
		Username:     user.Name,
	}, nil
}

// encodeSessionData serializes session data for storage
func encodeSessionData(session *webauthn.SessionData) ([]byte, error) {
	return json.Marshal(session)
}

// decodeSessionData deserializes session data
func decodeSessionData(data []byte) (*webauthn.SessionData, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
