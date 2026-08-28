package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"vault/db"
)

// WebAuthnHandler handles WebAuthn registration and authentication
type WebAuthnHandler struct {
	db               *db.DB
	webauthn         *webauthn.WebAuthn
	userVerification protocol.UserVerificationRequirement
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
func NewWebAuthnHandler(database *db.DB, rpID, rpOrigin, rpName, userVerification string) (*WebAuthnHandler, error) {
	if rpName == "" {
		rpName = "Agent Credentials"
	}
	verification, err := parseUserVerification(userVerification)
	if err != nil {
		return nil, err
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
		db:               database,
		webauthn:         wa,
		userVerification: verification,
	}, nil
}

func parseUserVerification(value string) (protocol.UserVerificationRequirement, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(protocol.VerificationPreferred):
		return protocol.VerificationPreferred, nil
	case string(protocol.VerificationRequired):
		return protocol.VerificationRequired, nil
	default:
		return "", fmt.Errorf("invalid WebAuthn user verification %q: use preferred or required", value)
	}
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
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: h.userVerification,
		}),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
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
		return fmt.Errorf("failed to create credential: %s", webAuthnErrorMessage("registration", err))
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

// webAuthnErrorMessage preserves useful validation failures without returning
// low-level protocol data (such as RP hashes) to the browser.
func webAuthnErrorMessage(ceremony string, err error) string {
	var protocolErr *protocol.Error
	if !errors.As(err, &protocolErr) {
		return err.Error()
	}

	log.Printf("WebAuthn %s failed: type=%s details=%q debug=%q", ceremony, protocolErr.Type, protocolErr.Details, protocolErr.DevInfo)
	debug := strings.ToLower(protocolErr.DevInfo)
	switch {
	case strings.Contains(debug, "rp hash mismatch"):
		return "the authenticator used a different relying-party ID; reload Vault at its configured URL and try again"
	case strings.Contains(debug, "user presence flag not set"):
		return "the authenticator did not confirm user presence; complete the touch or device prompt and try again"
	case strings.Contains(debug, "user verification required"):
		return "the authenticator did not perform user verification; use a passkey provider or a security key with a PIN or biometric configured"
	case protocolErr.Details != "":
		return protocolErr.Details
	default:
		return "WebAuthn validation failed"
	}
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
	options, session, err := h.webauthn.BeginLogin(
		waUser,
		webauthn.WithUserVerification(h.userVerification),
	)
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

// BeginPasskeyAuthentication starts either a discoverable, username-less
// passkey ceremony or a username-assisted ceremony for older non-resident
// credentials.
func (h *WebAuthnHandler) BeginPasskeyAuthentication(username string) (*BeginAuthenticationResponse, error) {
	var (
		options *protocol.CredentialAssertion
		session *webauthn.SessionData
		userID  []byte
		err     error
	)
	if username == "" {
		options, session, err = h.webauthn.BeginDiscoverableLogin(
			webauthn.WithUserVerification(h.userVerification),
		)
	} else {
		user, getErr := h.db.GetUserByName(username)
		if getErr != nil {
			return nil, fmt.Errorf("failed to get user: %w", getErr)
		}
		if user == nil || !user.Active {
			return nil, fmt.Errorf("user not found or inactive")
		}
		waUser, userErr := h.toWebAuthnUser(user)
		if userErr != nil {
			return nil, userErr
		}
		if len(waUser.credentials) == 0 {
			return nil, fmt.Errorf("user has no registered credentials")
		}
		options, session, err = h.webauthn.BeginLogin(
			waUser,
			webauthn.WithUserVerification(h.userVerification),
		)
		userID = append([]byte(nil), user.ID...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to begin passkey authentication: %w", err)
	}
	sessionID := string(session.Challenge)
	sessionData, err := encodeSessionData(session)
	if err != nil {
		return nil, err
	}
	if err := h.db.CreateWebAuthnChallenge(sessionID, userID, sessionData, db.ChallengeTypeAuthenticate, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}
	return &BeginAuthenticationResponse{Options: options, SessionID: sessionID}, nil
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

// FinishPasskeyAuthentication performs complete WebAuthn validation including
// challenge, origin, RP ID, user verification, credential ownership, and
// signature checks.
func (h *WebAuthnHandler) FinishPasskeyAuthentication(req *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error) {
	if req == nil || req.Response == nil {
		return nil, fmt.Errorf("passkey response is required")
	}
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
	session, err := decodeSessionData(challenge.Challenge)
	if err != nil {
		return nil, err
	}
	parsedResponse, err := req.Response.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse passkey response: %w", err)
	}

	var user *db.User
	var credential *webauthn.Credential
	if len(challenge.UserID) > 0 {
		user, err = h.db.GetUser(challenge.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || !user.Active {
			return nil, fmt.Errorf("user not found or inactive")
		}
		waUser, userErr := h.toWebAuthnUser(user)
		if userErr != nil {
			return nil, userErr
		}
		credential, err = h.webauthn.ValidateLogin(waUser, *session, parsedResponse)
	} else {
		credential, err = h.webauthn.ValidateDiscoverableLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				storedCredential, lookupErr := h.db.GetCredential(rawID)
				if lookupErr != nil {
					return nil, lookupErr
				}
				if storedCredential == nil || !bytesEqual(storedCredential.UserID, userHandle) {
					return nil, fmt.Errorf("passkey is not registered to this user")
				}
				resolved, lookupErr := h.db.GetUser(userHandle)
				if lookupErr != nil {
					return nil, lookupErr
				}
				if resolved == nil || !resolved.Active {
					return nil, fmt.Errorf("user not found or inactive")
				}
				waUser, convertErr := h.toWebAuthnUser(resolved)
				if convertErr != nil {
					return nil, convertErr
				}
				user = resolved
				return waUser, nil
			},
			*session,
			parsedResponse,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("passkey authentication failed: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("passkey user could not be resolved")
	}
	if err := h.db.UpdateCredentialSignCount(credential.ID, credential.Authenticator.SignCount); err != nil {
		fmt.Printf("Warning: failed to update sign count: %v\n", err)
	}
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
