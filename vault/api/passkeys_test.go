package api

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"vault/db"
)

func newPasskeyTestHandler(t *testing.T) (*WebAuthnHandler, *db.DB) {
	t.Helper()
	database, err := db.Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	handler, err := NewWebAuthnHandler(database, "localhost", "http://localhost:8033", "Credential Vault", "")
	if err != nil {
		t.Fatal(err)
	}
	return handler, database
}

func TestWebAuthnErrorMessageExplainsAuthenticatorValidation(t *testing.T) {
	tests := []struct {
		name string
		info string
		want string
	}{
		{"rp ID", "RP Hash mismatch. Expected abc and Received def", "different relying-party ID"},
		{"presence", "User presence flag not set by authenticator", "did not confirm user presence"},
		{"verification", "User verification required but flag not set by authenticator", "did not perform user verification"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := protocol.ErrVerification.WithInfo(test.info)
			if got := webAuthnErrorMessage("registration", err); !strings.Contains(got, test.want) {
				t.Fatalf("message = %q, want it to contain %q", got, test.want)
			}
		})
	}

	plain := errors.New("plain failure")
	if got := webAuthnErrorMessage("registration", plain); got != plain.Error() {
		t.Fatalf("plain message = %q, want %q", got, plain.Error())
	}
}

func TestPasskeyRegistrationRequiresDiscoverableCredentialAndPrefersUserVerificationByDefault(t *testing.T) {
	handler, database := newPasskeyTestHandler(t)
	if _, err := database.CreateUser("operator", "Vault Operator"); err != nil {
		t.Fatal(err)
	}
	response, err := handler.BeginRegistration("operator")
	if err != nil {
		t.Fatal(err)
	}
	selection := response.Options.Response.AuthenticatorSelection
	if selection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Fatalf("resident key = %q, want required", selection.ResidentKey)
	}
	if selection.UserVerification != protocol.VerificationPreferred {
		t.Fatalf("user verification = %q, want preferred", selection.UserVerification)
	}
	if selection.AuthenticatorAttachment != "" {
		t.Fatalf("authenticator attachment = %q, want platform-neutral", selection.AuthenticatorAttachment)
	}
}

func TestBeginPasskeyAuthenticationSupportsUsernameLessAccountSelection(t *testing.T) {
	handler, database := newPasskeyTestHandler(t)
	response, err := handler.BeginPasskeyAuthentication("")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Options.Response.AllowedCredentials) != 0 {
		t.Fatalf("discoverable login allow list = %#v, want empty", response.Options.Response.AllowedCredentials)
	}
	if response.Options.Response.UserVerification != protocol.VerificationPreferred {
		t.Fatalf("user verification = %q, want preferred", response.Options.Response.UserVerification)
	}
	challenge, err := database.GetWebAuthnChallenge(response.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if challenge == nil || len(challenge.UserID) != 0 {
		t.Fatalf("discoverable challenge = %#v", challenge)
	}
	session, err := decodeSessionData(challenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if session.UserID != nil {
		t.Fatalf("discoverable session user ID = %x, want nil", session.UserID)
	}
}

func TestPasskeyUserVerificationCanBeRequired(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	handler, err := NewWebAuthnHandler(database, "localhost", "http://localhost:8033", "Credential Vault", "required")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateUser("operator", "Vault Operator"); err != nil {
		t.Fatal(err)
	}
	registration, err := handler.BeginRegistration("operator")
	if err != nil {
		t.Fatal(err)
	}
	if got := registration.Options.Response.AuthenticatorSelection.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("registration user verification = %q, want required", got)
	}
	login, err := handler.BeginPasskeyAuthentication("")
	if err != nil {
		t.Fatal(err)
	}
	if got := login.Options.Response.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("login user verification = %q, want required", got)
	}
}

func TestPasskeyUserVerificationRejectsInvalidConfiguration(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := NewWebAuthnHandler(database, "localhost", "http://localhost:8033", "Credential Vault", "sometimes"); err == nil || !strings.Contains(err.Error(), "preferred or required") {
		t.Fatalf("invalid configuration error = %v", err)
	}
}

func TestBeginPasskeyAuthenticationKeepsUsernameFallback(t *testing.T) {
	handler, database := newPasskeyTestHandler(t)
	user, err := database.CreateUser("operator", "Vault Operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateCredential(&db.Credential{
		ID: []byte("credential-id"), UserID: user.ID, PublicKey: []byte("unused-at-begin"),
	}); err != nil {
		t.Fatal(err)
	}
	response, err := handler.BeginPasskeyAuthentication("operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Options.Response.AllowedCredentials) != 1 {
		t.Fatalf("username-assisted allow list = %#v", response.Options.Response.AllowedCredentials)
	}
	challenge, err := database.GetWebAuthnChallenge(response.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if challenge == nil || !bytesEqual(challenge.UserID, user.ID) {
		t.Fatalf("username-assisted challenge user = %x, want %x", challenge.UserID, user.ID)
	}
}
