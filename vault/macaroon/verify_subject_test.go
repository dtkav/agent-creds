package macaroon

import (
	"testing"
	"time"

	supermac "github.com/superfly/macaroon"
)

func testVerifier(t *testing.T, subjects ...string) (*Verifier, string) {
	t.Helper()
	key := supermac.NewSigningKey()
	store := &KeyStore{
		SigningKey:  key,
		KeyID:       []byte("test-kid"),
		TokenPrefix: DefaultTokenPrefix,
	}
	m, err := supermac.New(store.KeyID, TokenLocation, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := m.Add(&supermac.ValidityWindow{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		caveat, err := NewSubjectCaveat(subject)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Add(caveat); err != nil {
			t.Fatal(err)
		}
	}
	token, err := EncodeToken(m)
	if err != nil {
		t.Fatal(err)
	}
	return NewVerifier(store), token
}

func TestVerifyRequestReturnsSignedIdentityFacts(t *testing.T) {
	verifier, token := testVerifier(t, "subject-123")
	result := verifier.VerifyRequest("Bearer "+token, &Access{
		Host:      "service.internal",
		Method:    "POST",
		Path:      "/graphql",
		Timestamp: time.Now(),
	})
	if !result.Valid {
		t.Fatalf("verification failed: %s", result.Error)
	}
	if result.Subject == nil || *result.Subject != "subject-123" {
		t.Fatalf("subject = %#v", result.Subject)
	}
	if result.KeyID != "test-kid" || result.Location != TokenLocation || result.ExpiresAt == nil {
		t.Fatalf("identity facts = %#v", result)
	}
	headers := result.IdentityHeaders()
	if headers["x-agent-creds-verified"] != "1" || headers["x-agent-creds-subject"] != "subject-123" {
		t.Fatalf("identity headers = %#v", headers)
	}
}

func TestVerifyRequestRejectsConflictingSubjects(t *testing.T) {
	verifier, token := testVerifier(t, "subject-123", "other-subject")
	result := verifier.VerifyRequest("Bearer "+token, &Access{
		Host:      "service.internal",
		Method:    "POST",
		Path:      "/graphql",
		Timestamp: time.Now(),
	})
	if result.Valid || result.Error != "conflicting subject caveats" {
		t.Fatalf("result = %#v", result)
	}
}

func TestVerifyRequestReturnsSignedApplicationConstraints(t *testing.T) {
	verifier, token := testVerifier(t, "subject-123")
	m, err := DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := NewApplicationConstraint("example", map[string]any{
		"service": []string{"records"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add(constraint); err != nil {
		t.Fatal(err)
	}
	token, err = EncodeToken(m)
	if err != nil {
		t.Fatal(err)
	}

	result := verifier.VerifyRequest("Bearer "+token, &Access{
		Host:      "records.example",
		Method:    "GET",
		Path:      "/v1/records",
		Timestamp: time.Now(),
	})
	if !result.Valid {
		t.Fatalf("verification failed: %s", result.Error)
	}
	if len(result.ApplicationConstraints) != 1 || result.ApplicationConstraints[0].Namespace != "example" {
		t.Fatalf("constraints = %#v", result.ApplicationConstraints)
	}
}
