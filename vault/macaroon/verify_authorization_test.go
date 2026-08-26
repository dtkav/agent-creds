package macaroon

import (
	"strings"
	"testing"
	"time"

	supermac "github.com/superfly/macaroon"
)

func TestThirdPartyAuthorizationRequiresSignedApplicationConstraint(t *testing.T) {
	encryptionKey := make(supermac.EncryptionKey, supermac.EncryptionKeySize)
	for index := range encryptionKey {
		encryptionKey[index] = byte(index + 1)
	}
	store := &KeyStore{
		SigningKey:    supermac.NewSigningKey(),
		EncryptionKey: encryptionKey,
		KeyID:         []byte("authorization-test"),
		TokenPrefix:   DefaultTokenPrefix,
	}
	primary, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Add3P(encryptionKey, SSHAuthorizationLocation, &AuthorizationRequest{
		Credential: "/github/example/project/git",
		Namespace:  "github",
		Authorizer: "dispatch-test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := primary.Add(&ApplicationConstraintRequirement{Namespace: "github"}); err != nil {
		t.Fatal(err)
	}
	// A bearer can attenuate the primary with ordinary application constraints.
	// That must not let it fill the authorization hole without a trusted proof.
	forgedConstraint, err := NewApplicationConstraint("github", map[string]any{
		"repository": "Example/Project",
		"branches":   []any{"queue/forged"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Add(forgedConstraint); err != nil {
		t.Fatal(err)
	}
	primaryToken, err := EncodeToken(primary)
	if err != nil {
		t.Fatal(err)
	}

	access := &Access{Host: "github.com", Method: "POST", Path: "/Example/Project.git/git-receive-pack", Timestamp: time.Now()}
	verifier := NewVerifier(store)
	if result := verifier.VerifyRequest("Bearer "+primaryToken, access); result.Valid || !strings.Contains(result.Error, "no matching discharge") {
		t.Fatalf("primary-only result = %#v", result)
	}

	thirdParty := supermac.GetCaveats[*supermac.Caveat3P](&primary.UnsafeCaveats)
	if len(thirdParty) != 1 {
		t.Fatalf("third-party caveats = %#v", thirdParty)
	}
	requests, emptyDischarge, err := supermac.DischargeTicket(
		encryptionKey, thirdParty[0].Location, thirdParty[0].Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 {
		t.Fatalf("authorization requests = %#v", requests)
	}
	emptyToken, err := EncodeToken(emptyDischarge)
	if err != nil {
		t.Fatal(err)
	}
	if result := verifier.VerifyRequest("Bearer "+primaryToken+","+emptyToken, access); result.Valid || !strings.Contains(result.Error, "required application constraint") {
		t.Fatalf("empty-discharge result = %#v", result)
	}

	// Keep the successful proof independent from the intentionally incomplete
	// discharge above.
	signedPrimary, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := signedPrimary.Add3P(encryptionKey, SSHAuthorizationLocation, &AuthorizationRequest{
		Credential: "/github/example/project/git",
		Namespace:  "github",
		Authorizer: "dispatch-test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := signedPrimary.Add(&ApplicationConstraintRequirement{Namespace: "github"}); err != nil {
		t.Fatal(err)
	}
	signedPrimaryToken, err := EncodeToken(signedPrimary)
	if err != nil {
		t.Fatal(err)
	}
	signedThirdParty := supermac.GetCaveats[*supermac.Caveat3P](&signedPrimary.UnsafeCaveats)
	_, signedDischarge, err := supermac.DischargeTicket(
		encryptionKey, signedThirdParty[0].Location, signedThirdParty[0].Ticket)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := NewAuthorizedApplicationConstraint("github", map[string]any{
		"repository": "Example/Project",
		"branches":   []any{"queue/example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := signedDischarge.Add(constraint); err != nil {
		t.Fatal(err)
	}
	dischargeToken, err := EncodeToken(signedDischarge)
	if err != nil {
		t.Fatal(err)
	}
	result := verifier.VerifyRequest("Bearer "+signedPrimaryToken+","+dischargeToken, access)
	if !result.Valid {
		t.Fatalf("signed authorization failed: %s", result.Error)
	}
	if len(result.ApplicationConstraints) != 1 || result.ApplicationConstraints[0].Namespace != "github" || !result.ApplicationConstraints[0].Authorized {
		t.Fatalf("verified constraints = %#v", result.ApplicationConstraints)
	}
}
