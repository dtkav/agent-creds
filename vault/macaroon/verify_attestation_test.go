package macaroon

import (
	"reflect"
	"strings"
	"testing"
	"time"

	supermac "github.com/superfly/macaroon"
)

func TestThirdPartyProofCarriesArbitraryApplicationAttestations(t *testing.T) {
	const location = "workflow-authorizer"
	encryptionKey := make(supermac.EncryptionKey, supermac.EncryptionKeySize)
	for index := range encryptionKey {
		encryptionKey[index] = byte(index + 1)
	}
	store := &KeyStore{
		SigningKey:  supermac.NewSigningKey(),
		KeyID:       []byte("attestation-test"),
		TokenPrefix: DefaultTokenPrefix,
	}
	primary, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	// The ticket is an arbitrary caveat set owned by the discharger. This
	// example asks it to authorize a workflow, but agent-creds does not assign
	// semantics to the namespace or body.
	ticketRequest, err := NewApplicationConstraint("workflow-request", map[string]any{
		"repository": "Example/Project",
		"operation":  "publish",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Add3P(encryptionKey, location, ticketRequest); err != nil {
		t.Fatal(err)
	}
	if err := primary.Add(&ApplicationAttestationRequirement{
		Namespace: "workflow-result",
		Location:  location,
	}); err != nil {
		t.Fatal(err)
	}

	// An ordinary bearer-attenuable caveat cannot satisfy a proof requirement.
	bearerConstraint, err := NewApplicationConstraint("workflow-result", map[string]any{
		"subject": "forged@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Add(bearerConstraint); err != nil {
		t.Fatal(err)
	}
	proofOnly, err := NewApplicationAttestation("workflow-result", map[string]any{"subject": "operator@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Add(proofOnly); err == nil || !strings.Contains(err.Error(), "cannot add attestations") {
		t.Fatalf("adding proof-only attestation to primary returned %v", err)
	}

	primaryToken, err := EncodeToken(primary)
	if err != nil {
		t.Fatal(err)
	}
	access := &Access{Host: "example.internal", Method: "POST", Path: "/publish", Timestamp: time.Now()}
	verifier := NewVerifier(store)
	verifier.AddTrusted3P(location, encryptionKey)
	if result := verifier.VerifyRequest("Bearer "+primaryToken, access); result.Valid || !strings.Contains(result.Error, "no matching discharge") {
		t.Fatalf("primary-only result = %#v", result)
	}

	thirdParty := supermac.GetCaveats[*supermac.Caveat3P](&primary.UnsafeCaveats)
	if len(thirdParty) != 1 {
		t.Fatalf("third-party caveats = %#v", thirdParty)
	}
	ticketCaveats, emptyProof, err := supermac.DischargeTicket(encryptionKey, location, thirdParty[0].Ticket)
	if err != nil {
		t.Fatal(err)
	}
	requests := supermac.GetCaveats[*ApplicationConstraint](supermac.NewCaveatSet(ticketCaveats...))
	if len(requests) != 1 || requests[0].Namespace != "workflow-request" || requests[0].Constraint["operation"] != "publish" {
		t.Fatalf("ticket caveats = %#v", ticketCaveats)
	}
	if err := emptyProof.BindToParentMacaroon(primary); err != nil {
		t.Fatal(err)
	}
	emptyToken, err := EncodeToken(emptyProof)
	if err != nil {
		t.Fatal(err)
	}
	if result := verifier.VerifyRequest("Bearer "+primaryToken+","+emptyToken, access); result.Valid || !strings.Contains(result.Error, "required application attestation") {
		t.Fatalf("empty-proof result = %#v", result)
	}

	_, proof, err := supermac.DischargeTicket(encryptionKey, location, thirdParty[0].Ticket)
	if err != nil {
		t.Fatal(err)
	}
	workflowAttestation, err := NewApplicationAttestation("workflow-result", map[string]any{
		"subject": "operator@example.com",
		"scopes":  []any{"publish"},
	})
	if err != nil {
		t.Fatal(err)
	}
	auditAttestation, err := NewApplicationAttestation("audit-context", map[string]any{
		"request_id": "req-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Add(workflowAttestation, auditAttestation); err != nil {
		t.Fatal(err)
	}
	if err := proof.BindToParentMacaroon(primary); err != nil {
		t.Fatal(err)
	}
	proofToken, err := EncodeToken(proof)
	if err != nil {
		t.Fatal(err)
	}
	result := verifier.VerifyRequest("Bearer "+primaryToken+","+proofToken, access)
	if !result.Valid {
		t.Fatalf("proof verification failed: %s", result.Error)
	}
	if len(result.ApplicationConstraints) != 3 {
		t.Fatalf("verified constraints = %#v", result.ApplicationConstraints)
	}
	if result.ApplicationConstraints[0].ThirdParty != nil {
		t.Fatalf("bearer constraint acquired third-party provenance: %#v", result.ApplicationConstraints[0])
	}
	for _, verified := range result.ApplicationConstraints[1:] {
		if verified.ThirdParty == nil || verified.ThirdParty.Location != location {
			t.Fatalf("attestation provenance = %#v", verified.ThirdParty)
		}
	}
	if !reflect.DeepEqual(result.ApplicationConstraints[1].Constraint["scopes"], []any{"publish"}) {
		t.Fatalf("attestation body = %#v", result.ApplicationConstraints[1].Constraint)
	}

	// A cryptographically valid discharge from an unregistered location can
	// carry ordinary restrictions, but its attestations are not trusted.
	untrustedVerifier := NewVerifier(store)
	if result := untrustedVerifier.VerifyRequest("Bearer "+primaryToken+","+proofToken, access); result.Valid || !strings.Contains(result.Error, "required application attestation") {
		t.Fatalf("untrusted proof result = %#v", result)
	}
}
