package api

import (
	"testing"
	"time"

	supermac "github.com/superfly/macaroon"
	tfmac "vault/macaroon"
)

func TestMintTokenUsesInjectedVaultKeyStore(t *testing.T) {
	t.Setenv("MACAROON_SIGNING_KEY", "")
	store := &tfmac.KeyStore{
		SigningKey:  supermac.NewSigningKey(),
		KeyID:       []byte("injected"),
		TokenPrefix: tfmac.DefaultTokenPrefix,
	}
	server := &Server{keyStore: store}
	token, err := server.mintToken("subject-123", nil, nil, nil, []ApplicationConstraintRequest{{
		Namespace:  "example",
		Constraint: map[string]any{"service": []string{"records"}},
	}}, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tfmac.DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	caveats, err := decoded.VerifyParsed(store.SigningKey, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	subjects := supermac.GetCaveats[*tfmac.SubjectCaveat](caveats)
	if len(subjects) != 1 || subjects[0].Subject != "subject-123" {
		t.Fatalf("subjects = %#v", subjects)
	}
	constraints := supermac.GetCaveats[*tfmac.ApplicationConstraint](caveats)
	if len(constraints) != 1 || constraints[0].Namespace != "example" {
		t.Fatalf("constraints = %#v", constraints)
	}
}
