package macaroon

import (
	"testing"

	upstreammac "github.com/superfly/macaroon"
)

func TestApplicationConstraintRoundTripsThroughMacaroonEncoding(t *testing.T) {
	constraint, err := NewApplicationConstraint("example", map[string]any{
		"services": []string{"records", "files"},
		"action":   "read",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := upstreammac.NewCaveatSet(constraint).MarshalMsgpack()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := upstreammac.DecodeCaveats(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got := upstreammac.GetCaveats[*ApplicationConstraint](decoded)
	if len(got) != 1 || got[0].Namespace != "example" {
		t.Fatalf("decoded constraints = %#v", got)
	}
	if got[0].Constraint["action"] != "read" {
		t.Fatalf("decoded body = %#v", got[0].Constraint)
	}
}

func TestApplicationConstraintRequiresNamespaceAndBody(t *testing.T) {
	if _, err := NewApplicationConstraint("", map[string]any{}); err == nil {
		t.Fatal("empty namespace was accepted")
	}
	if _, err := NewApplicationConstraint("example", nil); err == nil {
		t.Fatal("nil body was accepted")
	}
}
