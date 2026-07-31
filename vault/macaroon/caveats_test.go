package macaroon

import "testing"

func TestPathCaveatIgnoresQueryString(t *testing.T) {
	caveat := &PathCaveat{Patterns: []string{"/v1/customers"}}
	access := &Access{Path: "/v1/customers?limit=3"}
	if err := caveat.Prohibits(access); err != nil {
		t.Fatalf("allowed path with query string was prohibited: %v", err)
	}
}

func TestPathCaveatStillRejectsDifferentPathWithQueryString(t *testing.T) {
	caveat := &PathCaveat{Patterns: []string{"/v1/customers"}}
	access := &Access{Path: "/v1/balance?expand=available"}
	if err := caveat.Prohibits(access); err == nil {
		t.Fatal("different path with query string was allowed")
	}
}
