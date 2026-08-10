package macaroon

import "testing"

func TestExtractTokensAcceptsGitHubCLITokenScheme(t *testing.T) {
	main, discharges, err := extractTokens("token acm_main,acm_discharge")
	if err != nil {
		t.Fatal(err)
	}
	if main != "acm_main" {
		t.Fatalf("main token = %q, want acm_main", main)
	}
	if len(discharges) != 1 || discharges[0] != "acm_discharge" {
		t.Fatalf("discharges = %#v, want [acm_discharge]", discharges)
	}
}

func TestIsMacaroonAuthAcceptsGitHubCLITokenScheme(t *testing.T) {
	if !IsMacaroonAuth("token acm_main", "acm_") {
		t.Fatal("GitHub CLI token auth was not recognized as a macaroon")
	}
}
