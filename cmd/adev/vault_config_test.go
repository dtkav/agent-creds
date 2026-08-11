package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type vaultRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn vaultRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestVaultSigningKeyResolvesSecretRef(t *testing.T) {
	yaml := []byte(`secrets:
  vault:
    SIGNING_KEY: MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=
signing_key:
  $secret: vault#SIGNING_KEY
credentials: {}
`)

	got, err := vaultSigningKey(yaml)
	if err != nil {
		t.Fatalf("vaultSigningKey returned error: %v", err)
	}
	if got != "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=" {
		t.Fatalf("vaultSigningKey = %q", got)
	}
}

func TestValidateVaultStartupConfigRejectsEmptySigningKey(t *testing.T) {
	yaml := []byte(`secrets:
  vault:
    SIGNING_KEY: ""
signing_key:
  $secret: vault#SIGNING_KEY
credentials: {}
`)

	if err := validateVaultStartupConfig(yaml); err == nil {
		t.Fatal("validateVaultStartupConfig succeeded with an empty signing key")
	}
}

func TestVaultHTTPHealthyRequiresOK(t *testing.T) {
	status := http.StatusServiceUnavailable
	client := &http.Client{Transport: vaultRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})}

	if vaultHTTPHealthyWithClient(client, "http://vault.example/health") {
		t.Fatal("vaultHTTPHealthy accepted an unhealthy response")
	}
	status = http.StatusOK
	if !vaultHTTPHealthyWithClient(client, "http://vault.example/health") {
		t.Fatal("vaultHTTPHealthy rejected an OK response")
	}
}

func TestVaultHealthURL(t *testing.T) {
	if got := vaultHealthURL("http://localhost:8033"); got != "http://localhost:8033/health" {
		t.Fatalf("vaultHealthURL = %q", got)
	}
	if got := vaultHealthURL("http://localhost:8033/health"); got != "http://localhost:8033/health" {
		t.Fatalf("vaultHealthURL duplicated health path: %q", got)
	}
}
