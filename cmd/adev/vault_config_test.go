package main

import "testing"

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
