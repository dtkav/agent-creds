package vault

import "testing"

func TestLoadBytesResolvesSecretReferences(t *testing.T) {
	config, err := LoadBytes([]byte(`
secrets:
  github/relay-diffs:
    TOKEN: replacement-token
signing_key: signing-key
credentials:
  github/relay-diffs:
    type: bearer
    token:
      $secret: github/relay-diffs#TOKEN
    env: GH_TOKEN
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got := config.Credentials["github/relay-diffs"].Token; got != "replacement-token" {
		t.Fatalf("resolved token = %q, want replacement-token", got)
	}
}
