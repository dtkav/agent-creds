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
	refs := config.CredentialSecretRefs["github/relay-diffs"]
	if len(refs) != 1 || refs[0].Field != "token" || refs[0].Reference != "github/relay-diffs#TOKEN" {
		t.Fatalf("secret references = %#v", refs)
	}
}

func TestLoadBytesTracksNestedCredentialPointersWithoutSecretValues(t *testing.T) {
	config, err := LoadBytes([]byte(`
secrets:
  oidc:
    CLIENT_SECRET: must-never-appear-in-inventory
signing_key: signing-key
credentials:
  records/prod:
    type: custom_oidc
    nested:
      client_secret:
        $secret: oidc#CLIENT_SECRET
    audiences:
      - public
      - value:
          $secret: oidc#AUDIENCE
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	refs := config.CredentialSecretRefs["records/prod"]
	if len(refs) != 2 {
		t.Fatalf("secret references = %#v", refs)
	}
	if refs[0].Field != "nested.client_secret" || refs[0].Reference != "oidc#CLIENT_SECRET" {
		t.Fatalf("first secret reference = %#v", refs[0])
	}
	if refs[1].Field != "audiences[1].value" || refs[1].Reference != "oidc#AUDIENCE" {
		t.Fatalf("second secret reference = %#v", refs[1])
	}
}
