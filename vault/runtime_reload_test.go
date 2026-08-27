package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vault/policy"
	vaultcfg "vault/vault"
)

type testConstraintCredentialMacaroon struct {
	testCredentialMacaroon
}

func (testConstraintCredentialMacaroon) ConstraintSchema(context.Context) (map[string]any, error) {
	return map[string]any{
		"type":     "object",
		"required": []any{"branches"},
	}, nil
}

func (testConstraintCredentialMacaroon) ValidateConstraint(_ context.Context, body map[string]any) error {
	if _, ok := body["branches"]; !ok {
		return fmt.Errorf("branches is required")
	}
	return nil
}

func testRuntimeConfig(name, token string) *vaultcfg.Config {
	return &vaultcfg.Config{
		SigningKey:    "test-signing-key",
		EncryptionKey: "test-encryption-key",
		Credentials: map[string]vaultcfg.CredentialConfig{
			name: {
				Type:  "bearer",
				Token: token,
				Env:   "TEST_TOKEN",
				Capabilities: &vaultcfg.CapabilitiesConfig{
					Hosts: []string{"api.example.com"},
					Endpoints: []vaultcfg.EndpointCap{{
						Methods: []string{"GET"},
						Paths:   []string{"/v1/**"},
					}},
				},
			},
		},
	}
}

func newTestRuntimeStore(t *testing.T, cfg *vaultcfg.Config) *runtimeStore {
	t.Helper()
	snapshot, _, err := buildRuntimeSnapshot(cfg, nil, 1)
	if err != nil {
		t.Fatalf("building initial runtime: %v", err)
	}
	store := newRuntimeStore(snapshot, nil, 1)
	t.Cleanup(store.Close)
	return store
}

func TestRuntimeStoreReloadSwapsCompleteSnapshot(t *testing.T) {
	store := newTestRuntimeStore(t, testRuntimeConfig("service/old", "old-token"))
	before := store.Load()

	warnings, err := store.Reload(testRuntimeConfig("service/new", "new-token"))
	if err != nil {
		t.Fatalf("reloading runtime: %v", err)
	}
	if len(warnings) == 0 {
		// The capability host differs from the credential name, which is a
		// warning in the current config model. Preserve warnings on reload.
		t.Fatal("reload discarded config warnings")
	}

	after := store.Load()
	if after == before {
		t.Fatal("reload did not swap the runtime snapshot")
	}
	if _, ok := after.credentials["service/old"]; ok {
		t.Fatal("new snapshot retained a credential from the old snapshot")
	}
	if _, ok := after.credentials["service/new"]; !ok {
		t.Fatal("new snapshot is missing the replacement credential")
	}
	if got := after.config.Credentials["service/new"].Token; got != "new-token" {
		t.Fatalf("new snapshot token = %q, want replacement", got)
	}
}

func TestRuntimeStoreReloadFailureKeepsLastKnownGoodSnapshot(t *testing.T) {
	store := newTestRuntimeStore(t, testRuntimeConfig("service/stable", "stable-token"))
	before := store.Load()

	changedKeys := testRuntimeConfig("service/rejected", "rejected-token")
	changedKeys.SigningKey = "different-signing-key"
	if _, err := store.Reload(changedKeys); err == nil {
		t.Fatal("reload accepted a signing-key change")
	}
	if got := store.Load(); got != before {
		t.Fatal("signing-key failure replaced the active snapshot")
	}

	badProvider := testRuntimeConfig("service/rejected", "rejected-token")
	credential := badProvider.Credentials["service/rejected"]
	credential.Type = "provider-that-does-not-exist"
	badProvider.Credentials["service/rejected"] = credential
	if _, err := store.Reload(badProvider); err == nil {
		t.Fatal("reload accepted an unknown credential provider")
	}
	if got := store.Load(); got != before {
		t.Fatal("provider failure replaced the active snapshot")
	}
}

func TestControlHandlerReloadAndCredentialInfo(t *testing.T) {
	store := newTestRuntimeStore(t, testRuntimeConfig("service/old", "old-token"))
	handler := newControlHandler(store)

	configYAML := `
signing_key: test-signing-key
encryption_key: test-encryption-key
credentials:
  service/new:
    type: bearer
    token: new-secret-that-must-not-leak
    env: TEST_TOKEN
    capabilities:
      hosts: [api.example.com]
      endpoints:
        - methods: [GET]
          paths: [/v1/**]
          description: Read example records.
`
	reloadRequest := httptest.NewRequest(http.MethodPost, controlReloadPath, strings.NewReader(configYAML))
	reloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(reloadResponse, reloadRequest)
	if reloadResponse.Code != http.StatusOK {
		t.Fatalf("reload status = %d, body = %s", reloadResponse.Code, reloadResponse.Body.String())
	}

	infoRequest := httptest.NewRequest(http.MethodGet, controlCredentialInfoPath+"?path=/service/new", nil)
	infoResponse := httptest.NewRecorder()
	handler.ServeHTTP(infoResponse, infoRequest)
	if infoResponse.Code != http.StatusOK {
		t.Fatalf("info status = %d, body = %s", infoResponse.Code, infoResponse.Body.String())
	}
	if bytes.Contains(infoResponse.Body.Bytes(), []byte("new-secret-that-must-not-leak")) {
		t.Fatal("credential info response exposed the upstream secret")
	}

	var info credentialInfoResponse
	if err := json.Unmarshal(infoResponse.Body.Bytes(), &info); err != nil {
		t.Fatalf("decoding credential info: %v", err)
	}
	if info.Type != "bearer" || len(info.EnvVars) != 1 || info.EnvVars[0] != "TEST_TOKEN" {
		t.Fatalf("unexpected credential info: %#v", info)
	}
	if len(info.Endpoints) != 1 || info.Endpoints[0].Description != "Read example records." {
		t.Fatalf("unexpected endpoint info: %#v", info.Endpoints)
	}
	listRequest := httptest.NewRequest(http.MethodGet, controlCredentialsPath, nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listResponse.Code, listResponse.Body.String())
	}
	if got := listResponse.Body.String(); !strings.Contains(got, `"/service/new"`) || strings.Contains(got, `"/service/old"`) {
		t.Fatalf("credential list did not use reloaded snapshot: %s", got)
	}

	beforeInvalid := store.Load()
	invalidRequest := httptest.NewRequest(http.MethodPost, controlReloadPath, strings.NewReader("not: [valid"))
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid reload status = %d, want 400", invalidResponse.Code)
	}
	if got := store.Load(); got != beforeInvalid {
		t.Fatal("invalid control reload replaced the active snapshot")
	}
}

func TestCredentialInfoIncludesPluginDerivedMacaroonConstraint(t *testing.T) {
	store := newTestRuntimeStore(t, testRuntimeConfig("service/scoped", "secret-token"))
	snapshot := store.Load()
	credential := snapshot.credentials["service/scoped"]
	credential.macaroon = testCredentialMacaroon{
		namespace: "example",
		constraint: &policy.Constraint{
			Namespace: "example",
			Body:      map[string]any{"branches": []any{"agent/work"}},
		},
	}
	snapshot.credentials["service/scoped"] = credential

	response := httptest.NewRecorder()
	newControlHandler(store).ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		controlCredentialInfoPath+"?path=/service/scoped",
		nil,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("info status = %d, body = %s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("secret-token")) {
		t.Fatal("credential info exposed the provider secret")
	}
	var info credentialInfoResponse
	if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Constraints) != 1 || info.Constraints[0].Namespace != "example" {
		t.Fatalf("constraints = %#v", info.Constraints)
	}
}

func TestCredentialInfoIncludesPluginCaveatMetadata(t *testing.T) {
	store := newTestRuntimeStore(t, testRuntimeConfig("service/scoped", "secret-token"))
	snapshot := store.Load()
	credential := snapshot.credentials["service/scoped"]
	credential.macaroon = testConstraintCredentialMacaroon{
		testCredentialMacaroon: testCredentialMacaroon{
			namespace: "example",
			authorize: func(context.Context, policy.Request) (policy.Decision, error) {
				return policy.Allow(), nil
			},
		},
	}
	snapshot.credentials["service/scoped"] = credential
	handler := newControlHandler(store)

	info := httptest.NewRecorder()
	handler.ServeHTTP(info, httptest.NewRequest(
		http.MethodGet, controlCredentialInfoPath+"?path=/service/scoped", nil))
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), `"namespace":"example"`) {
		t.Fatalf("credential info = %d %s", info.Code, info.Body.String())
	}

	var metadata credentialInfoResponse
	if err := json.Unmarshal(info.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Caveat == nil || metadata.Caveat.Namespace != "example" {
		t.Fatalf("caveat metadata = %#v", metadata.Caveat)
	}
}
