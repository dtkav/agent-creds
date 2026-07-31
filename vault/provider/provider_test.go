package provider

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestRegistryBuildsIndependentProviders(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("test", func(config map[string]any) (CredentialProvider, error) {
		config["mutated"] = true
		return &staticProvider{headers: map[string]string{"x-test": "ok"}}, nil
	}); err != nil {
		t.Fatal(err)
	}

	config := map[string]any{"value": "original"}
	built, err := registry.Build("test", config)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := config["mutated"]; exists {
		t.Fatal("factory mutated caller-owned config")
	}

	result, err := built.Resolve(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Headers["x-test"] != "ok" {
		t.Fatalf("unexpected headers: %#v", result.Headers)
	}
}

func TestValidateHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr bool
	}{
		{name: "valid", headers: map[string]string{"authorization": "Bearer token"}},
		{name: "empty", headers: map[string]string{}, wantErr: true},
		{name: "verifier owned", headers: map[string]string{"x-agent-creds-subject": "value"}, wantErr: true},
		{name: "space in name", headers: map[string]string{"bad name": "value"}, wantErr: true},
		{name: "colon in name", headers: map[string]string{":authority": "value"}, wantErr: true},
		{name: "newline in value", headers: map[string]string{"x-test": "one\ntwo"}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateHeaders(test.headers)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateHeaders() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestBasicProviderAllowsExplicitEmptyPassword(t *testing.T) {
	built, err := newBasicProvider(map[string]any{
		"username": "sk_test_example",
		"password": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := built.Resolve(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("sk_test_example:"))
	if got := result.Headers["authorization"]; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
}
