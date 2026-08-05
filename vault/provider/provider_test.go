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

func TestHeaderProvider(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
		header string
		value  string
	}{
		{
			name: "authorization value",
			config: map[string]any{
				"header": "Authorization",
				"value":  "FlyV1 fm2_example",
			},
			header: "authorization",
			value:  "FlyV1 fm2_example",
		},
		{
			name: "raw header value",
			config: map[string]any{
				"header": "X-API-Key",
				"value":  "secret",
			},
			header: "x-api-key",
			value:  "secret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			built, err := newHeaderProvider(test.config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := built.Resolve(context.Background(), Request{})
			if err != nil {
				t.Fatal(err)
			}
			if got := result.Headers[test.header]; got != test.value {
				t.Fatalf("%s = %q, want %q", test.header, got, test.value)
			}
		})
	}
}

func TestHeaderProviderRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
	}{
		{name: "missing header", config: map[string]any{"value": "secret"}},
		{name: "missing value", config: map[string]any{"header": "Authorization"}},
		{name: "invalid header", config: map[string]any{"header": "bad header", "value": "secret"}},
		{name: "routing header", config: map[string]any{"header": "Host", "value": "secret"}},
		{name: "verifier header", config: map[string]any{"header": "X-Agent-Creds-Subject", "value": "secret"}},
		{name: "multiline value", config: map[string]any{"header": "Authorization", "value": "one\ntwo"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newHeaderProvider(test.config); err == nil {
				t.Fatal("newHeaderProvider() accepted invalid configuration")
			}
		})
	}
}

func TestBearerProviderUsesStaticHeaderPreset(t *testing.T) {
	built, err := newBearerProvider(map[string]any{"token": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := built.Resolve(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Headers["authorization"]; got != "Bearer secret" {
		t.Fatalf("authorization = %q, want %q", got, "Bearer secret")
	}
}
