package jsvm

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"vault/provider"
)

func TestPublicExampleScriptsLoad(t *testing.T) {
	examples := filepath.Join("..", "..", "..", "examples")
	manager, err := NewManagerWithPolicies(
		[]string{
			filepath.Join(examples, "providers"),
			filepath.Join(examples, "policies"),
		},
		1,
		[]Spec{{
			Name: "example-command",
			Type: "command_session",
			Config: map[string]any{
				"command":           "/usr/local/bin/session-helper",
				"token_url":         "https://auth.service.example/session",
				"client_id":         "deployment-client",
				"audience":          "api.service.example",
				"allowed_audiences": []any{"api.service.example"},
				"client_secret":     "deployment-secret",
			},
		}},
		[]PolicySpec{{
			Name: "example-policy",
			Type: "subject_scope",
			Config: map[string]any{
				"namespace":      "records",
				"required_scope": "records:read",
			},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	capability := "acm_example_capability"
	extracted, err := manager.Extractor(Spec{
		Name: "example-command",
		Type: "command_session",
	}).Extract(context.Background(), provider.ExtractionRequest{
		Host:   "api.service.example",
		Method: "GET",
		Path:   "/v1/records",
		Headers: map[string]string{
			"x-service-authorization": "Session " + base64.StdEncoding.EncodeToString([]byte(capability)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if extracted != capability {
		t.Fatalf("extracted capability = %q, want %q", extracted, capability)
	}
}
