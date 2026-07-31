package jsvm

import (
	"path/filepath"
	"testing"
)

func TestPublicExampleScriptsLoad(t *testing.T) {
	examples := filepath.Join("..", "..", "..", "examples")
	_, err := NewManagerWithPolicies(
		[]string{
			filepath.Join(examples, "providers"),
			filepath.Join(examples, "policies"),
		},
		1,
		[]Spec{{
			Name: "example-command",
			Type: "command_session",
			Config: map[string]any{
				"command":      "/usr/local/bin/session-helper",
				"audience":     "api.service.example",
				"access_token": "deployment-token",
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
}
