package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestFetchCredentialPathsUsesLiveControlPlane(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/credentials" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"paths":["/service/a","/service/b"]}`))
	}))
	defer server.Close()
	t.Setenv("VAULT_CONTROL_URL", server.URL)

	paths, err := fetchCredentialPaths()
	if err != nil {
		t.Fatalf("fetchCredentialPaths: %v", err)
	}
	if want := []string{"/service/a", "/service/b"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestFetchCredentialConstraintsUsesLiveControlPlane(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/credentials/info" || r.URL.Query().Get("path") != "/github/agent" {
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "type": "github",
  "constraints": [{"namespace":"github","constraint":{"branches":["refs/heads/agent/work"]}}]
}`))
	}))
	defer server.Close()
	t.Setenv("VAULT_CONTROL_URL", server.URL)

	constraints, err := fetchCredentialConstraints("/github/agent")
	if err != nil {
		t.Fatalf("fetchCredentialConstraints: %v", err)
	}
	if len(constraints) != 1 || constraints[0].Namespace != "github" {
		t.Fatalf("constraints = %#v", constraints)
	}
	branches, ok := constraints[0].Constraint["branches"].([]any)
	if !ok || len(branches) != 1 || branches[0] != "refs/heads/agent/work" {
		t.Fatalf("constraint body = %#v", constraints[0].Constraint)
	}
}
