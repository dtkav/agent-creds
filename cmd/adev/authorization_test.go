package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeAuthorizationConfig(t *testing.T, text string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sandbox.toml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestNamedAuthorizationBindsCredentialAndProviderConstraint(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[upstream."github.com"]

[authorization.github]
upstreams = ["github.com"]
credential = "/github/example/project/git"
env = "GIT_GITHUB_TOKEN"
methods = ["GET", "POST"]
paths = ["/Example/Project.git/**"]
repository = "Example/Project"
branches = ["queue/example"]
`)
	cfg, err := LoadProjectConfigWithPlugins(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	upstream := cfg.Upstream["github.com"]
	if upstream.Authorization != "github" {
		t.Fatalf("authorization = %q", upstream.Authorization)
	}
	if upstream.Credential != "/github/example/project/git" || upstream.Env != "GIT_GITHUB_TOKEN" {
		t.Fatalf("bound upstream = %#v", upstream)
	}
	want := map[string]any{
		"repository": "Example/Project",
		"branches":   []any{"queue/example"},
	}
	if !reflect.DeepEqual(upstream.AuthorizationConstraint, want) {
		t.Fatalf("constraint = %#v, want %#v", upstream.AuthorizationConstraint, want)
	}
}

func TestNamedAuthorizationCanUsePluginRoute(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[sandbox]
plugins = ["github"]

[authorization.github]
upstreams = ["github.com"]
credential = "/github/example/project/git"
repository = "Example/Project"
branches = ["queue/example"]
`)
	cfg, err := LoadProjectConfigWithPlugins(dir, filepath.Clean("../.."))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream["github.com"].Authorization != "github" {
		t.Fatalf("plugin route was not bound: %#v", cfg.Upstream["github.com"])
	}
}

func TestNamedAuthorizationCanOmitHostCaveat(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[upstream."session.internal"]

[authorization.session]
upstreams = ["session.internal"]
credential = "/session/internal"
credential_file = "session"
host_caveat = false
subject = "user:usr_123"
`)
	cfg, err := LoadProjectConfigWithPlugins(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	upstream := cfg.Upstream["session.internal"]
	if !upstream.OmitHostCaveat {
		t.Fatal("host_caveat = false was ignored")
	}
	if _, exists := upstream.AuthorizationConstraint["host_caveat"]; exists {
		t.Fatalf("host_caveat leaked into provider constraint: %#v", upstream.AuthorizationConstraint)
	}
}

func TestNamedAuthorizationCanBindPolicyOnlyRoute(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[upstream."records.internal"]
policy = "/records/context"

[authorization.context]
upstreams = ["records.internal"]
namespace = "records-context"
credential_file = "records-context"
methods = ["POST"]
subject = "user:usr_123"
`)
	cfg, err := LoadProjectConfigWithPlugins(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	upstream := cfg.Upstream["records.internal"]
	if upstream.Credential != "" || upstream.Policy != "/records/context" {
		t.Fatalf("policy-only upstream = %#v", upstream)
	}
	if upstream.AuthorizationNamespace != "records-context" {
		t.Fatalf("namespace = %q", upstream.AuthorizationNamespace)
	}
	if got := upstream.AuthorizationConstraint["subject"]; got != "user:usr_123" {
		t.Fatalf("attestation body = %#v", upstream.AuthorizationConstraint)
	}
}

func TestPolicyOnlyAuthorizationRequiresDeliveryTarget(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[upstream."records.internal"]
policy = "/records/context"

[authorization.context]
upstreams = ["records.internal"]
namespace = "records-context"
subject = "user:usr_123"
`)
	_, err := LoadProjectConfigWithPlugins(dir, dir)
	if err == nil || !strings.Contains(err.Error(), "env or credential_file is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestNamedAuthorizationRejectsOverlappingUpstreams(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[upstream."github.com"]

[authorization.first]
upstreams = ["github.com"]
credential = "/github/example/project/git"
branches = ["queue/first"]

[authorization.second]
upstreams = ["github.com"]
credential = "/github/example/project/git"
branches = ["queue/second"]
`)
	_, err := LoadProjectConfigWithPlugins(dir, dir)
	if err == nil || !strings.Contains(err.Error(), "claimed by both") {
		t.Fatalf("error = %v", err)
	}
}

func TestNamedAuthorizationRejectsCredentialOnRoute(t *testing.T) {
	dir := writeAuthorizationConfig(t, `
[upstream."github.com"]
credential = "/github/legacy"

[authorization.github]
upstreams = ["github.com"]
credential = "/github/example/project/git"
branches = ["queue/example"]
`)
	_, err := LoadProjectConfigWithPlugins(dir, dir)
	if err == nil || !strings.Contains(err.Error(), "also declares fields owned by the named authorization") {
		t.Fatalf("error = %v", err)
	}
}
