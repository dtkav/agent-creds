package main

import "testing"

func TestUpstreamTokenEnvOverride(t *testing.T) {
	info := &CredentialInfo{EnvVars: []string{"VAULT_DEFAULT_TOKEN"}}
	upstream := UpstreamConfig{Env: "GH_TOKEN"}
	if got := upstreamTokenEnv(upstream, info); got != "GH_TOKEN" {
		t.Fatalf("upstreamTokenEnv = %q, want GH_TOKEN", got)
	}
}

func TestUpstreamTokenEnvFallsBackToCredentialMetadata(t *testing.T) {
	info := &CredentialInfo{EnvVars: []string{"SERVICE_TOKEN"}}
	if got := upstreamTokenEnv(UpstreamConfig{}, info); got != "SERVICE_TOKEN" {
		t.Fatalf("upstreamTokenEnv = %q, want SERVICE_TOKEN", got)
	}
}

func TestUpstreamEnvChangeRequiresRemint(t *testing.T) {
	old := UpstreamConfig{Credential: "/github/relay", Env: "OLD_TOKEN"}
	new := UpstreamConfig{Credential: "/github/relay", Env: "NEW_TOKEN"}
	if !upstreamChanged(old, new) {
		t.Fatal("env override change did not invalidate the minted token environment")
	}
}

func TestUpstreamMintsOnlyForExplicitDelivery(t *testing.T) {
	tests := []struct {
		name     string
		upstream UpstreamConfig
		want     bool
	}{
		{name: "route credential only", upstream: UpstreamConfig{Credential: "/service/session"}},
		{name: "credential environment", upstream: UpstreamConfig{Credential: "/service/session", Env: "SERVICE_TOKEN"}, want: true},
		{name: "credential file", upstream: UpstreamConfig{Credential: "/service/session", CredentialFile: "service"}, want: true},
		{name: "named policy environment", upstream: UpstreamConfig{Authorization: "context", Env: "SERVICE_TOKEN"}, want: true},
		{name: "named credential without delivery", upstream: UpstreamConfig{Credential: "/service/session", Authorization: "context"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.upstream.MintsToken(); got != test.want {
				t.Fatalf("MintsToken() = %v, want %v", got, test.want)
			}
		})
	}
}
