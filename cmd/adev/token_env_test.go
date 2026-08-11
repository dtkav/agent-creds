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
