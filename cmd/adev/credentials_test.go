package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superfly/macaroon"
)

func testAgentCredential(t *testing.T, caveats ...macaroon.Caveat) string {
	t.Helper()
	value, err := macaroon.New([]byte("test"), "agent-creds", macaroon.NewSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := value.Add(caveats...); err != nil {
		t.Fatal(err)
	}
	raw, err := value.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return agentCredentialPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func TestAttenuateAgentCredentialScopesPrimaryAndPreservesDischarge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dischargeExpiry := now.Add(40 * time.Minute).Unix()
	primary := testAgentCredential(t)
	discharge := testAgentCredential(t, &macaroon.ValidityWindow{
		NotBefore: now.Unix(),
		NotAfter:  dischargeExpiry,
	})
	hot, err := attenuateAgentCredential(primary+","+discharge, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(hot, ",")
	if len(parts) != 2 || parts[1] != discharge {
		t.Fatalf("derived credential did not preserve discharge: %q", hot)
	}
	derived, err := decodeAgentCredential(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	windows := macaroon.GetCaveats[*macaroon.ValidityWindow](&derived.UnsafeCaveats)
	if len(windows) != 1 || windows[0].NotAfter != dischargeExpiry {
		t.Fatalf("derived validity = %#v", windows)
	}
}

func TestAttenuatedAgentCredentialAcceptsDischargeBoundToStableParent(t *testing.T) {
	rootKey := macaroon.NewSigningKey()
	thirdPartyKey := macaroon.NewEncryptionKey()
	primary, err := macaroon.New([]byte("primary"), "agent-creds", rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Add3P(thirdPartyKey, "agent-creds-auth"); err != nil {
		t.Fatal(err)
	}
	tickets := primary.TicketsForThirdParty("agent-creds-auth")
	if len(tickets) != 1 {
		t.Fatalf("third-party tickets = %d", len(tickets))
	}
	_, discharge, err := macaroon.DischargeTicket(thirdPartyKey, "agent-creds-auth", tickets[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := discharge.BindToParentMacaroon(primary); err != nil {
		t.Fatal(err)
	}
	encodedPrimary, err := encodeAgentCredential(primary)
	if err != nil {
		t.Fatal(err)
	}
	encodedDischarge, err := encodeAgentCredential(discharge)
	if err != nil {
		t.Fatal(err)
	}

	hot, err := attenuateAgentCredential(
		encodedPrimary+","+encodedDischarge,
		time.Unix(1_800_000_000, 0),
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(hot, ",")
	derivedPrimary, err := decodeAgentCredential(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	derivedDischarge, err := decodeAgentCredential(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	dischargeBytes, err := derivedDischarge.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := derivedPrimary.Verify(rootKey, [][]byte{dischargeBytes}, nil); err != nil {
		t.Fatalf("bound discharge rejected attenuated descendant: %v", err)
	}
}

func TestMaterializeCredentialFilesPublishesOnlyFileEntries(t *testing.T) {
	instanceDir := filepath.Join(t.TempDir(), "generated", "instances", "test")
	projection := credentialProjectionDir(instanceDir)
	if err := os.MkdirAll(projection, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projection, "stale"), []byte("old"), 0400); err != nil {
		t.Fatal(err)
	}
	entries := []TokenEntry{
		{CredentialFile: "service-read", Combined: "hot-service"},
		{EnvVar: "LEGACY_TOKEN", Combined: "legacy"},
	}
	if err := materializeCredentialFiles(instanceDir, entries); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(projection, "service-read"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hot-service\n" {
		t.Fatalf("credential content = %q", content)
	}
	info, err := os.Stat(filepath.Join(projection, "service-read"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0400 {
		t.Fatalf("credential mode = %o, want 400", got)
	}
	if _, err := os.Stat(filepath.Join(projection, "stale")); !os.IsNotExist(err) {
		t.Fatalf("stale credential remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(projection, "LEGACY_TOKEN")); !os.IsNotExist(err) {
		t.Fatalf("environment credential was projected: %v", err)
	}
}

func TestCredentialBrokerStateIsOutsideSandboxProjection(t *testing.T) {
	instanceDir := filepath.Join("/repo", "generated", "instances", "test")
	if got := credentialAuthzDir(instanceDir); strings.HasPrefix(got, instanceDir+string(filepath.Separator)) {
		t.Fatalf("broker state %q is beneath sandbox projection %q", got, instanceDir)
	}
}

func TestPrepareCredentialAuthzDirMigratesLegacyCache(t *testing.T) {
	instanceDir := filepath.Join(t.TempDir(), "generated", "instances", "test")
	legacyDir := filepath.Join(instanceDir, "authz")
	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "api.example.test.token"), []byte("stable"), 0600); err != nil {
		t.Fatal(err)
	}

	authzDir, err := prepareCredentialAuthzDir(instanceDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyDir); !os.IsNotExist(err) {
		t.Fatalf("legacy sandbox-visible cache remains: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(authzDir, "api.example.test.token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "stable" {
		t.Fatalf("migrated token = %q", content)
	}
}

func TestValidateUpstreamsAcceptsCredentialFileDelivery(t *testing.T) {
	valid := map[string]UpstreamConfig{
		"api.example.test": {
			Credential:     "/example/read-only",
			CredentialFile: "example-token",
		},
	}
	if err := ValidateUpstreams(valid); err != nil {
		t.Fatalf("valid credential file: %v", err)
	}
	invalid := map[string]UpstreamConfig{
		"api.example.test": {
			Credential:     "/example/read-only",
			Env:            "EXAMPLE_TOKEN",
			CredentialFile: "../example-token",
		},
	}
	if err := ValidateUpstreams(invalid); err == nil {
		t.Fatal("unsafe mixed credential delivery was accepted")
	}
	duplicates := map[string]UpstreamConfig{
		"metrics.example.test": {Credential: "/metrics", CredentialFile: "observability"},
		"logs.example.test":    {Credential: "/logs", CredentialFile: "observability"},
	}
	if err := ValidateUpstreams(duplicates); err == nil {
		t.Fatal("duplicate credential file delivery was accepted")
	}
}
