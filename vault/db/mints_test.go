package db

import (
	"testing"
	"time"
)

func TestMintLogStoresMetadataWithoutCapability(t *testing.T) {
	database, err := Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	credential := "/records/prod"
	tokenID := "capability-uuid"
	expiresAt := time.Unix(1_800_000_000, 0)
	entry := &MintEntry{
		Timestamp:  time.Unix(1_700_000_000, 0),
		Source:     "ssh",
		Credential: &credential,
		Hosts:      []string{"records.example.com"},
		Methods:    []string{"GET"},
		Paths:      []string{"/v1/**"},
		ExpiresAt:  &expiresAt,
		TokenID:    &tokenID,
	}
	if err := database.InsertMintEntry(entry); err != nil {
		t.Fatal(err)
	}

	entries, err := database.QueryMintLog(nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("mint entries = %d, want 1", len(entries))
	}
	got := entries[0]
	if got.Source != "ssh" || got.Credential == nil || *got.Credential != credential {
		t.Fatalf("mint entry = %#v", got)
	}
	if len(got.Hosts) != 1 || got.Hosts[0] != "records.example.com" {
		t.Fatalf("mint hosts = %#v", got.Hosts)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("mint expiry = %v", got.ExpiresAt)
	}

	var columns []string
	rows, err := database.Query("PRAGMA table_info(mint_log)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	for _, column := range columns {
		if column == "token" || column == "macaroon" || column == "capability" {
			t.Fatalf("mint log has secret-bearing column %q", column)
		}
	}
}
