package main

import (
	"database/sql"
	"testing"
	"time"
)

func TestStoreHidesLegacyEmptyIncompleteTraces(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/operations.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, op := range []*Operation{
		{
			Source: "old", Provider: "openai", Operation: "responses",
			Model: "unknown", StartedAt: "2026-01-01T00:00:00Z",
			EndedAt: "2026-01-01T00:05:00Z", DurationMS: 300000,
			Outcome: "incomplete",
		},
		{
			Source: "old-error", Provider: "openai", Operation: "responses",
			Model: "unknown", StartedAt: "2026-01-01T00:00:00Z",
			EndedAt: "2026-01-01T00:05:10Z", DurationMS: 310000,
			StatusCode: 429, Outcome: "error",
		},
		{
			Source: "new", Provider: "openai", Operation: "responses",
			Model: "gpt-test", StartedAt: "2026-01-01T00:00:00Z",
			EndedAt: "2026-01-01T00:00:02Z", DurationMS: 2000,
			StatusCode: 200, Outcome: "success", InputTokens: 10, OutputTokens: 2,
		},
	} {
		if err := store.Insert(op); err != nil {
			t.Fatal(err)
		}
	}

	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].Source != "new" {
		t.Fatalf("recent operations include legacy noise: %+v", operations)
	}
	metrics, err := store.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || metrics[0].Operations != 1 {
		t.Fatalf("metrics include legacy noise: %+v", metrics)
	}
}

func TestStoreMigratesAndPersistsResolvedAgentName(t *testing.T) {
	path := t.TempDir() + "/operations.db"
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`
CREATE TABLE operations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	source TEXT NOT NULL, provider TEXT NOT NULL, operation_name TEXT NOT NULL,
	model TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
	duration_ms INTEGER NOT NULL, status_code INTEGER NOT NULL,
	outcome TEXT NOT NULL, input_tokens INTEGER NOT NULL,
	output_tokens INTEGER NOT NULL, cache_read_tokens INTEGER NOT NULL,
	cache_write_tokens INTEGER NOT NULL, reasoning_tokens INTEGER NOT NULL,
	request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL
)`); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	op := &Operation{
		Source: "0m62fua8t3xk2sl", AgentID: "0m62fua8t3xk2sl", AgentName: "Dispatch",
		Provider: "openai", Operation: "responses", Model: "gpt-test",
		StartedAt: "2026-01-01T00:00:00Z", EndedAt: "2026-01-01T00:00:01Z",
		DurationMS: 1000, StatusCode: 200, Outcome: "success", InputTokens: 1,
		CostCredits: 0.00125,
	}
	if err := store.Insert(op); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(path)
	if err != nil {
		t.Fatalf("reopening migrated store: %v", err)
	}
	defer store.Close()
	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].AgentID != "0m62fua8t3xk2sl" ||
		operations[0].AgentName != "Dispatch" || operations[0].CostCredits != 0.00125 {
		t.Fatalf("migrated operation was not persisted: %+v", operations)
	}
}

func TestStoreSinceReturnsTimelineWindow(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/operations.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, endedAt := range []string{
		"2026-01-01T00:00:10Z", "2026-01-01T02:00:10Z",
	} {
		op := &Operation{
			Source: "agent", Provider: "openai", Operation: "responses",
			Model: "gpt-test", StartedAt: endedAt, EndedAt: endedAt,
			StatusCode: 200, Outcome: "success", InputTokens: 1,
		}
		if err := store.Insert(op); err != nil {
			t.Fatal(err)
		}
	}
	since, err := time.Parse(time.RFC3339, "2026-01-01T01:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := store.Since(since, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].EndedAt != "2026-01-01T02:00:10Z" {
		t.Fatalf("timeline window returned unexpected operations: %+v", operations)
	}
}
