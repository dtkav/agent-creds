package main

import "testing"

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
