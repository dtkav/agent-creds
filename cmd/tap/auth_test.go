package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthTrackerCorrelatesRegardlessOfOrderAndClears(t *testing.T) {
	tracker := NewAuthTracker()
	at := time.Date(2026, 8, 19, 22, 58, 16, 0, time.UTC)
	tracker.ObserveOperation(Operation{
		Source: "kind", AgentID: "kind", AgentName: "Kind",
		Provider: "anthropic", Operation: "messages", StatusCode: 401,
		EndedAt: at.Add(time.Second).Format(time.RFC3339Nano),
	})
	if alerts := tracker.Alerts(); len(alerts) != 0 {
		t.Fatalf("provider 401 alone created alert: %+v", alerts)
	}
	tracker.ObserveOAuth("kind", "Kind", 400, at)

	alerts := tracker.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("correlated failures produced %d alerts: %+v", len(alerts), alerts)
	}
	alert := alerts[0]
	if alert.AgentID != "kind" || alert.AgentName != "Kind" ||
		alert.Provider != "anthropic" || alert.OAuthStatus != 400 ||
		alert.ProviderStatus != 401 || alert.FailureCount != 1 {
		t.Fatalf("unexpected alert: %+v", alert)
	}
	metrics := tracker.Metrics()
	if len(metrics) != 1 || !metrics[0].Blocked || metrics[0].FailureCount != 1 {
		t.Fatalf("unexpected blocked metric: %+v", metrics)
	}

	tracker.ObserveOAuth("kind", "Kind", 200, at.Add(time.Minute))
	if alerts := tracker.Alerts(); len(alerts) != 0 {
		t.Fatalf("successful OAuth exchange did not clear alert: %+v", alerts)
	}
	metrics = tracker.Metrics()
	if len(metrics) != 1 || metrics[0].Blocked || metrics[0].FailureCount != 1 {
		t.Fatalf("unexpected recovered metric: %+v", metrics)
	}
}

func TestAuthTrackerDeactivationClearsAlertButRetainsCounter(t *testing.T) {
	tracker := NewAuthTracker()
	at := time.Now().UTC().Truncate(time.Second)
	tracker.ObserveOAuth("agent", "Agent", 400, at)
	tracker.ObserveOperation(Operation{
		AgentID: "agent", Provider: "anthropic", Operation: "messages",
		StatusCode: 401, EndedAt: at.Add(time.Second).Format(time.RFC3339Nano),
	})
	tracker.Deactivate("agent")
	if alerts := tracker.Alerts(); len(alerts) != 0 {
		t.Fatalf("inactive source retained alert: %+v", alerts)
	}
	metrics := tracker.Metrics()
	if len(metrics) != 1 || metrics[0].Blocked || metrics[0].FailureCount != 1 {
		t.Fatalf("inactive source lost failure counter: %+v", metrics)
	}
}

func TestAuthTrackerIgnoresUncorrelatedAndUnrelatedFailures(t *testing.T) {
	tracker := NewAuthTracker()
	at := time.Date(2026, 8, 19, 22, 58, 16, 0, time.UTC)
	tracker.ObserveOAuth("agent", "", 400, at)
	tracker.ObserveOperation(Operation{
		AgentID: "agent", Provider: "anthropic", Operation: "messages",
		StatusCode: 401, EndedAt: at.Add(authCorrelationWindow + time.Second).Format(time.RFC3339Nano),
	})
	tracker.ObserveOperation(Operation{
		AgentID: "agent", Provider: "openai", Operation: "responses",
		StatusCode: 401, EndedAt: at.Format(time.RFC3339Nano),
	})
	if alerts := tracker.Alerts(); len(alerts) != 0 {
		t.Fatalf("uncorrelated traffic created alert: %+v", alerts)
	}
}

func TestParseAuthLogLineAcceptsOnlyTimestampAndStatus(t *testing.T) {
	at, status, ok := parseAuthLogLine([]byte("2026-08-19T22:58:16Z 400"))
	if !ok || status != 400 || at.Format(time.RFC3339) != "2026-08-19T22:58:16Z" {
		t.Fatalf("valid line parsed as %v %d %v", at, status, ok)
	}
	for _, line := range []string{
		"2026-08-19T22:58:16Z 400 token",
		"platform.claude.com /v1/oauth/token 400",
		"bad-time 400",
		"2026-08-19T22:58:16Z 999",
	} {
		if _, _, ok := parseAuthLogLine([]byte(line)); ok {
			t.Fatalf("unexpectedly accepted %q", line)
		}
	}
}

func TestWatchAuthLogCorrelatesNetworkStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	at := time.Now().UTC().Truncate(time.Second)
	if err := os.WriteFile(path, []byte(at.Format("2006-01-02T15:04:05Z")+" 400\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tracker := NewAuthTracker()
	tracker.ObserveOperation(Operation{
		AgentID: "kind", AgentName: "Kind", Provider: "anthropic",
		Operation: "messages", StatusCode: 401,
		EndedAt: at.Add(time.Second).Format(time.RFC3339Nano),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAuthLog(ctx, Source{
		ID: "source", AgentID: "kind", AgentName: "Kind",
		AdminURL: "unix://" + filepath.Join(dir, "admin.sock"),
	}, tracker)

	deadline := time.Now().Add(2 * time.Second)
	for len(tracker.Alerts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if alerts := tracker.Alerts(); len(alerts) != 1 || alerts[0].AgentID != "kind" {
		t.Fatalf("watcher did not correlate status log: %+v", alerts)
	}
}

func TestNormalizerRestoresRecentUnauthorizedOperation(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "operations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	at := time.Now().UTC().Truncate(time.Second)
	operation := &Operation{
		Source: "kind", AgentID: "kind", AgentName: "Kind",
		Provider: "anthropic", Operation: "messages", Model: "unknown",
		StartedAt:  at.Format(time.RFC3339Nano),
		EndedAt:    at.Add(time.Second).Format(time.RFC3339Nano),
		DurationMS: 1000, StatusCode: 401, Outcome: "error",
	}
	if err := store.Insert(operation); err != nil {
		t.Fatal(err)
	}
	normalizer := NewNormalizer(store, NewHub())
	normalizer.auth.ObserveOAuth("kind", "Kind", 400, at)
	if alerts := normalizer.auth.Alerts(); len(alerts) != 1 {
		t.Fatalf("recent provider 401 was not restored: %+v", alerts)
	}
}
