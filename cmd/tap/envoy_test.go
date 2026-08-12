package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestSourceManagerReconcileAddsAndRemovesSources(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewSourceManager(nil)
	manager.Run(ctx, Config{Sources: []Source{
		{ID: "alpha", AdminURL: "unix:///missing/alpha.sock", ConfigID: "agent_creds_global_tap"},
		{ID: "beta", AdminURL: "unix:///missing/beta.sock", ConfigID: "agent_creds_global_tap"},
	}})
	status := manager.Status()
	if len(status) != 2 {
		t.Fatalf("initial source count = %d", len(status))
	}

	manager.Reconcile(ctx, Config{Sources: []Source{
		{ID: "beta", AdminURL: "unix:///missing/beta.sock", ConfigID: "agent_creds_global_tap"},
		{ID: "gamma", AdminURL: "unix:///missing/gamma.sock", ConfigID: "agent_creds_global_tap"},
	}})
	status = manager.Status()
	if len(status) != 2 {
		t.Fatalf("reconciled source count = %d", len(status))
	}
	if _, ok := status["alpha"]; ok {
		t.Fatal("removed source alpha is still registered")
	}
	if _, ok := status["beta"]; !ok {
		t.Fatal("unchanged source beta was removed")
	}
	if _, ok := status["gamma"]; !ok {
		t.Fatal("new source gamma was not registered")
	}
}

func TestLoadConfigDefaultsMissingAgentIDToSourceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	data := []byte(`{"sources":[{"id":"mq-private-session","admin_url":"unix:///tmp/admin.sock"}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Sources[0].AgentID; got != "mq-private-session" {
		t.Fatalf("legacy source agent ID = %q, want source ID", got)
	}
}

func TestTapRequestUsesBoundedFullBodyStreamingForGenAIOnly(t *testing.T) {
	payload, err := tapRequestPayload(Source{ConfigID: "test-config"})
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	tapConfig := request["tap_config"].(map[string]any)
	output := tapConfig["output_config"].(map[string]any)
	if output["max_buffered_rx_bytes"] != float64(maxTraceBodyBytes) ||
		output["max_buffered_tx_bytes"] != float64(maxTraceBodyBytes) {
		t.Fatalf("tap body limits are not %d bytes: %#v", maxTraceBodyBytes, output)
	}
	match := tapConfig["match"].(map[string]any)
	if _, broad := match["any_match"]; broad {
		t.Fatalf("tap still captures every HTTP request: %#v", match)
	}
	if _, ok := match["or_match"]; !ok {
		t.Fatalf("tap has no GenAI endpoint matcher: %#v", match)
	}
}

func TestUnixSourceClientUsesHTTP2(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: h2c.NewHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/tap" {
				t.Errorf("request path = %q", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}), &http2.Server{})}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())

	client, endpoint, err := sourceClient("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 {
		t.Fatalf("Unix tap protocol = %s, want HTTP/2", response.Proto)
	}
}
