package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReloadConfigStreamsConfigAndReturnsStatus(t *testing.T) {
	secretConfig := []byte("credentials:\n  service:\n    token: must-not-be-returned\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/config/reload" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(secretConfig) {
			t.Fatalf("config body = %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"reloaded","generation":2}`)
	}))
	defer server.Close()

	response, err := reloadConfig(server.Client(), server.URL, secretConfig, time.Second)
	if err != nil {
		t.Fatalf("reloadConfig: %v", err)
	}
	if string(response) != `{"status":"reloaded","generation":2}` {
		t.Fatalf("response = %s", response)
	}
}

func TestReloadConfigReturnsRejectedConfigWithoutRetry(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, `{"error":"invalid vault config"}`, http.StatusBadRequest)
	}))
	defer server.Close()

	if _, err := reloadConfig(server.Client(), server.URL, []byte("invalid"), time.Second); err == nil {
		t.Fatal("reloadConfig accepted a rejected config")
	}
	if requests != 1 {
		t.Fatalf("rejected config requests = %d, want 1", requests)
	}
}
