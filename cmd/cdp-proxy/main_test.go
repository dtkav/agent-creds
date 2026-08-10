package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestLoadTCPUpstreams(t *testing.T) {
	upstreams = nil
	t.Setenv("CDP_PORT_MAP", "")
	t.Setenv("CDP_TCP_PORT_MAP", "9222:29222,9333:29333")
	t.Setenv("CDP_TCP_HOST", "10.0.2.2")

	loadUpstreams()

	if len(upstreams) != 2 {
		t.Fatalf("len(upstreams) = %d, want 2", len(upstreams))
	}
	if got := upstreams[0]; got.chromePort != 9222 || got.network != "tcp" || got.address != "10.0.2.2:29222" {
		t.Fatalf("first upstream = %#v", got)
	}
}

func TestTrustFilteredUpstream(t *testing.T) {
	trustFilteredUpstream = true
	t.Cleanup(func() { trustFilteredUpstream = false })
	if !isTargetAllowed(CDPTarget{}, nil) {
		t.Fatal("a pre-filtered upstream should not require a second target allowlist")
	}
}

func TestWebSocketProxySupportsTCPUpstream(t *testing.T) {
	upstreamUpgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upstreamUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		messageType, payload, err := conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(messageType, payload)
		}
	}))
	defer upstreamServer.Close()

	u := upstream{chromePort: 9222, network: "tcp", address: strings.TrimPrefix(upstreamServer.URL, "http://")}
	allowedMu.Lock()
	allowedIDs = map[string]upstream{"target": u}
	allowedMu.Unlock()
	t.Cleanup(func() {
		allowedMu.Lock()
		allowedIDs = make(map[string]upstream)
		allowedMu.Unlock()
	})

	proxyServer := httptest.NewServer(http.HandlerFunc(handleDevTools))
	defer proxyServer.Close()
	proxyURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/devtools/page/target"
	conn, _, err := websocket.DefaultDialer.Dial(proxyURL, nil)
	if err != nil {
		t.Fatalf("dialing proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	payload := []byte(`{"id":1,"method":"Runtime.enable"}`)
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		t.Fatalf("writing through proxy: %v", err)
	}
	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("reading through proxy: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %s, want %s", got, payload)
	}
}
