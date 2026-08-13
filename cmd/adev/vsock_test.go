package main

import (
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBrowserCallbackPorts(t *testing.T) {
	rawURL := "http://localhost:43123/start?redirect_uri=http%3A%2F%2Flocalhost%3A43123%2Fcallback"
	if got, want := browserCallbackPorts(rawURL), []string{"43123"}; !slices.Equal(got, want) {
		t.Fatalf("browserCallbackPorts() = %v, want %v", got, want)
	}
	if got := browserCallbackPorts("https://example.com/?redirect_uri=https%3A%2F%2Fremote.example%3A4444%2Fcallback"); len(got) != 0 {
		t.Fatalf("remote callback ports = %v, want none", got)
	}
}

func TestBrowserTargetForLogRedactsOAuthParameters(t *testing.T) {
	got := browserTargetForLog(
		"https://claude.ai/oauth/authorize?state=secret&code_challenge=also-secret#fragment")
	if want := "https://claude.ai/oauth/authorize"; got != want {
		t.Fatalf("browserTargetForLog() = %q, want %q", got, want)
	}
}

func TestHostBrowserCommandDoesNotReenterSandboxBridge(t *testing.T) {
	t.Setenv("BROWSER", "/run/adev-tools/open-browser")
	t.Setenv("BROWSER_SOCKET_PATH", "/run/adev-forward/browser.sock")
	t.Setenv("DISPLAY", ":99")

	cmd := hostBrowserCommand("https://claude.ai/oauth/authorize?test=1")
	if cmd.Path != "xdg-open" && !strings.HasSuffix(cmd.Path, "/xdg-open") {
		t.Fatalf("browser command = %q, want xdg-open", cmd.Path)
	}
	for _, item := range cmd.Env {
		if strings.HasPrefix(item, "BROWSER=") ||
			strings.HasPrefix(item, "BROWSER_SOCKET_PATH=") {
			t.Fatalf("host browser inherited sandbox bridge: %q", item)
		}
	}
	if environmentValue(cmd.Env, "DISPLAY") == "" {
		t.Fatalf("host browser lost its desktop environment: %q", cmd.Env)
	}
}

func TestOverlayDesktopEnvironmentUsesOnlyGraphicalSessionValues(t *testing.T) {
	inherited := []string{
		"DISPLAY=:stale",
		"PATH=/sandbox/bin",
		"BROWSER=/run/adev-tools/open-browser",
	}
	manager := []string{
		"DISPLAY=:fresh",
		"WAYLAND_DISPLAY=wayland-1",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"BROWSER=host-browser",
		"PATH=/host/bin",
	}

	got := overlayDesktopEnvironment(
		environmentWithout(inherited, "BROWSER", "BROWSER_SOCKET_PATH"),
		manager,
	)
	if value := environmentValue(got, "DISPLAY"); value != ":fresh" {
		t.Fatalf("DISPLAY = %q, want :fresh", value)
	}
	if value := environmentValue(got, "WAYLAND_DISPLAY"); value != "wayland-1" {
		t.Fatalf("WAYLAND_DISPLAY = %q, want wayland-1", value)
	}
	if value := environmentValue(got, "PATH"); value != "/sandbox/bin" {
		t.Fatalf("PATH = %q, want inherited sandbox path", value)
	}
	if value := environmentValue(got, "BROWSER"); value != "" {
		t.Fatalf("BROWSER = %q, want removed", value)
	}
}

func TestSlirpHostForwarderAddsLoopbackMappingOnce(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "slirp.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type apiRequest struct {
		Execute   string `json:"execute"`
		Arguments struct {
			Proto     string `json:"proto"`
			HostAddr  string `json:"host_addr"`
			HostPort  int    `json:"host_port"`
			GuestAddr string `json:"guest_addr"`
			GuestPort int    `json:"guest_port"`
		} `json:"arguments"`
	}
	requests := make(chan apiRequest, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		payload, _ := io.ReadAll(conn)
		var request apiRequest
		_ = json.Unmarshal(payload, &request)
		requests <- request
		_, _ = conn.Write([]byte(`{"return":{"id":42}}`))
	}()

	forwarder := newSlirpHostForwarder(socketPath)
	if err := forwarder.Forward("43123"); err != nil {
		t.Fatalf("first Forward: %v", err)
	}
	if err := forwarder.Forward("43123"); err != nil {
		t.Fatalf("duplicate Forward: %v", err)
	}
	request := <-requests
	if request.Execute != "add_hostfwd" || request.Arguments.Proto != "tcp" {
		t.Fatalf("request = %#v", request)
	}
	if request.Arguments.HostAddr != "127.0.0.1" || request.Arguments.HostPort != 43123 {
		t.Fatalf("host mapping = %#v", request.Arguments)
	}
	if request.Arguments.GuestAddr != "10.0.2.100" || request.Arguments.GuestPort != 43123 {
		t.Fatalf("guest mapping = %#v", request.Arguments)
	}
}
