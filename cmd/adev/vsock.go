package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AllocateTCPBrowserPort returns a deterministic TCP port for browser forwarding.
// Port: 50000 + (hash(slug) % 1000)
func AllocateTCPBrowserPort(slug string) int {
	h := fnv.New32a()
	h.Write([]byte(slug))
	return 50000 + int(h.Sum32()%1000)
}

// AllocateTCPCDPPort returns a deterministic TCP port for a specific Chrome CDP port.
// Port: 51000 + (hash(slug + cdpPort) % 1000)
func AllocateTCPCDPPort(slug string, cdpPort int) int {
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s%d", slug, cdpPort)))
	return 51000 + int(h.Sum32()%1000)
}

// BrowserCallbackForwarder publishes a localhost callback port from the host
// into a sandbox. The browser request is opened only after this succeeds.
type BrowserCallbackForwarder func(port string) error

// startBrowserForwardTCP listens on a TCP port for allowlisted browser-open
// requests. callbackForwarder provides the runtime-specific OAuth return path.
func startBrowserForwardTCP(bindIP string, port int, targets []BrowserTargetConfig, callbackForwarder BrowserCallbackForwarder) (*ForwardState, error) {
	addr := fmt.Sprintf("%s:%d", bindIP, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawURL := r.URL.Query().Get("url")
		if rawURL == "" {
			http.Error(w, "missing url parameter", http.StatusBadRequest)
			return
		}

		// Check URL against allow-list (empty list = all blocked)
		allowed := false
		for _, t := range targets {
			if MatchGlob(t.URL, rawURL) {
				allowed = true
				break
			}
		}
		if !allowed {
			fmt.Fprintf(os.Stderr, "[browser-fwd] denied target: %s\n",
				browserTargetForLog(rawURL))
			http.Error(w, "url not allowed", http.StatusForbidden)
			return
		}

		for _, callbackPort := range browserCallbackPorts(rawURL) {
			if callbackForwarder == nil {
				continue
			}
			if err := callbackForwarder(callbackPort); err != nil {
				fmt.Fprintf(os.Stderr, "[browser-fwd] callback localhost:%s: %v\n", callbackPort, err)
				http.Error(w, "callback forwarding unavailable", http.StatusBadGateway)
				return
			}
			// The sandbox-side bridge is started from the same request. Give its
			// listener a moment to bind before the host browser can redirect.
			time.Sleep(100 * time.Millisecond)
		}

		cmd := hostBrowserCommand(rawURL)
		output, err := cmd.CombinedOutput()
		if err != nil {
			detail := strings.TrimSpace(string(output))
			if detail == "" {
				detail = err.Error()
			}
			fmt.Fprintf(os.Stderr, "[browser-fwd] opening host browser: %s\n", detail)
			http.Error(w, detail, http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(os.Stderr, "[browser-fwd] opened target: %s\n",
			browserTargetForLog(rawURL))

		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	return &ForwardState{Listener: listener}, nil
}

func browserTargetForLog(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid URL>"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.User = nil
	return parsed.String()
}

// hostBrowserCommand must not inherit the sandbox's browser bridge. adev is
// commonly launched from another adev identity, whose BROWSER points back to
// /run/adev-tools/open-browser. Passing that value to xdg-open makes the host
// half recursively call the inner bridge instead of reaching the desktop.
func hostBrowserCommand(rawURL string) *exec.Cmd {
	cmd := exec.Command("xdg-open", rawURL)
	cmd.Env = hostBrowserEnvironment(os.Environ())
	return cmd
}

var desktopEnvironmentNames = map[string]bool{
	"DBUS_SESSION_BUS_ADDRESS": true,
	"DISPLAY":                  true,
	"WAYLAND_DISPLAY":          true,
	"XAUTHORITY":               true,
	"XDG_CURRENT_DESKTOP":      true,
	"XDG_RUNTIME_DIR":          true,
	"XDG_SESSION_TYPE":         true,
}

// hostBrowserEnvironment refreshes the graphical-session variables from the
// host user's long-lived systemd manager. A browser forwarder can outlive the
// terminal (or sandbox) that launched it, so its inherited DISPLAY/Wayland and
// D-Bus values are not a durable way to reach the desktop.
func hostBrowserEnvironment(inherited []string) []string {
	environment := environmentWithout(
		inherited, "BROWSER", "BROWSER_SOCKET_PATH")
	environment = ensureUserBusEnvironment(environment)
	cmd := exec.Command("systemctl", "--user", "show-environment")
	cmd.Env = environment
	output, err := cmd.Output()
	if err != nil {
		return environment
	}
	return overlayDesktopEnvironment(environment, strings.Split(string(output), "\n"))
}

func ensureUserBusEnvironment(environment []string) []string {
	runtimeDir := environmentValue(environment, "XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		candidate := fmt.Sprintf("/run/user/%d", os.Getuid())
		if _, err := os.Stat(candidate + "/bus"); err == nil {
			runtimeDir = candidate
			environment = setEnvironment(
				environment, "XDG_RUNTIME_DIR", runtimeDir)
		}
	}
	if runtimeDir != "" && environmentValue(
		environment, "DBUS_SESSION_BUS_ADDRESS") == "" {
		if _, err := os.Stat(runtimeDir + "/bus"); err == nil {
			environment = setEnvironment(
				environment, "DBUS_SESSION_BUS_ADDRESS",
				"unix:path="+runtimeDir+"/bus")
		}
	}
	return environment
}

func overlayDesktopEnvironment(environment, manager []string) []string {
	for _, item := range manager {
		name, value, found := strings.Cut(item, "=")
		if !found || !desktopEnvironmentNames[name] {
			continue
		}
		environment = setEnvironment(environment, name, value)
	}
	return environment
}

func setEnvironment(environment []string, name, value string) []string {
	environment = environmentWithout(environment, name)
	return append(environment, name+"="+value)
}

func environmentValue(environment []string, name string) string {
	for _, item := range environment {
		key, value, found := strings.Cut(item, "=")
		if found && key == name {
			return value
		}
	}
	return ""
}

func environmentWithout(environment []string, names ...string) []string {
	blocked := make(map[string]bool, len(names))
	for _, name := range names {
		blocked[name] = true
	}
	filtered := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, _ := strings.Cut(item, "=")
		if !blocked[name] {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// browserCallbackPorts extracts unique localhost ports from both the browser
// URL itself and an OAuth redirect_uri query parameter.
func browserCallbackPorts(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var ports []string
	add := func(u *url.URL) {
		port := u.Port()
		if port == "" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") || seen[port] {
			return
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return
		}
		seen[port] = true
		ports = append(ports, port)
	}
	add(parsed)
	if redirectURI := parsed.Query().Get("redirect_uri"); redirectURI != "" {
		if redirect, err := url.Parse(redirectURI); err == nil {
			add(redirect)
		}
	}
	return ports
}

// slirpHostForwarder adds loopback-only host forwards through slirp4netns's
// QMP-like API. A port is installed at most once for the life of an instance.
type slirpHostForwarder struct {
	socketPath string
	mu         sync.Mutex
	ports      map[int]bool
}

func newSlirpHostForwarder(socketPath string) *slirpHostForwarder {
	return &slirpHostForwarder{socketPath: socketPath, ports: make(map[int]bool)}
}

func (f *slirpHostForwarder) Forward(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid callback port %q", port)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ports[n] {
		return nil
	}
	request := map[string]any{
		"execute": "add_hostfwd",
		"arguments": map[string]any{
			"proto":      "tcp",
			"host_addr":  "127.0.0.1",
			"host_port":  n,
			"guest_addr": "10.0.2.100",
			"guest_port": n,
		},
	}
	if err := callSlirpAPI(f.socketPath, request); err != nil {
		return err
	}
	f.ports[n] = true
	return nil
}

func callSlirpAPI(socketPath string, request any) error {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to slirp API: %w", err)
	}
	defer conn.Close()
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(payload) >= 4096 {
		return fmt.Errorf("slirp API request is too large")
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("writing slirp API request: %w", err)
	}
	if unixConn, ok := conn.(*net.UnixConn); ok {
		if err := unixConn.CloseWrite(); err != nil {
			return fmt.Errorf("finishing slirp API request: %w", err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return fmt.Errorf("reading slirp API response: %w", err)
	}
	var result struct {
		Return json.RawMessage `json:"return"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return fmt.Errorf("decoding slirp API response: %w", err)
	}
	if len(result.Error) > 0 && string(result.Error) != "null" {
		return fmt.Errorf("slirp API rejected host forward: %s", strings.TrimSpace(string(result.Error)))
	}
	if len(result.Return) == 0 {
		return fmt.Errorf("slirp API returned no result")
	}
	return nil
}

// startCDPForwardTCP listens on TCP and forwards to a local CDP port.
func startCDPForwardTCP(bindIP string, port int, cdpPort int) (*ForwardState, error) {
	addr := fmt.Sprintf("%s:%d", bindIP, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	cdpAddr := fmt.Sprintf("localhost:%d", cdpPort)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				upstream, err := net.Dial("tcp", cdpAddr)
				if err != nil {
					return
				}
				defer upstream.Close()
				go io.Copy(upstream, c)
				io.Copy(c, upstream)
			}(conn)
		}
	}()

	return &ForwardState{Listener: listener}, nil
}
