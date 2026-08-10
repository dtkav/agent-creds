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

		cmd := exec.Command("xdg-open", rawURL)
		if err := cmd.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go cmd.Wait()

		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	return &ForwardState{Listener: listener}, nil
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
