package main

import (
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

// AllocateTCPPorts returns deterministic TCP ports for an instance.
// Browser: 50000 + (hash(slug) % 1000)
// CDP: 51000 + (hash(slug) % 1000)
func AllocateTCPPorts(slug string) (browser int, cdp int) {
	h := fnv.New32a()
	h.Write([]byte(slug))
	offset := int(h.Sum32() % 1000)
	return 50000 + offset, 51000 + offset
}

// startBrowserForwardTCP listens on a TCP port for browser forward requests.
// In gVisor mode, binds to gateway IP so sandbox can reach it directly.
// sandboxContainerName is used for OAuth callback proxying (to reach the sandbox).
func startBrowserForwardTCP(sandboxContainerName string, bindIP string, port int, targets []BrowserTargetConfig) (*ForwardState, error) {
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

		// If the URL or its redirect_uri points to localhost with a port, set up a TCP proxy
		// so the host browser's OAuth callback can reach the sandbox container.
		if parsed, err := url.Parse(rawURL); err == nil {
			// Check main URL
			host := parsed.Hostname()
			port := parsed.Port()
			if port != "" && (host == "localhost" || host == "127.0.0.1") {
				go proxyLocalPort(sandboxContainerName, port)
				time.Sleep(100 * time.Millisecond)
			}
			// Check redirect_uri parameter (for OAuth flows)
			if redirectURI := parsed.Query().Get("redirect_uri"); redirectURI != "" {
				if redirectParsed, err := url.Parse(redirectURI); err == nil {
					host := redirectParsed.Hostname()
					port := redirectParsed.Port()
					if port != "" && (host == "localhost" || host == "127.0.0.1") {
						go proxyLocalPort(sandboxContainerName, port)
						time.Sleep(100 * time.Millisecond)
					}
				}
			}
		}

		cmd := exec.Command("xdg-open", rawURL)
		if err := cmd.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go cmd.Wait()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	return &ForwardState{Listener: listener}, nil
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
