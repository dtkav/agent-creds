package main

import (
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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

// startBrowserForwardTCP listens on a TCP port for browser forward requests.
// In gVisor mode, binds to gateway IP so sandbox can reach it directly.
// sandboxContainerName is used for OAuth callback proxying on the host side.
// tcp-bridge inside the container handles the container side (0.0.0.0 -> localhost).
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

		// Extract localhost callback ports and set up host-side proxy.
		// tcp-bridge inside the container sets up the container-side proxy.
		if parsed, err := url.Parse(rawURL); err == nil {
			// Check main URL
			if port := parsed.Port(); port != "" {
				host := parsed.Hostname()
				if host == "localhost" || host == "127.0.0.1" {
					fmt.Fprintf(os.Stderr, "[browser-fwd] main URL has localhost:%s\n", port)
					go proxyLocalPort(sandboxContainerName, port)
					time.Sleep(100 * time.Millisecond)
				}
			}
			// Check redirect_uri parameter (OAuth flows)
			if redirectURI := parsed.Query().Get("redirect_uri"); redirectURI != "" {
				fmt.Fprintf(os.Stderr, "[browser-fwd] found redirect_uri: %s\n", redirectURI)
				if redirectParsed, err := url.Parse(redirectURI); err == nil {
					if port := redirectParsed.Port(); port != "" {
						host := redirectParsed.Hostname()
						fmt.Fprintf(os.Stderr, "[browser-fwd] redirect_uri host=%s port=%s\n", host, port)
						if host == "localhost" || host == "127.0.0.1" {
							go proxyLocalPort(sandboxContainerName, port)
							time.Sleep(100 * time.Millisecond)
						}
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

		w.Header().Set("Connection", "close")
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
