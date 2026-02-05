// cdp-proxy is a protocol-aware CDP proxy that filters targets based on allow-list config.
// It listens on a TCP port and proxies to /run/cdp-forward.sock with filtering applied.
//
// Filtering behavior:
// - /json/list: Returns only allowed targets
// - /devtools/page/<id>: Blocks WebSocket connections to disallowed targets
// - CDP messages: Blocks Target.attachToTarget for disallowed targetIds
//
// Configuration is loaded from /etc/aenv/agent-creds.toml [[cdp_target]] blocks.
// If no cdp_target blocks exist, all targets are blocked.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/websocket"
)

type CDPTargetConfig struct {
	Type  string `toml:"type"`
	Title string `toml:"title"`
	URL   string `toml:"url"`
}

type Config struct {
	CDPTargets []CDPTargetConfig `toml:"cdp_target"`
}

type CDPTarget struct {
	ID                       string `json:"id"`
	Type                     string `json:"type"`
	Title                    string `json:"title"`
	URL                      string `json:"url"`
	WebSocketDebuggerUrl     string `json:"webSocketDebuggerUrl,omitempty"`
	DevtoolsFrontendUrl      string `json:"devtoolsFrontendUrl,omitempty"`
	FaviconUrl               string `json:"faviconUrl,omitempty"`
	Description              string `json:"description,omitempty"`
	ParentId                 string `json:"parentId,omitempty"`
	Attached                 bool   `json:"attached,omitempty"`
	CanAccessOpener          bool   `json:"canAccessOpener,omitempty"`
	BrowserContextId         string `json:"browserContextId,omitempty"`
}

var (
	config       Config
	allowedIDs   = make(map[string]bool)
	allowedMu    sync.RWMutex
	sockPath     = "/run/cdp-forward.sock"
	upgrader     = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

func main() {
	port := 9222
	if p := os.Getenv("CDP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			port = v
		}
	}

	loadConfig()

	http.HandleFunc("/json/list", handleJSONList)
	http.HandleFunc("/json/", handleJSONPassthrough)
	http.HandleFunc("/devtools/", handleDevTools)
	http.HandleFunc("/", handlePassthrough)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		os.Exit(1)
	}
}

func loadConfig() {
	path := "/etc/aenv/agent-creds.toml"
	if _, err := toml.DecodeFile(path, &config); err != nil {
		// Config not found or invalid - all targets blocked
		config.CDPTargets = nil
	}
}

// matchGlob performs simple glob matching where * matches any characters.
func matchGlob(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	re := regexp.QuoteMeta(pattern)
	re = strings.ReplaceAll(re, `\*`, `.*`)
	re = "^" + re + "$"
	matched, _ := regexp.MatchString(re, value)
	return matched
}

func isTargetAllowed(target CDPTarget) bool {
	if len(config.CDPTargets) == 0 {
		return false
	}
	for _, cfg := range config.CDPTargets {
		typeMatch := matchGlob(cfg.Type, target.Type)
		titleMatch := matchGlob(cfg.Title, target.Title)
		urlMatch := matchGlob(cfg.URL, target.URL)
		if typeMatch && titleMatch && urlMatch {
			return true
		}
	}
	return false
}

func updateAllowedIDs(targets []CDPTarget) {
	allowedMu.Lock()
	defer allowedMu.Unlock()
	allowedIDs = make(map[string]bool)
	for _, t := range targets {
		if isTargetAllowed(t) {
			allowedIDs[t.ID] = true
		}
	}
}

func isIDAllowed(id string) bool {
	allowedMu.RLock()
	defer allowedMu.RUnlock()
	return allowedIDs[id]
}

func handleJSONList(w http.ResponseWriter, r *http.Request) {
	// Fetch from upstream
	resp, err := fetchUpstream("/json/list")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var targets []CDPTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update allowed IDs cache
	updateAllowedIDs(targets)

	// Filter targets
	var allowed []CDPTarget
	for _, t := range targets {
		if isTargetAllowed(t) {
			allowed = append(allowed, t)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allowed)
}

func handleJSONPassthrough(w http.ResponseWriter, r *http.Request) {
	resp, err := fetchUpstream(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleDevTools(w http.ResponseWriter, r *http.Request) {
	// Extract target ID from path: /devtools/page/<id>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	targetID := parts[3]

	// Check if target is allowed
	if !isIDAllowed(targetID) {
		http.Error(w, "target not allowed", http.StatusForbidden)
		return
	}

	// Check if this is a WebSocket upgrade
	if websocket.IsWebSocketUpgrade(r) {
		handleWebSocket(w, r)
		return
	}

	// Otherwise passthrough
	handlePassthrough(w, r)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Connect to upstream via unix socket
	upstreamConn, err := net.Dial("unix", sockPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// Forward the HTTP upgrade request
	if err := r.Write(upstreamConn); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Read the response
	upstreamResp, err := http.ReadResponse(bufio.NewReader(upstreamConn), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	if upstreamResp.StatusCode != http.StatusSwitchingProtocols {
		for k, v := range upstreamResp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(upstreamResp.StatusCode)
		io.Copy(w, upstreamResp.Body)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send the upgrade response to client
	upstreamResp.Write(clientConn)

	// Bidirectional proxy with CDP message filtering
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Upstream (filter messages)
	go func() {
		defer wg.Done()
		filterCDPMessages(clientBuf, upstreamConn, clientConn)
	}()

	// Upstream -> Client (passthrough)
	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
	}()

	wg.Wait()
}

// filterCDPMessages reads WebSocket frames, inspects CDP messages, and blocks
// Target.attachToTarget calls for disallowed targets.
func filterCDPMessages(src *bufio.ReadWriter, dst net.Conn, clientConn net.Conn) {
	for {
		// Read frame header
		header := make([]byte, 2)
		if _, err := io.ReadFull(src, header); err != nil {
			return
		}

		fin := header[0]&0x80 != 0
		opcode := header[0] & 0x0F
		masked := header[1]&0x80 != 0
		payloadLen := int(header[1] & 0x7F)

		// Extended payload length
		var extLen int
		if payloadLen == 126 {
			ext := make([]byte, 2)
			if _, err := io.ReadFull(src, ext); err != nil {
				return
			}
			extLen = int(ext[0])<<8 | int(ext[1])
		} else if payloadLen == 127 {
			ext := make([]byte, 8)
			if _, err := io.ReadFull(src, ext); err != nil {
				return
			}
			extLen = 0
			for i := 0; i < 8; i++ {
				extLen = extLen<<8 | int(ext[i])
			}
		} else {
			extLen = payloadLen
		}

		// Mask key
		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			if _, err := io.ReadFull(src, maskKey); err != nil {
				return
			}
		}

		// Payload
		payload := make([]byte, extLen)
		if extLen > 0 {
			if _, err := io.ReadFull(src, payload); err != nil {
				return
			}
		}

		// Unmask if needed
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		// Check for Target.attachToTarget (opcode 1 = text frame)
		if opcode == 1 && fin {
			var msg struct {
				Method string `json:"method"`
				Params struct {
					TargetId string `json:"targetId"`
				} `json:"params"`
			}
			if json.Unmarshal(payload, &msg) == nil {
				if msg.Method == "Target.attachToTarget" && msg.Params.TargetId != "" {
					if !isIDAllowed(msg.Params.TargetId) {
						// Block this message - don't forward, send error response
						continue
					}
				}
			}
		}

		// Re-mask and forward
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		// Rebuild and send frame
		dst.Write(header)
		if payloadLen == 126 {
			ext := make([]byte, 2)
			ext[0] = byte(extLen >> 8)
			ext[1] = byte(extLen)
			dst.Write(ext)
		} else if payloadLen == 127 {
			ext := make([]byte, 8)
			for i := 7; i >= 0; i-- {
				ext[i] = byte(extLen)
				extLen >>= 8
			}
			dst.Write(ext)
		}
		if masked {
			dst.Write(maskKey)
		}
		dst.Write(payload)
	}
}

func handlePassthrough(w http.ResponseWriter, r *http.Request) {
	resp, err := fetchUpstream(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func fetchUpstream(path string) (*http.Response, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	return client.Get("http://localhost" + path)
}
