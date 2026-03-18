// cdp-proxy is a protocol-aware CDP proxy that filters targets based on allow-list config.
// It listens on 127.0.0.1:9222 and proxies to one or more upstream CDP sockets with filtering.
//
// Multiple upstream support: CDP_PORT_MAP env var contains chromePort:tcpPort pairs.
// Each upstream has a socket at /tmp/cdp-<chromePort>.sock created by tcp-bridge.
// Targets from all upstreams are merged, filtered, and served on the single proxy port.
//
// Filtering behavior:
// - /json/list: Returns only allowed targets (merged from all upstreams)
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
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/websocket"
)

type CDPTargetConfig struct {
	Port  int    `toml:"port"`
	Type  string `toml:"type"`
	Title string `toml:"title"`
	URL   string `toml:"url"`
}

type Config struct {
	CDPTargets []CDPTargetConfig `toml:"cdp_target"`
}

type CDPTarget struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerUrl string `json:"webSocketDebuggerUrl,omitempty"`
	DevtoolsFrontendUrl  string `json:"devtoolsFrontendUrl,omitempty"`
	FaviconUrl           string `json:"faviconUrl,omitempty"`
	Description          string `json:"description,omitempty"`
	ParentId             string `json:"parentId,omitempty"`
	Attached             bool   `json:"attached,omitempty"`
	CanAccessOpener      bool   `json:"canAccessOpener,omitempty"`
	BrowserContextId     string `json:"browserContextId,omitempty"`
}

// upstream represents a single Chrome CDP upstream identified by its socket path.
type upstream struct {
	chromePort int    // the Chrome CDP port this upstream corresponds to
	sockPath   string // Unix socket path, e.g. /tmp/cdp-9222.sock
}

var (
	config     Config
	upstreams  []upstream                  // all upstream sockets
	portFilter map[int][]CDPTargetConfig   // chromePort → filter patterns for that port
	allowedIDs = make(map[string]string)   // targetID → sockPath (which upstream owns it)
	allowedMu  sync.RWMutex
	listenPort = 9222
	upgrader   = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

func main() {
	loadConfig()
	loadUpstreams()

	http.HandleFunc("/json/list", handleJSONList)
	http.HandleFunc("/json/", handleJSONPassthrough)
	http.HandleFunc("/devtools/", handleDevTools)
	http.HandleFunc("/", handlePassthrough)

	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	if err := http.ListenAndServe(addr, nil); err != nil {
		os.Exit(1)
	}
}

func loadConfig() {
	path := "/etc/aenv/agent-creds.toml"
	if _, err := toml.DecodeFile(path, &config); err != nil {
		config.CDPTargets = nil
	}

	// Group filter patterns by port (0 → 9222)
	portFilter = make(map[int][]CDPTargetConfig)
	for _, ct := range config.CDPTargets {
		p := ct.Port
		if p == 0 {
			p = 9222
		}
		portFilter[p] = append(portFilter[p], ct)
	}
}

func loadUpstreams() {
	cdpPortMap := os.Getenv("CDP_PORT_MAP")
	if cdpPortMap == "" {
		return
	}
	for _, entry := range strings.Split(cdpPortMap, ",") {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		var chromePort int
		if _, err := fmt.Sscanf(parts[0], "%d", &chromePort); err != nil {
			continue
		}
		sockPath := fmt.Sprintf("/tmp/cdp-%d.sock", chromePort)
		upstreams = append(upstreams, upstream{chromePort: chromePort, sockPath: sockPath})
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

func isTargetAllowed(target CDPTarget, filters []CDPTargetConfig) bool {
	if len(filters) == 0 {
		return false
	}
	for _, cfg := range filters {
		typeMatch := matchGlob(cfg.Type, target.Type)
		titleMatch := matchGlob(cfg.Title, target.Title)
		urlMatch := matchGlob(cfg.URL, target.URL)
		if typeMatch && titleMatch && urlMatch {
			return true
		}
	}
	return false
}

func isIDAllowed(id string) bool {
	allowedMu.RLock()
	defer allowedMu.RUnlock()
	_, ok := allowedIDs[id]
	return ok
}

func getIDSocket(id string) string {
	allowedMu.RLock()
	defer allowedMu.RUnlock()
	return allowedIDs[id]
}

// rewriteCDPUrl rewrites a CDP URL (webSocketDebuggerUrl or devtoolsFrontendUrl)
// to use the proxy's listen port instead of the upstream's port (typically 80 from
// the Unix socket connection). Only rewrites URLs pointing to localhost.
func rewriteCDPUrl(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}
	for _, scheme := range []string{"ws://", "wss://", "http://", "https://"} {
		if strings.HasPrefix(rawURL, scheme) {
			rest := rawURL[len(scheme):]
			slashIdx := strings.Index(rest, "/")
			if slashIdx < 0 {
				slashIdx = len(rest)
			}
			host := rest[:slashIdx]
			path := rest[slashIdx:]
			// Strip existing port to get bare hostname
			bareHost := host
			if colonIdx := strings.LastIndex(bareHost, ":"); colonIdx >= 0 {
				bareHost = bareHost[:colonIdx]
			}
			// Only rewrite localhost URLs, not external ones
			if bareHost != "localhost" && bareHost != "127.0.0.1" {
				return rawURL
			}
			return fmt.Sprintf("%s%s:%d%s", scheme, bareHost, listenPort, path)
		}
	}
	return rawURL
}

func handleJSONList(w http.ResponseWriter, r *http.Request) {
	newAllowed := make(map[string]string)
	var allTargets []CDPTarget

	for _, u := range upstreams {
		resp, err := fetchFromSocket(u.sockPath, "/json/list")
		if err != nil {
			continue
		}
		var targets []CDPTarget
		if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		// Get filters for this upstream's Chrome port
		filters := portFilter[u.chromePort]

		for _, t := range targets {
			if isTargetAllowed(t, filters) {
				t.WebSocketDebuggerUrl = rewriteCDPUrl(t.WebSocketDebuggerUrl)
				t.DevtoolsFrontendUrl = rewriteCDPUrl(t.DevtoolsFrontendUrl)
				allTargets = append(allTargets, t)
				newAllowed[t.ID] = u.sockPath
			}
		}
	}

	// Update allowed IDs cache atomically
	allowedMu.Lock()
	allowedIDs = newAllowed
	allowedMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allTargets)
}

func handleJSONPassthrough(w http.ResponseWriter, r *http.Request) {
	// For /json/version and other /json/* endpoints, use the first available upstream
	if len(upstreams) == 0 {
		http.Error(w, "no upstreams", http.StatusBadGateway)
		return
	}

	resp, err := fetchFromSocket(upstreams[0].sockPath, r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// /json/version returns a webSocketDebuggerUrl that also needs rewriting
	if strings.HasSuffix(r.URL.Path, "/json/version") {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var version map[string]interface{}
		if json.Unmarshal(body, &version) == nil {
			if wsURL, ok := version["webSocketDebuggerUrl"].(string); ok {
				version["webSocketDebuggerUrl"] = rewriteCDPUrl(wsURL)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(version)
			return
		}
		// If not JSON, fall through to raw passthrough
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

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
		handleWebSocket(w, r, targetID)
		return
	}

	// Otherwise passthrough to the target's upstream
	sock := getIDSocket(targetID)
	if sock == "" {
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}
	resp, err := fetchFromSocket(sock, r.URL.Path)
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

func handleWebSocket(w http.ResponseWriter, r *http.Request, targetID string) {
	// Look up which upstream socket owns this target
	sock := getIDSocket(targetID)
	if sock == "" {
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}

	// Connect to upstream via unix socket
	upstreamConn, err := net.Dial("unix", sock)
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
	if len(upstreams) == 0 {
		http.Error(w, "no upstreams", http.StatusBadGateway)
		return
	}
	resp, err := fetchFromSocket(upstreams[0].sockPath, r.URL.Path)
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

func fetchFromSocket(sockPath string, path string) (*http.Response, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	return client.Get("http://localhost" + path)
}
