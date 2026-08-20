package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type Source struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	AdminURL  string `json:"admin_url"`
	ConfigID  string `json:"config_id"`
}

type Config struct {
	Sources []Source `json:"sources"`
}

type sourceState struct {
	connected  atomic.Bool
	reconnects atomic.Uint64
	captures   atomic.Uint64
}

type managedSource struct {
	source Source
	state  *sourceState
	cancel context.CancelFunc
}

type SourceManager struct {
	normalizer *Normalizer
	mu         sync.RWMutex
	sources    map[string]*managedSource
}

func NewSourceManager(normalizer *Normalizer) *SourceManager {
	return &SourceManager{
		normalizer: normalizer,
		sources:    make(map[string]*managedSource),
	}
}

func LoadConfig(path string) (Config, error) {
	data, err := osReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	seen := make(map[string]bool)
	for i := range config.Sources {
		source := &config.Sources[i]
		source.ID = strings.TrimSpace(source.ID)
		source.AgentID = strings.TrimSpace(source.AgentID)
		source.AgentName = strings.TrimSpace(source.AgentName)
		source.AdminURL = strings.TrimSpace(source.AdminURL)
		if source.AgentID == "" {
			source.AgentID = source.ID
		}
		if source.ConfigID == "" {
			source.ConfigID = "agent_creds_global_tap"
		}
		if source.ID == "" || source.AdminURL == "" {
			return Config{}, fmt.Errorf("tap source %d requires id and admin_url", i)
		}
		if seen[source.ID] {
			return Config{}, fmt.Errorf("duplicate tap source %q", source.ID)
		}
		seen[source.ID] = true
	}
	return config, nil
}

func (m *SourceManager) Run(ctx context.Context, config Config) {
	m.Reconcile(ctx, config)
}

// Reconcile applies a new source set without restarting the collector. Sources
// whose endpoint did not change keep their long-lived Envoy tap stream.
func (m *SourceManager) Reconcile(ctx context.Context, config Config) {
	desired := make(map[string]Source, len(config.Sources))
	for _, source := range config.Sources {
		desired[source.ID] = source
	}

	type sourceStart struct {
		ctx    context.Context
		source Source
		state  *sourceState
	}
	var starts []sourceStart

	m.mu.Lock()
	var removedAgentIDs []string
	for id, current := range m.sources {
		next, ok := desired[id]
		if ok && next == current.source {
			delete(desired, id)
			continue
		}
		current.cancel()
		removedAgentIDs = append(removedAgentIDs, current.source.AgentID)
		delete(m.sources, id)
	}
	for _, source := range desired {
		sourceCtx, cancel := context.WithCancel(ctx)
		state := &sourceState{}
		m.sources[source.ID] = &managedSource{
			source: source, state: state, cancel: cancel,
		}
		starts = append(starts, sourceStart{
			ctx: sourceCtx, source: source, state: state,
		})
	}
	remainingAgentIDs := make(map[string]bool, len(m.sources))
	for _, current := range m.sources {
		remainingAgentIDs[current.source.AgentID] = true
	}
	m.mu.Unlock()
	if m.normalizer != nil && m.normalizer.auth != nil {
		for _, agentID := range removedAgentIDs {
			if !remainingAgentIDs[agentID] {
				m.normalizer.auth.Remove(agentID)
			}
		}
	}

	for _, start := range starts {
		go m.capture(start.ctx, start.source, start.state)
		if m.normalizer != nil && m.normalizer.auth != nil {
			go watchAuthLog(start.ctx, start.source, m.normalizer.auth)
		}
	}
}

func (m *SourceManager) Status() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]bool, len(m.sources))
	for id, source := range m.sources {
		result[id] = source.state.connected.Load()
	}
	return result
}

func (m *SourceManager) Reconnects() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]uint64, len(m.sources))
	for id, source := range m.sources {
		result[id] = source.state.reconnects.Load()
	}
	return result
}

func (m *SourceManager) capture(ctx context.Context, source Source, state *sourceState) {
	client, endpoint, err := sourceClient(source.AdminURL)
	if err != nil {
		log.Printf("tap source %q configuration error: %v", source.ID, err)
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		captureID := state.captures.Add(1)
		err := m.captureOnce(ctx, client, endpoint, source, state, captureID)
		state.connected.Store(false)
		if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
			// The error is deliberately source-level only. Response bodies from
			// Envoy admin are never logged.
			log.Printf("tap source %q disconnected: %v", source.ID, err)
		}
		state.reconnects.Add(1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (m *SourceManager) captureOnce(
	ctx context.Context, client *http.Client, endpoint string,
	source Source, state *sourceState, captureID uint64,
) error {
	payload, err := tapRequestPayload(source)
	if err != nil {
		return err
	}
	if m.normalizer != nil {
		defer m.normalizer.DiscardCapture(source.ID, captureID)
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Envoy /tap returned %s", response.Status)
	}
	state.connected.Store(true)
	decoder := json.NewDecoder(response.Body)
	for {
		var envelope json.RawMessage
		if err := decoder.Decode(&envelope); err != nil {
			return err
		}
		if m.normalizer != nil {
			m.normalizer.Consume(
				source.ID, source.AgentID, source.AgentName, captureID, envelope)
		}
	}
}

func tapRequestPayload(source Source) ([]byte, error) {
	return json.Marshal(map[string]any{
		"config_id": source.ConfigID,
		"tap_config": map[string]any{
			"match": genAIRequestMatcher(),
			"output_config": map[string]any{
				"streaming":             true,
				"max_buffered_rx_bytes": maxTraceBodyBytes,
				"max_buffered_tx_bytes": maxTraceBodyBytes,
				"sinks": []map[string]any{{
					"format":          "JSON_BODY_AS_BYTES",
					"streaming_admin": map[string]any{},
				}},
			},
		},
	})
}

func genAIRequestMatcher() map[string]any {
	pathRule := func(regex string) map[string]any {
		return map[string]any{"http_request_headers_match": map[string]any{
			"headers": []map[string]any{{
				"name": ":path",
				"string_match": map[string]any{
					"safe_regex": map[string]any{"regex": regex},
				},
			}},
		}}
	}
	return map[string]any{"or_match": map[string]any{"rules": []map[string]any{
		pathRule(`^.*/responses(\?.*)?$`),
		pathRule(`^.*/messages(\?.*)?$`),
	}}}
}

func sourceClient(adminURL string) (*http.Client, string, error) {
	parsed, err := url.Parse(adminURL)
	if err != nil {
		return nil, "", err
	}
	if parsed.Scheme == "unix" {
		socket := filepath.Clean(parsed.Path)
		if socket == "." || !filepath.IsAbs(socket) {
			return nil, "", fmt.Errorf("unix admin_url must contain an absolute socket path")
		}
		// Envoy explicitly recommends HTTP/2 or TCP for long-lived /tap admin
		// streams. HTTP/1.1 over UDS cannot reliably detect early client closes.
		transport := &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
			},
		}
		return &http.Client{Transport: transport}, "http://envoy/tap", nil
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, "", fmt.Errorf("admin_url scheme must be http, https, or unix")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/tap"
	return &http.Client{
		Transport: &http.Transport{DisableCompression: true},
	}, parsed.String(), nil
}
