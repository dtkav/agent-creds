package main

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authCorrelationWindow = 10 * time.Second
	authLogPollInterval   = 500 * time.Millisecond
)

// AuthAlert is a credential-free account authentication signal. It is formed
// by correlating two status codes already visible at the network boundary; it
// never contains a URL, header, body, token, or provider response payload.
type AuthAlert struct {
	AgentID        string `json:"agent_id"`
	AgentName      string `json:"agent_name"`
	Provider       string `json:"provider"`
	DetectedAt     string `json:"detected_at"`
	ElapsedMS      int64  `json:"elapsed_ms"`
	OAuthStatus    int    `json:"oauth_status"`
	ProviderStatus int    `json:"provider_status"`
	FailureCount   uint64 `json:"failure_count"`
}

type AuthMetric struct {
	AgentID      string
	AgentName    string
	Provider     string
	Blocked      bool
	FailureCount uint64
}

type authState struct {
	agentID                  string
	agentName                string
	lastOAuthFailure         time.Time
	lastProviderUnauthorized time.Time
	blockedSince             time.Time
	oauthStatus              int
	providerStatus           int
	failureCount             uint64
	blocked                  bool
}

type AuthTracker struct {
	mu     sync.Mutex
	states map[string]*authState
}

func NewAuthTracker() *AuthTracker {
	return &AuthTracker{states: make(map[string]*authState)}
}

func (t *AuthTracker) ObserveOAuth(agentID, agentName string, status int, at time.Time) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" || at.IsZero() {
		return
	}
	at = at.UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.state(agentID, agentName)
	switch {
	case status >= 200 && status < 300:
		state.clear()
	case status >= 400:
		state.lastOAuthFailure = at
		state.oauthStatus = status
		state.failureCount++
		state.correlate()
	}
}

func (t *AuthTracker) ObserveOperation(operation Operation) {
	if operation.Provider != "anthropic" || operation.Operation != "messages" {
		return
	}
	agentID := strings.TrimSpace(operation.AgentID)
	if agentID == "" {
		agentID = strings.TrimSpace(operation.Source)
	}
	if agentID == "" {
		return
	}
	at := operationEnd(operation)
	if at.IsZero() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.state(agentID, operation.AgentName)
	switch {
	case operation.StatusCode == 401:
		state.lastProviderUnauthorized = at.UTC()
		state.providerStatus = operation.StatusCode
		state.correlate()
	case operation.StatusCode >= 200 && operation.StatusCode < 300:
		state.clear()
	}
}

func (t *AuthTracker) Alerts() []AuthAlert {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	alerts := make([]AuthAlert, 0)
	for _, state := range t.states {
		if !state.blocked {
			continue
		}
		alerts = append(alerts, AuthAlert{
			AgentID: state.agentID, AgentName: state.agentName,
			Provider: "anthropic", DetectedAt: state.blockedSince.Format(time.RFC3339Nano),
			ElapsedMS:   now.Sub(state.blockedSince).Milliseconds(),
			OAuthStatus: state.oauthStatus, ProviderStatus: state.providerStatus,
			FailureCount: state.failureCount,
		})
	}
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].DetectedAt < alerts[j].DetectedAt
	})
	return alerts
}

func (t *AuthTracker) Metrics() []AuthMetric {
	t.mu.Lock()
	defer t.mu.Unlock()
	metrics := make([]AuthMetric, 0, len(t.states))
	for _, state := range t.states {
		if state.failureCount == 0 && !state.blocked {
			continue
		}
		metrics = append(metrics, AuthMetric{
			AgentID: state.agentID, AgentName: state.agentName,
			Provider: "anthropic", Blocked: state.blocked,
			FailureCount: state.failureCount,
		})
	}
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].AgentID < metrics[j].AgentID
	})
	return metrics
}

func (t *AuthTracker) Deactivate(agentID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state := t.states[strings.TrimSpace(agentID)]; state != nil {
		state.clear()
	}
}

func (t *AuthTracker) state(agentID, agentName string) *authState {
	state := t.states[agentID]
	if state == nil {
		state = &authState{agentID: agentID}
		t.states[agentID] = state
	}
	if strings.TrimSpace(agentName) != "" {
		state.agentName = strings.TrimSpace(agentName)
	}
	return state
}

func (s *authState) correlate() {
	if s.lastOAuthFailure.IsZero() || s.lastProviderUnauthorized.IsZero() {
		return
	}
	delta := s.lastOAuthFailure.Sub(s.lastProviderUnauthorized)
	if delta < 0 {
		delta = -delta
	}
	if delta > authCorrelationWindow {
		return
	}
	if !s.blocked {
		s.blockedSince = s.lastOAuthFailure
		if s.lastProviderUnauthorized.Before(s.blockedSince) {
			s.blockedSince = s.lastProviderUnauthorized
		}
	}
	s.blocked = true
}

func (s *authState) clear() {
	s.lastOAuthFailure = time.Time{}
	s.lastProviderUnauthorized = time.Time{}
	s.blockedSince = time.Time{}
	s.oauthStatus = 0
	s.providerStatus = 0
	s.blocked = false
}

type authLogCursor struct {
	offset  int64
	pending []byte
}

func watchAuthLog(ctx context.Context, source Source, tracker *AuthTracker) {
	path, ok := authLogPath(source)
	if !ok || tracker == nil {
		return
	}
	cursor := &authLogCursor{}
	poll := func() {
		for _, line := range readAuthLogUpdates(path, cursor) {
			at, status, valid := parseAuthLogLine(line)
			if valid {
				tracker.ObserveOAuth(source.AgentID, source.AgentName, status, at)
			}
		}
	}
	poll()
	ticker := time.NewTicker(authLogPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

func authLogPath(source Source) (string, bool) {
	parsed, err := url.Parse(source.AdminURL)
	if err != nil || parsed.Scheme != "unix" || parsed.Path == "" {
		return "", false
	}
	return filepath.Join(filepath.Dir(parsed.Path), "auth.log"), true
}

func readAuthLogUpdates(path string, cursor *authLogCursor) [][]byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil
	}
	if info.Size() < cursor.offset {
		cursor.offset = 0
		cursor.pending = nil
	}
	if _, err := file.Seek(cursor.offset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(file)
	if err != nil || len(data) == 0 {
		return nil
	}
	cursor.offset += int64(len(data))
	data = append(cursor.pending, data...)
	lastNewline := bytes.LastIndexByte(data, '\n')
	if lastNewline < 0 {
		cursor.pending = data
		return nil
	}
	complete := data[:lastNewline]
	cursor.pending = append(cursor.pending[:0], data[lastNewline+1:]...)
	return bytes.Split(complete, []byte{'\n'})
}

func parseAuthLogLine(line []byte) (time.Time, int, bool) {
	fields := strings.Fields(string(line))
	if len(fields) != 2 {
		return time.Time{}, 0, false
	}
	at, err := time.Parse("2006-01-02T15:04:05Z", fields[0])
	if err != nil {
		return time.Time{}, 0, false
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 599 {
		return time.Time{}, 0, false
	}
	return at.UTC(), status, true
}
