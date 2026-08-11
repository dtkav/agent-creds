package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxTraceBodyBytes = 8 << 20
	traceMaxAge       = 5 * time.Minute
)

type traceState struct {
	source        string
	traceID       string
	started       time.Time
	lastSeen      time.Time
	provider      string
	operation     string
	model         string
	statusCode    int
	requestBytes  int64
	responseBytes int64
	requestBody   bytes.Buffer
	responseBody  bytes.Buffer
	overflowed    bool
}

type Normalizer struct {
	store *Store
	hub   *Hub

	mu     sync.Mutex
	traces map[string]*traceState

	invalidSegments atomic.Uint64
	overflowed      atomic.Uint64
}

func NewNormalizer(store *Store, hub *Hub) *Normalizer {
	return &Normalizer{store: store, hub: hub, traces: make(map[string]*traceState)}
}

func (n *Normalizer) Consume(source string, envelope json.RawMessage) {
	segment, err := streamedSegment(envelope)
	if err != nil {
		n.invalidSegments.Add(1)
		return
	}
	traceID := scalarString(first(segment, "trace_id", "traceId"))
	if traceID == "" {
		n.invalidSegments.Add(1)
		return
	}
	key := source + "\x00" + traceID

	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now().UTC()
	state := n.traces[key]
	if state == nil {
		state = &traceState{
			source: source, traceID: traceID, started: now, lastSeen: now,
		}
		n.traces[key] = state
	}
	state.lastSeen = now

	switch {
	case first(segment, "request_headers", "requestHeaders") != nil:
		state.applyRequestHeaders(first(segment, "request_headers", "requestHeaders"))
	case first(segment, "request_body_chunk", "requestBodyChunk") != nil:
		chunk := bodyBytes(first(segment, "request_body_chunk", "requestBodyChunk"))
		state.requestBytes += int64(len(chunk))
		state.appendBounded(&state.requestBody, chunk, n)
		state.parseRequestModel()
	case first(segment, "response_headers", "responseHeaders") != nil:
		state.applyResponseHeaders(first(segment, "response_headers", "responseHeaders"))
	case first(segment, "response_body_chunk", "responseBodyChunk") != nil:
		chunk := bodyBytes(first(segment, "response_body_chunk", "responseBodyChunk"))
		state.responseBytes += int64(len(chunk))
		state.appendBounded(&state.responseBody, chunk, n)
		if op, complete := state.normalized(false); complete {
			n.finish(key, op)
		}
	case first(segment, "response_trailers", "responseTrailers") != nil:
		if op, _ := state.normalized(true); op != nil {
			n.finish(key, op)
		}
	}
}

func (n *Normalizer) finish(key string, op *Operation) {
	delete(n.traces, key)
	if op == nil || op.validate() != nil {
		return
	}
	if err := n.store.Insert(op); err != nil {
		// Do not include any transport material in errors.
		n.invalidSegments.Add(1)
		return
	}
	n.hub.Publish(*op)
}

func (n *Normalizer) Reap() {
	n.mu.Lock()
	defer n.mu.Unlock()
	cutoff := time.Now().Add(-traceMaxAge)
	for key, state := range n.traces {
		if state.lastSeen.Before(cutoff) {
			if op, _ := state.normalized(true); op != nil {
				if op.Outcome == "success" {
					op.Outcome = "incomplete"
				}
				if err := n.store.Insert(op); err == nil {
					n.hub.Publish(*op)
				}
			}
			delete(n.traces, key)
		}
	}
}

func (s *traceState) appendBounded(dst *bytes.Buffer, chunk []byte, n *Normalizer) {
	if s.overflowed || len(chunk) == 0 {
		return
	}
	if dst.Len()+len(chunk) > maxTraceBodyBytes {
		s.overflowed = true
		s.requestBody.Reset()
		s.responseBody.Reset()
		n.overflowed.Add(1)
		return
	}
	dst.Write(chunk)
}

func (s *traceState) applyRequestHeaders(value any) {
	headers := headerMap(value)
	authority := headers[":authority"]
	path := headers[":path"]
	if parsed, err := url.Parse(path); err == nil {
		path = parsed.Path
	} else if before, _, ok := strings.Cut(path, "?"); ok {
		path = before
	}
	switch {
	case strings.EqualFold(authority, "api.openai.com") || strings.HasSuffix(path, "/responses"):
		s.provider, s.operation = "openai", "responses"
	case strings.EqualFold(authority, "api.anthropic.com") || strings.HasSuffix(path, "/messages"):
		s.provider, s.operation = "anthropic", "messages"
	default:
		s.provider, s.operation = "unknown", "generate"
	}
}

func (s *traceState) applyResponseHeaders(value any) {
	status, _ := strconv.Atoi(headerMap(value)[":status"])
	s.statusCode = status
}

func (s *traceState) parseRequestModel() {
	if s.model != "" || s.overflowed {
		return
	}
	var body struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(s.requestBody.Bytes(), &body) == nil {
		s.model = body.Model
	}
}

func (s *traceState) normalized(force bool) (*Operation, bool) {
	if s.provider == "" {
		s.provider, s.operation = "unknown", "generate"
	}
	var usage tokenUsage
	var complete bool
	switch s.provider {
	case "openai":
		usage, complete = parseOpenAI(s.responseBody.Bytes())
	case "anthropic":
		usage, complete = parseAnthropic(s.responseBody.Bytes())
	default:
		complete = force
	}
	if s.overflowed {
		complete = force
	}
	if force {
		complete = true
	}
	if !complete {
		return nil, false
	}
	if usage.model != "" {
		s.model = usage.model
	}
	if s.model == "" {
		s.model = "unknown"
	}
	startedAt, endedAt, durationMS := operationTimes(s.started)
	outcome := "success"
	if s.statusCode >= 400 {
		outcome = "error"
	}
	if s.overflowed {
		outcome = "overflow"
	}
	return &Operation{
		Source: s.source, Provider: s.provider, Operation: s.operation,
		Model: s.model, StartedAt: startedAt, EndedAt: endedAt,
		DurationMS: durationMS, StatusCode: s.statusCode, Outcome: outcome,
		InputTokens: usage.input, OutputTokens: usage.output,
		CacheReadTokens: usage.cacheRead, CacheWriteTokens: usage.cacheWrite,
		ReasoningTokens: usage.reasoning, RequestBytes: s.requestBytes,
		ResponseBytes: s.responseBytes,
	}, true
}

type tokenUsage struct {
	model      string
	input      int64
	output     int64
	cacheRead  int64
	cacheWrite int64
	reasoning  int64
}

func parseOpenAI(body []byte) (tokenUsage, bool) {
	var root map[string]any
	if json.Unmarshal(body, &root) == nil {
		usage := openAIObject(root)
		return usage, usage.input > 0 || usage.output > 0
	}
	var usage tokenUsage
	var completed bool
	for _, data := range sseData(body) {
		if string(data) == "[DONE]" {
			completed = true
			continue
		}
		var event map[string]any
		if json.Unmarshal(data, &event) != nil {
			continue
		}
		current := openAIObject(event)
		if current.input != 0 || current.output != 0 {
			usage = current
		}
		if current.model != "" {
			usage.model = current.model
		}
		if scalarString(event["type"]) == "response.completed" {
			completed = true
		}
	}
	return usage, completed && (usage.input > 0 || usage.output > 0)
}

func openAIObject(root map[string]any) tokenUsage {
	object := root
	if nested, ok := root["response"].(map[string]any); ok {
		object = nested
	}
	usage, _ := object["usage"].(map[string]any)
	inputDetails, _ := usage["input_tokens_details"].(map[string]any)
	outputDetails, _ := usage["output_tokens_details"].(map[string]any)
	return tokenUsage{
		model:     scalarString(object["model"]),
		input:     intValue(usage["input_tokens"]),
		output:    intValue(usage["output_tokens"]),
		cacheRead: intValue(inputDetails["cached_tokens"]),
		reasoning: intValue(outputDetails["reasoning_tokens"]),
	}
}

func parseAnthropic(body []byte) (tokenUsage, bool) {
	var root map[string]any
	if json.Unmarshal(body, &root) == nil {
		usage := anthropicObject(root)
		return usage, usage.input > 0 || usage.output > 0
	}
	var usage tokenUsage
	var completed bool
	for _, data := range sseData(body) {
		var event map[string]any
		if json.Unmarshal(data, &event) != nil {
			continue
		}
		eventType := scalarString(event["type"])
		if eventType == "message_stop" {
			completed = true
		}
		current := anthropicObject(event)
		if current.model != "" {
			usage.model = current.model
		}
		if current.input != 0 {
			usage.input = current.input
		}
		if current.output != 0 {
			usage.output = current.output
		}
		if current.cacheRead != 0 {
			usage.cacheRead = current.cacheRead
		}
		if current.cacheWrite != 0 {
			usage.cacheWrite = current.cacheWrite
		}
	}
	return usage, completed && (usage.input > 0 || usage.output > 0)
}

func anthropicObject(root map[string]any) tokenUsage {
	object := root
	if nested, ok := root["message"].(map[string]any); ok {
		object = nested
	}
	usage, _ := object["usage"].(map[string]any)
	if usage == nil {
		usage, _ = root["usage"].(map[string]any)
	}
	return tokenUsage{
		model:      scalarString(object["model"]),
		input:      intValue(usage["input_tokens"]),
		output:     intValue(usage["output_tokens"]),
		cacheRead:  intValue(usage["cache_read_input_tokens"]),
		cacheWrite: intValue(usage["cache_creation_input_tokens"]),
	}
}

func streamedSegment(envelope json.RawMessage) (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(envelope, &root); err != nil {
		return nil, err
	}
	for _, key := range []string{"http_streamed_trace_segment", "httpStreamedTraceSegment"} {
		if segment, ok := root[key].(map[string]any); ok {
			return segment, nil
		}
	}
	return nil, fmt.Errorf("not an HTTP streamed trace segment")
}

func first(object map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := object[key]; ok {
			return value
		}
	}
	return nil
}

func headerMap(value any) map[string]string {
	object, _ := value.(map[string]any)
	list, _ := object["headers"].([]any)
	headers := make(map[string]string, len(list))
	for _, item := range list {
		header, _ := item.(map[string]any)
		headers[strings.ToLower(scalarString(header["key"]))] = scalarString(header["value"])
	}
	return headers
}

func bodyBytes(value any) []byte {
	object, _ := value.(map[string]any)
	if nested, ok := object["data"].(map[string]any); ok {
		object = nested
	}
	encoded := scalarString(first(object, "as_bytes", "asBytes"))
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	return decoded
}

func scalarString(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	case float64:
		return strconv.FormatInt(int64(value), 10)
	default:
		return ""
	}
}

func intValue(value any) int64 {
	switch value := value.(type) {
	case float64:
		return int64(value)
	case json.Number:
		result, _ := value.Int64()
		return result
	case int64:
		return value
	default:
		return 0
	}
}

func sseData(body []byte) [][]byte {
	var result [][]byte
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			result = append(result, bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:"))))
		}
	}
	return result
}
