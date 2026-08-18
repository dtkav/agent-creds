package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	maxTraceBodyBytes = 8 << 20
	traceMaxAge       = 5 * time.Minute
)

type traceState struct {
	activeID       uint64
	source         string
	agentName      string
	traceID        string
	started        time.Time
	lastSeen       time.Time
	provider       string
	operation      string
	model          string
	statusCode     int
	requestCoding  string
	responseCoding string
	requestBytes   int64
	responseBytes  int64
	requestBody    bytes.Buffer
	responseBody   bytes.Buffer
	overflowed     bool
}

type traceKey struct {
	sourceID  string
	captureID uint64
	traceID   string
}

type Normalizer struct {
	store *Store
	hub   *Hub

	mu     sync.Mutex
	traces map[traceKey]*traceState

	invalidSegments atomic.Uint64
	overflowed      atomic.Uint64
	discarded       atomic.Uint64
	nextActiveID    atomic.Uint64
}

type ActiveOperation struct {
	ID            uint64 `json:"id"`
	AgentID       string `json:"agent_id"`
	AgentName     string `json:"agent_name"`
	Provider      string `json:"provider"`
	Operation     string `json:"operation"`
	Model         string `json:"model"`
	StartedAt     string `json:"started_at"`
	LastSeenAt    string `json:"last_seen_at"`
	ElapsedMS     int64  `json:"elapsed_ms"`
	Phase         string `json:"phase"`
	RequestBytes  int64  `json:"request_bytes"`
	ResponseBytes int64  `json:"response_bytes"`
}

func NewNormalizer(store *Store, hub *Hub) *Normalizer {
	return &Normalizer{store: store, hub: hub, traces: make(map[traceKey]*traceState)}
}

func (n *Normalizer) Consume(
	sourceID, agentID, agentName string, captureID uint64, envelope json.RawMessage,
) {
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
	key := traceKey{sourceID: sourceID, captureID: captureID, traceID: traceID}

	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now().UTC()
	state := n.traces[key]
	if state == nil {
		state = &traceState{
			activeID: n.nextActiveID.Add(1),
			source:   agentID, agentName: agentName, traceID: traceID,
			started: now, lastSeen: now,
		}
		n.traces[key] = state
	}
	state.lastSeen = now

	switch {
	case first(segment, "request_headers", "requestHeaders") != nil:
		state.applyRequestHeaders(first(segment, "request_headers", "requestHeaders"))
	case first(segment, "request_body_chunk", "requestBodyChunk") != nil:
		chunk, truncated := bodyBytes(first(segment, "request_body_chunk", "requestBodyChunk"))
		state.requestBytes += int64(len(chunk))
		state.appendBounded(&state.requestBody, chunk, n)
		if truncated {
			state.markOverflowed(n)
		}
		state.parseRequestModel(n)
	case first(segment, "response_headers", "responseHeaders") != nil:
		state.applyResponseHeaders(first(segment, "response_headers", "responseHeaders"))
	case first(segment, "response_body_chunk", "responseBodyChunk") != nil:
		chunk, truncated := bodyBytes(first(segment, "response_body_chunk", "responseBodyChunk"))
		state.responseBytes += int64(len(chunk))
		state.appendBounded(&state.responseBody, chunk, n)
		if truncated {
			state.markOverflowed(n)
		}
		if op, complete := state.normalized(false, n); complete {
			n.finish(key, op)
		}
	case first(segment, "response_trailers", "responseTrailers") != nil:
		if op, _ := state.normalized(true, n); op != nil {
			n.finish(key, op)
		}
	}
}

func (n *Normalizer) Active() []ActiveOperation {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now().UTC()
	active := make([]ActiveOperation, 0, len(n.traces))
	for _, state := range n.traces {
		if state.provider != "openai" && state.provider != "anthropic" &&
			state.provider != "openrouter" {
			continue
		}
		provider := state.provider
		operation := state.operation
		model := state.model
		if operation == "" {
			operation = "request"
		}
		if model == "" {
			model = "detecting"
		}
		phase := "requesting"
		if state.statusCode != 0 || state.responseBytes != 0 {
			phase = "streaming"
		}
		active = append(active, ActiveOperation{
			ID: state.activeID, AgentID: state.source, AgentName: state.agentName,
			Provider: provider, Operation: operation, Model: model,
			StartedAt:  state.started.Format(time.RFC3339Nano),
			LastSeenAt: state.lastSeen.Format(time.RFC3339Nano),
			ElapsedMS:  now.Sub(state.started).Milliseconds(), Phase: phase,
			RequestBytes: state.requestBytes, ResponseBytes: state.responseBytes,
		})
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].StartedAt < active[j].StartedAt
	})
	return active
}

func (n *Normalizer) finish(key traceKey, op *Operation) {
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

// DiscardCapture removes partial traces when an Envoy admin stream ends. Trace
// IDs are only scoped to an originating Envoy and may repeat after a new tap
// session, so transport fragments must never cross capture generations.
func (n *Normalizer) DiscardCapture(sourceID string, captureID uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for key := range n.traces {
		if key.sourceID == sourceID && key.captureID == captureID {
			delete(n.traces, key)
			n.discarded.Add(1)
		}
	}
}

func (n *Normalizer) Reap() {
	n.mu.Lock()
	defer n.mu.Unlock()
	cutoff := time.Now().Add(-traceMaxAge)
	for key, state := range n.traces {
		if state.lastSeen.Before(cutoff) {
			op, _ := state.normalized(true, n)
			if meaningfulIncomplete(op) {
				if op.Outcome == "success" {
					op.Outcome = "incomplete"
				}
				if err := n.store.Insert(op); err == nil {
					n.hub.Publish(*op)
				}
			}
			if !meaningfulIncomplete(op) {
				n.discarded.Add(1)
			}
			delete(n.traces, key)
		}
	}
}

func meaningfulIncomplete(op *Operation) bool {
	if op == nil {
		return false
	}
	return op.StatusCode >= 400 || op.InputTokens > 0 || op.OutputTokens > 0
}

func (s *traceState) appendBounded(dst *bytes.Buffer, chunk []byte, n *Normalizer) {
	if s.overflowed || len(chunk) == 0 {
		return
	}
	if dst.Len()+len(chunk) > maxTraceBodyBytes {
		s.markOverflowed(n)
		return
	}
	dst.Write(chunk)
}

func (s *traceState) markOverflowed(n *Normalizer) {
	if s.overflowed {
		return
	}
	s.overflowed = true
	s.requestBody.Reset()
	s.responseBody.Reset()
	n.overflowed.Add(1)
}

func (s *traceState) applyRequestHeaders(value any) {
	headers := headerMap(value)
	s.requestCoding = headers["content-encoding"]
	authority := headers[":authority"]
	path := headers[":path"]
	if parsed, err := url.Parse(path); err == nil {
		path = parsed.Path
	} else if before, _, ok := strings.Cut(path, "?"); ok {
		path = before
	}
	switch {
	case openRouterAuthority(authority) && strings.HasSuffix(path, "/chat/completions"):
		s.provider, s.operation = "openrouter", "chat.completions"
	case openRouterAuthority(authority) && strings.HasSuffix(path, "/responses"):
		s.provider, s.operation = "openrouter", "responses"
	case openRouterAuthority(authority) && strings.HasSuffix(path, "/completions"):
		s.provider, s.operation = "openrouter", "completions"
	case openRouterAuthority(authority):
		// Do not classify unsupported OpenRouter routes by path alone.
	case strings.EqualFold(authority, "api.openai.com") || strings.HasSuffix(path, "/responses"):
		s.provider, s.operation = "openai", "responses"
	case strings.EqualFold(authority, "api.anthropic.com") || strings.HasSuffix(path, "/messages"):
		s.provider, s.operation = "anthropic", "messages"
	default:
		s.provider, s.operation = "unknown", "generate"
	}
}

func openRouterAuthority(authority string) bool {
	authority = strings.ToLower(strings.TrimSuffix(authority, ":443"))
	return authority == "openrouter.ai" || strings.HasSuffix(authority, ".openrouter.ai")
}

func (s *traceState) applyResponseHeaders(value any) {
	headers := headerMap(value)
	status, _ := strconv.Atoi(headers[":status"])
	s.statusCode = status
	s.responseCoding = headers["content-encoding"]
}

func (s *traceState) parseRequestModel(n *Normalizer) {
	if s.model != "" || s.overflowed {
		return
	}
	decoded, overflow := decodeContent(s.requestBody.Bytes(), s.requestCoding)
	if overflow {
		s.markOverflowed(n)
		return
	}
	var body struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(decoded, &body) == nil {
		s.model = body.Model
	}
}

func (s *traceState) normalized(force bool, n *Normalizer) (*Operation, bool) {
	if s.provider == "" {
		s.provider, s.operation = "unknown", "generate"
	}
	if s.provider == "unknown" {
		return nil, force
	}
	body, decodedOverflow := decodeContent(s.responseBody.Bytes(), s.responseCoding)
	if decodedOverflow {
		s.markOverflowed(n)
	}
	var usage tokenUsage
	var complete bool
	switch s.provider {
	case "openai":
		usage, complete = parseOpenAI(body)
	case "anthropic":
		usage, complete = parseAnthropic(body)
	case "openrouter":
		usage, complete = parseOpenRouter(body)
	}
	if s.statusCode >= 400 && json.Valid(body) {
		complete = true
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
	startedAt, endedAt, durationMS := operationTimes(s.started, s.lastSeen)
	outcome := "success"
	if s.statusCode >= 400 {
		outcome = "error"
	}
	if s.overflowed {
		outcome = "overflow"
	}
	return &Operation{
		Source: s.source, AgentID: s.source, AgentName: s.agentName,
		Provider: s.provider, Operation: s.operation,
		Model: s.model, StartedAt: startedAt, EndedAt: endedAt,
		DurationMS: durationMS, StatusCode: s.statusCode, Outcome: outcome,
		InputTokens: usage.input, OutputTokens: usage.output,
		CacheReadTokens: usage.cacheRead, CacheWriteTokens: usage.cacheWrite,
		ReasoningTokens: usage.reasoning, CostCredits: usage.cost,
		RequestBytes:  s.requestBytes,
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
	cost       float64
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

func parseOpenRouter(body []byte) (tokenUsage, bool) {
	var root map[string]any
	if json.Unmarshal(body, &root) == nil {
		return openRouterObject(root), hasOpenRouterUsage(root)
	}
	var usage tokenUsage
	var reported bool
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
		current := openRouterObject(event)
		if current.model != "" {
			usage.model = current.model
		}
		if hasOpenRouterUsage(event) {
			if current.model == "" {
				current.model = usage.model
			}
			usage = current
			reported = true
			completed = true
		}
		eventType := scalarString(event["type"])
		if eventType == "response.done" || eventType == "response.completed" {
			completed = true
		}
	}
	return usage, completed && reported
}

func hasOpenRouterUsage(root map[string]any) bool {
	object := root
	if nested, ok := root["response"].(map[string]any); ok {
		object = nested
	}
	usage, _ := object["usage"].(map[string]any)
	if usage == nil {
		usage, _ = root["usage"].(map[string]any)
	}
	return usage != nil
}

func openRouterObject(root map[string]any) tokenUsage {
	object := root
	if nested, ok := root["response"].(map[string]any); ok {
		object = nested
	}
	usage, _ := object["usage"].(map[string]any)
	if usage == nil {
		usage, _ = root["usage"].(map[string]any)
	}
	promptDetails, _ := usage["prompt_tokens_details"].(map[string]any)
	if promptDetails == nil {
		promptDetails, _ = usage["input_tokens_details"].(map[string]any)
	}
	completionDetails, _ := usage["completion_tokens_details"].(map[string]any)
	if completionDetails == nil {
		completionDetails, _ = usage["output_tokens_details"].(map[string]any)
	}
	input := intValue(usage["prompt_tokens"])
	if input == 0 {
		input = intValue(usage["input_tokens"])
	}
	output := intValue(usage["completion_tokens"])
	if output == 0 {
		output = intValue(usage["output_tokens"])
	}
	return tokenUsage{
		model:      scalarString(object["model"]),
		input:      input,
		output:     output,
		cacheRead:  intValue(promptDetails["cached_tokens"]),
		cacheWrite: intValue(promptDetails["cache_write_tokens"]),
		reasoning:  intValue(completionDetails["reasoning_tokens"]),
		cost:       floatValue(usage["cost"]),
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

func bodyBytes(value any) ([]byte, bool) {
	object, _ := value.(map[string]any)
	if nested, ok := object["data"].(map[string]any); ok {
		object = nested
	}
	encoded := scalarString(first(object, "as_bytes", "asBytes"))
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	truncated, _ := object["truncated"].(bool)
	return decoded, truncated
}

// decodeContent reverses HTTP content codings while strictly bounding the
// decoded representation. Providers commonly compress JSON and SSE responses;
// Envoy's tap observes those bytes before an SDK decompresses them.
func decodeContent(body []byte, contentEncoding string) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}
	encodings := strings.Split(strings.ToLower(contentEncoding), ",")
	decoded := body
	for i := len(encodings) - 1; i >= 0; i-- {
		encoding := strings.TrimSpace(encodings[i])
		if encoding == "" || encoding == "identity" {
			continue
		}
		var reader io.ReadCloser
		switch encoding {
		case "gzip", "x-gzip":
			gzipReader, err := gzip.NewReader(bytes.NewReader(decoded))
			if err != nil {
				return nil, false
			}
			reader = gzipReader
		case "deflate":
			zlibReader, err := zlib.NewReader(bytes.NewReader(decoded))
			if err == nil {
				reader = zlibReader
			} else {
				reader = flate.NewReader(bytes.NewReader(decoded))
			}
		case "br":
			reader = io.NopCloser(brotli.NewReader(bytes.NewReader(decoded)))
		case "zstd":
			zstdReader, err := zstd.NewReader(bytes.NewReader(decoded))
			if err != nil {
				return nil, false
			}
			reader = zstdReader.IOReadCloser()
		default:
			return nil, false
		}
		var overflow bool
		decoded, overflow = readBounded(reader)
		_ = reader.Close()
		if overflow {
			return nil, true
		}
		if decoded == nil {
			return nil, false
		}
	}
	return decoded, false
}

func readBounded(reader io.Reader) ([]byte, bool) {
	decoded, err := io.ReadAll(io.LimitReader(reader, maxTraceBodyBytes+1))
	if len(decoded) > maxTraceBodyBytes {
		return nil, true
	}
	// Streaming compression readers can return useful partial output with
	// io.ErrUnexpectedEOF. The provider parser still requires a terminal usage
	// event, so accepting partial decoded bytes cannot finish a trace early.
	if err != nil && len(decoded) == 0 {
		return nil, false
	}
	return decoded, false
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

func floatValue(value any) float64 {
	switch value := value.(type) {
	case float64:
		return value
	case json.Number:
		result, _ := value.Float64()
		return result
	case string:
		result, _ := strconv.ParseFloat(value, 64)
		return result
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
