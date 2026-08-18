package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNormalizerPersistsOnlyAllowlistedOperationData(t *testing.T) {
	path := t.TempDir() + "/operations.db"
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normalizer := NewNormalizer(store, NewHub())
	secret := "DO_NOT_PERSIST_super_secret_prompt"

	segments := []map[string]any{
		{"request_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":authority", "value": "api.openai.com"},
			map[string]any{"key": ":path", "value": "/v1/responses?token=" + secret},
			map[string]any{"key": "authorization", "value": "Bearer " + secret},
		}}},
		{"request_body_chunk": bodyChunk(`{"model":"gpt-test","input":"` + secret + `"}`)},
		{"response_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":status", "value": "200"},
			map[string]any{"key": "set-cookie", "value": secret},
		}}},
		{"response_body_chunk": bodyChunk(
			`data: {"type":"response.completed","response":{"model":"gpt-test","usage":{"input_tokens":17,"output_tokens":5,"input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":1}}}}` + "\n\n" +
				`data: [DONE]` + "\n\n" + secret)},
	}
	for _, segment := range segments {
		envelope, _ := json.Marshal(map[string]any{
			"http_streamed_trace_segment": mergeTraceID(segment),
		})
		normalizer.Consume("instance-a", "0m62fua8t3xk2sl", "Dispatch", 1, envelope)
	}
	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(operations))
	}
	op := operations[0]
	if op.Provider != "openai" || op.Model != "gpt-test" ||
		op.Source != "0m62fua8t3xk2sl" || op.AgentID != "0m62fua8t3xk2sl" ||
		op.AgentName != "Dispatch" ||
		op.InputTokens != 17 || op.OutputTokens != 5 ||
		op.CacheReadTokens != 2 || op.ReasoningTokens != 1 {
		t.Fatalf("unexpected normalized operation: %+v", op)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(database), secret) {
		t.Fatal("raw secret was found in SQLite")
	}
}

func TestNormalizerReportsOnlySafeActiveOperationFields(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/operations.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normalizer := NewNormalizer(store, NewHub())
	secret := "DO_NOT_EXPOSE_active_prompt"

	consume := func(segment map[string]any) {
		t.Helper()
		envelope, err := json.Marshal(map[string]any{
			"http_streamed_trace_segment": mergeTraceID(segment),
		})
		if err != nil {
			t.Fatal(err)
		}
		normalizer.Consume("instance-a", "agent-a", "Dispatch", 1, envelope)
	}
	consume(map[string]any{"request_headers": map[string]any{"headers": []any{
		map[string]any{"key": ":authority", "value": "api.openai.com"},
		map[string]any{"key": ":path", "value": "/v1/responses"},
	}}})
	consume(map[string]any{"request_body_chunk": bodyChunk(
		`{"model":"gpt-active","input":"` + secret + `"}`)})

	active := normalizer.Active()
	if len(active) != 1 {
		t.Fatalf("active operations = %d, want 1", len(active))
	}
	if active[0].AgentID != "agent-a" || active[0].AgentName != "Dispatch" ||
		active[0].Provider != "openai" || active[0].Model != "gpt-active" ||
		active[0].Phase != "requesting" || active[0].ElapsedMS < 0 {
		t.Fatalf("unexpected active operation: %+v", active[0])
	}
	encoded, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("active operation snapshot exposed request content")
	}
	unknownEnvelope, err := json.Marshal(map[string]any{
		"http_streamed_trace_segment": map[string]any{
			"trace_id": 2,
			"request_headers": map[string]any{"headers": []any{
				map[string]any{"key": ":authority", "value": "telemetry.example"},
				map[string]any{"key": ":path", "value": "/events"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	normalizer.Consume("instance-a", "agent-a", "Dispatch", 1, unknownEnvelope)
	if active := normalizer.Active(); len(active) != 1 {
		t.Fatalf("non-GenAI request appeared as active usage: %+v", active)
	}

	consume(map[string]any{"response_headers": map[string]any{"headers": []any{
		map[string]any{"key": ":status", "value": "200"},
	}}})
	if phase := normalizer.Active()[0].Phase; phase != "streaming" {
		t.Fatalf("active phase = %q, want streaming", phase)
	}
	consume(map[string]any{"response_body_chunk": bodyChunk(
		`data: {"type":"response.completed","response":{"model":"gpt-active","usage":{"input_tokens":10,"output_tokens":2}}}` + "\n\n")})
	if active := normalizer.Active(); len(active) != 0 {
		t.Fatalf("completed operation remained active: %+v", active)
	}
}

func TestNormalizerDecodesCompressedStreamingUsage(t *testing.T) {
	path := t.TempDir() + "/operations.db"
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normalizer := NewNormalizer(store, NewHub())
	response := []byte(`data: {"type":"response.completed","response":{"model":"gpt-compressed","usage":{"input_tokens":1234,"output_tokens":56}}}` + "\n\n")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	segments := []map[string]any{
		{"request_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":authority", "value": "chatgpt.com"},
			map[string]any{"key": ":path", "value": "/backend-api/codex/responses"},
		}}},
		{"request_body_chunk": bodyChunk(`{"model":"gpt-compressed","input":"` + strings.Repeat("x", 4096) + `"}`)},
		{"response_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":status", "value": "200"},
			map[string]any{"key": "content-encoding", "value": "gzip"},
		}}},
	}
	for _, segment := range segments {
		consumeTestSegment(t, normalizer, "engineer-b", 7, segment)
	}
	payload := compressed.Bytes()
	middle := len(payload) / 2
	consumeTestSegment(t, normalizer, "engineer-b", 7,
		map[string]any{"response_body_chunk": encodedBodyChunk(payload[:middle])})
	consumeTestSegment(t, normalizer, "engineer-b", 7,
		map[string]any{"response_body_chunk": encodedBodyChunk(payload[middle:])})

	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(operations))
	}
	op := operations[0]
	if op.Model != "gpt-compressed" || op.InputTokens != 1234 ||
		op.OutputTokens != 56 || op.RequestBytes <= 4096 || op.Outcome != "success" {
		t.Fatalf("unexpected compressed operation: %+v", op)
	}
}

func TestNormalizerDiscardsCaptureFragmentsAcrossReconnects(t *testing.T) {
	path := t.TempDir() + "/operations.db"
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normalizer := NewNormalizer(store, NewHub())
	requestHeaders := map[string]any{"request_headers": map[string]any{"headers": []any{
		map[string]any{"key": ":authority", "value": "api.openai.com"},
		map[string]any{"key": ":path", "value": "/v1/responses"},
	}}}
	consumeTestSegment(t, normalizer, "flapping-source", 1, requestHeaders)
	consumeTestSegment(t, normalizer, "flapping-source", 1,
		map[string]any{"request_body_chunk": bodyChunk(`{"model":"stale"}`)})
	normalizer.DiscardCapture("flapping-source", 1)

	consumeTestSegment(t, normalizer, "flapping-source", 2, requestHeaders)
	consumeTestSegment(t, normalizer, "flapping-source", 2,
		map[string]any{"request_body_chunk": bodyChunk(`{"model":"fresh"}`)})
	consumeTestSegment(t, normalizer, "flapping-source", 2,
		map[string]any{"response_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":status", "value": "200"},
		}}})
	consumeTestSegment(t, normalizer, "flapping-source", 2,
		map[string]any{"response_body_chunk": bodyChunk(
			`data: {"type":"response.completed","response":{"usage":{"input_tokens":8,"output_tokens":3}}}` + "\n\n")})

	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].Model != "fresh" {
		t.Fatalf("reconnected capture was contaminated: %+v", operations)
	}
}

func TestNormalizerCompletesJSONProviderErrorsWithoutUsage(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/operations.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normalizer := NewNormalizer(store, NewHub())
	consumeTestSegment(t, normalizer, "error-source", 1,
		map[string]any{"request_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":authority", "value": "api.anthropic.com"},
			map[string]any{"key": ":path", "value": "/v1/messages"},
		}}})
	consumeTestSegment(t, normalizer, "error-source", 1,
		map[string]any{"response_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":status", "value": "429"},
		}}})
	consumeTestSegment(t, normalizer, "error-source", 1,
		map[string]any{"response_body_chunk": bodyChunk(`{"type":"error"}`)})

	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].Outcome != "error" ||
		operations[0].StatusCode != 429 || operations[0].DurationMS >= 300000 {
		t.Fatalf("provider error did not complete promptly: %+v", operations)
	}
}

func TestAnthropicSSEUsage(t *testing.T) {
	body := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"model":"claude-test","usage":{"input_tokens":11,"output_tokens":1,"cache_creation_input_tokens":3,"cache_read_input_tokens":4}}}` +
		"\n\nevent: message_delta\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":9}}` +
		"\n\nevent: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n")
	usage, complete := parseAnthropic(body)
	if !complete || usage.model != "claude-test" || usage.input != 11 ||
		usage.output != 9 || usage.cacheRead != 4 || usage.cacheWrite != 3 {
		t.Fatalf("usage = %+v complete=%v", usage, complete)
	}
}

func TestNormalizerCapturesOpenRouterUsageAndCredits(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/operations.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normalizer := NewNormalizer(store, NewHub())
	consumeTestSegment(t, normalizer, "openrouter-agent", 1, map[string]any{
		"request_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":authority", "value": "openrouter.ai"},
			map[string]any{"key": ":path", "value": "/api/v1/chat/completions"},
		}},
	})
	consumeTestSegment(t, normalizer, "openrouter-agent", 1, map[string]any{
		"request_body_chunk": bodyChunk(`{"model":"anthropic/claude-test"}`),
	})
	active := normalizer.Active()
	if len(active) != 1 || active[0].Provider != "openrouter" ||
		active[0].Operation != "chat.completions" ||
		active[0].Model != "anthropic/claude-test" {
		t.Fatalf("unexpected active OpenRouter request: %+v", active)
	}
	consumeTestSegment(t, normalizer, "openrouter-agent", 1, map[string]any{
		"response_headers": map[string]any{"headers": []any{
			map[string]any{"key": ":status", "value": "200"},
		}},
	})
	consumeTestSegment(t, normalizer, "openrouter-agent", 1, map[string]any{
		"response_body_chunk": bodyChunk(
			`data: {"id":"gen-1","model":"anthropic/claude-test","usage":{"prompt_tokens":194,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":100,"cache_write_tokens":12},"completion_tokens_details":{"reasoning_tokens":3},"cost":0.00125}}` + "\n\n"),
	})
	operations, err := store.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(operations))
	}
	op := operations[0]
	if op.Provider != "openrouter" || op.Operation != "chat.completions" ||
		op.Model != "anthropic/claude-test" || op.InputTokens != 194 ||
		op.OutputTokens != 20 || op.CacheReadTokens != 100 ||
		op.CacheWriteTokens != 12 || op.ReasoningTokens != 3 ||
		op.CostCredits != 0.00125 {
		t.Fatalf("unexpected OpenRouter operation: %+v", op)
	}
}

func TestOpenRouterResponsesUsage(t *testing.T) {
	body := []byte(`data: {"type":"response.done","response":{"model":"openai/gpt-test","usage":{"input_tokens":12,"output_tokens":45,"input_tokens_details":{"cached_tokens":4},"output_tokens_details":{"reasoning_tokens":5},"cost":0.002}}}` + "\n\n" + `data: [DONE]` + "\n\n")
	usage, complete := parseOpenRouter(body)
	if !complete || usage.model != "openai/gpt-test" || usage.input != 12 ||
		usage.output != 45 || usage.cacheRead != 4 || usage.reasoning != 5 ||
		usage.cost != 0.002 {
		t.Fatalf("usage = %+v complete=%v", usage, complete)
	}
}

func bodyChunk(body string) map[string]any {
	return encodedBodyChunk([]byte(body))
}

func encodedBodyChunk(body []byte) map[string]any {
	return map[string]any{"as_bytes": base64.StdEncoding.EncodeToString(body)}
}

func mergeTraceID(segment map[string]any) map[string]any {
	result := map[string]any{"trace_id": 1}
	for key, value := range segment {
		result[key] = value
	}
	return result
}

func consumeTestSegment(
	t *testing.T, normalizer *Normalizer, source string, captureID uint64, segment map[string]any,
) {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"http_streamed_trace_segment": mergeTraceID(segment),
	})
	if err != nil {
		t.Fatal(err)
	}
	normalizer.Consume(source, source, "", captureID, envelope)
}
