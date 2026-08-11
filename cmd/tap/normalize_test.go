package main

import (
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
		normalizer.Consume("engineer-a", envelope)
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

func bodyChunk(body string) map[string]any {
	return map[string]any{"as_bytes": base64.StdEncoding.EncodeToString([]byte(body))}
}

func mergeTraceID(segment map[string]any) map[string]any {
	result := map[string]any{"trace_id": 1}
	for key, value := range segment {
		result[key] = value
	}
	return result
}
