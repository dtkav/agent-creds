package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Hub struct {
	mu          sync.Mutex
	subscribers map[chan Operation]struct{}
}

func NewHub() *Hub {
	return &Hub{subscribers: make(map[chan Operation]struct{})}
}

func (h *Hub) Publish(operation Operation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for subscriber := range h.subscribers {
		select {
		case subscriber <- operation:
		default:
		}
	}
}

type Server struct {
	store      *Store
	sources    *SourceManager
	normalizer *Normalizer
	hub        *Hub
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.ui)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/operations", s.operations)
	mux.HandleFunc("GET /api/operations/stream", s.stream)
	mux.HandleFunc("GET /api/export/otel-genai.jsonl", s.exportJSONL)
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "sources": s.sources.Status(),
	})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	status := s.sources.Status()
	ready := true
	for _, connected := range status {
		ready = ready && connected
	}
	code := http.StatusOK
	if !ready {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"ready": ready, "sources": status})
}

func (s *Server) operations(w http.ResponseWriter, request *http.Request) {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	operations, err := s.store.Recent(limit)
	if err != nil {
		http.Error(w, "database query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, operations)
}

func (s *Server) stream(w http.ResponseWriter, request *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	events := make(chan Operation, 64)
	s.hub.mu.Lock()
	s.hub.subscribers[events] = struct{}{}
	s.hub.mu.Unlock()
	defer func() {
		s.hub.mu.Lock()
		delete(s.hub.subscribers, events)
		s.hub.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case operation := <-events:
			data, _ := json.Marshal(operation)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) exportJSONL(w http.ResponseWriter, _ *http.Request) {
	operations, err := s.store.Recent(1000)
	if err != nil {
		http.Error(w, "database query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="genai-operations.jsonl"`)
	encoder := json.NewEncoder(w)
	for i := len(operations) - 1; i >= 0; i-- {
		op := operations[i]
		_ = encoder.Encode(map[string]any{
			"timestamp": op.EndedAt,
			"name":      "gen_ai.client.operation",
			"attributes": map[string]any{
				"agent_creds.source":             op.Source,
				"gen_ai.operation.name":          op.Operation,
				"gen_ai.provider.name":           op.Provider,
				"gen_ai.request.model":           op.Model,
				"gen_ai.usage.input_tokens":      op.InputTokens,
				"gen_ai.usage.output_tokens":     op.OutputTokens,
				"agent_creds.cache_read_tokens":  op.CacheReadTokens,
				"agent_creds.cache_write_tokens": op.CacheWriteTokens,
				"agent_creds.reasoning_tokens":   op.ReasoningTokens,
				"http.response.status_code":      op.StatusCode,
				"error.type":                     errorType(op.Outcome),
			},
		})
	}
}

func errorType(outcome string) any {
	if outcome == "success" {
		return nil
	}
	return outcome
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	rows, err := s.store.Metrics()
	if err != nil {
		http.Error(w, "database query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(w, "# HELP agent_creds_tap_source_connected Whether the tap is connected to an Envoy source.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_source_connected gauge")
	for source, connected := range s.sources.Status() {
		value := 0
		if connected {
			value = 1
		}
		fmt.Fprintf(w, "agent_creds_tap_source_connected{source=%q} %d\n", metricLabel(source), value)
	}
	fmt.Fprintln(w, "# HELP agent_creds_tap_source_reconnects_total Envoy tap stream reconnect attempts.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_source_reconnects_total counter")
	for source, reconnects := range s.sources.Reconnects() {
		fmt.Fprintf(w, "agent_creds_tap_source_reconnects_total{source=%q} %d\n",
			metricLabel(source), reconnects)
	}
	fmt.Fprintln(w, "# HELP agent_creds_tap_operations_total Completed normalized GenAI operations.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_operations_total counter")
	fmt.Fprintln(w, "# HELP agent_creds_tap_tokens_total Provider-reported tokens.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_tokens_total counter")
	fmt.Fprintln(w, "# HELP agent_creds_tap_operation_duration_seconds Total duration of normalized operations.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_operation_duration_seconds counter")
	for _, row := range rows {
		labels := fmt.Sprintf("provider=%q,model=%q,outcome=%q",
			metricLabel(row.Provider), metricLabel(row.Model), metricLabel(row.Outcome))
		fmt.Fprintf(w, "agent_creds_tap_operations_total{%s} %d\n", labels, row.Operations)
		for direction, value := range map[string]int64{
			"input": row.InputTokens, "output": row.OutputTokens,
			"cache_read": row.CacheReadTokens, "cache_write": row.CacheWriteTokens,
			"reasoning": row.ReasoningTokens,
		} {
			fmt.Fprintf(w, "agent_creds_tap_tokens_total{%s,direction=%q} %d\n",
				labels, direction, value)
		}
		fmt.Fprintf(w, "agent_creds_tap_operation_duration_seconds{%s} %.3f\n",
			labels, float64(row.DurationMS)/1000)
	}
	fmt.Fprintln(w, "# HELP agent_creds_tap_invalid_segments_total Envoy segments rejected without persistence.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_invalid_segments_total counter")
	fmt.Fprintf(w, "agent_creds_tap_invalid_segments_total %d\n", s.normalizer.invalidSegments.Load())
	fmt.Fprintln(w, "# HELP agent_creds_tap_overflowed_traces_total Traces whose bounded in-memory body buffer overflowed.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_overflowed_traces_total counter")
	fmt.Fprintf(w, "agent_creds_tap_overflowed_traces_total %d\n", s.normalizer.overflowed.Load())
	fmt.Fprintln(w, "# HELP agent_creds_tap_discarded_traces_total Partial GenAI traces discarded without persistence.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_discarded_traces_total counter")
	fmt.Fprintf(w, "agent_creds_tap_discarded_traces_total %d\n", s.normalizer.discarded.Load())
}

func metricLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, `"`, `\"`)
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) ui(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	writer := bufio.NewWriter(w)
	_ = template.Must(template.New("ui").Parse(uiHTML)).Execute(writer, nil)
	_ = writer.Flush()
}

const uiHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>agent-creds token operations</title>
<style>
:root{color-scheme:dark;background:#0b0d10;color:#e7e9ee;font:14px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
body{margin:0 auto;max-width:1500px;padding:24px}header{display:flex;gap:18px;align-items:baseline;margin-bottom:20px}
h1{font:600 20px system-ui;margin:0}.status{color:#8f98a8}.ok{color:#53d18b}.bad{color:#ff7b72}
.op{display:grid;grid-template-columns:150px minmax(240px,2fr) minmax(160px,1fr) minmax(190px,1fr) 120px 150px;gap:16px;padding:10px 12px;border-bottom:1px solid #29303a}
.op>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.head{color:#8f98a8}.tokens{color:#79c0ff}.dim{color:#8f98a8}
@media(max-width:760px){.op{grid-template-columns:1fr 1fr}.head{display:none}}
</style></head><body>
<header><h1>GenAI operations</h1><span id="status" class="status">connecting…</span></header>
<main id="ops"><div class="op head"><span>time</span><span>source</span><span>provider</span><span>model</span><span>latency</span><span>tokens in / out</span></div></main>
<script>
const root=document.getElementById("ops"),statusEl=document.getElementById("status");
function add(op){const row=document.createElement("div");row.className="op";
const cells=[[new Date(op.ended_at).toLocaleTimeString(),"dim"],[op.source,""],[op.provider+" · "+op.operation,""],[op.model,"dim"],[op.duration_ms+" ms","dim"],[op.input_tokens+" / "+op.output_tokens,"tokens"]];
for(const [value,cls] of cells){const span=document.createElement("span");span.className=cls;span.textContent=value;span.title=value;row.appendChild(span)}
root.insertBefore(row,root.children[1]);while(root.children.length>501)root.lastChild.remove()}
fetch("/api/operations").then(r=>r.json()).then(ops=>ops.reverse().forEach(add));
const stream=new EventSource("/api/operations/stream");
stream.addEventListener("ready",()=>{statusEl.textContent="live";statusEl.className="status ok"});
stream.onmessage=e=>add(JSON.parse(e.data));
stream.onerror=()=>{statusEl.textContent="disconnected";statusEl.className="status bad"};
</script></body></html>`
