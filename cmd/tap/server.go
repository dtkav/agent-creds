package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
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
	mux.HandleFunc("GET /api/activities", s.activities)
	mux.HandleFunc("GET /api/operations/stream", s.stream)
	mux.HandleFunc("GET /api/export/otel-genai.jsonl", s.exportJSONL)
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

const activityIdleGap = 45 * time.Second

type Activity struct {
	ID               string      `json:"id"`
	AgentID          string      `json:"agent_id"`
	AgentName        string      `json:"agent_name"`
	StartedAt        string      `json:"started_at"`
	EndedAt          string      `json:"ended_at"`
	DurationMS       int64       `json:"duration_ms"`
	RequestCount     int         `json:"request_count"`
	Providers        []string    `json:"providers"`
	Models           []string    `json:"models"`
	InputTokens      int64       `json:"input_tokens"`
	OutputTokens     int64       `json:"output_tokens"`
	CacheReadTokens  int64       `json:"cache_read_tokens"`
	CacheWriteTokens int64       `json:"cache_write_tokens"`
	ReasoningTokens  int64       `json:"reasoning_tokens"`
	Outcome          string      `json:"outcome"`
	Operations       []Operation `json:"operations"`

	started time.Time
	ended   time.Time
}

func (s *Server) activities(w http.ResponseWriter, request *http.Request) {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	operations, err := s.store.Recent(limit)
	if err != nil {
		http.Error(w, "database query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, groupOperations(operations, activityIdleGap))
}

func groupOperations(operations []Operation, idleGap time.Duration) []Activity {
	ordered := append([]Operation(nil), operations...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return operationStart(ordered[i]).Before(operationStart(ordered[j]))
	})

	activities := make([]Activity, 0, len(ordered))
	latestByAgent := make(map[string]int)
	for _, operation := range ordered {
		agentID := operation.AgentID
		if agentID == "" {
			agentID = operation.Source
		}
		started := operationStart(operation)
		ended := operationEnd(operation)
		index, found := latestByAgent[agentID]
		if !found || started.After(activities[index].ended.Add(idleGap)) {
			activities = append(activities, Activity{
				AgentID: agentID, AgentName: operation.AgentName,
				started: started, ended: ended, Outcome: "success",
			})
			index = len(activities) - 1
			latestByAgent[agentID] = index
		}
		activity := &activities[index]
		if started.Before(activity.started) {
			activity.started = started
		}
		if ended.After(activity.ended) {
			activity.ended = ended
		}
		if activity.AgentName == "" {
			activity.AgentName = operation.AgentName
		}
		activity.Operations = append(activity.Operations, operation)
		activity.InputTokens += operation.InputTokens
		activity.OutputTokens += operation.OutputTokens
		activity.CacheReadTokens += operation.CacheReadTokens
		activity.CacheWriteTokens += operation.CacheWriteTokens
		activity.ReasoningTokens += operation.ReasoningTokens
		if operation.Outcome != "success" {
			activity.Outcome = operation.Outcome
		}
	}

	for i := range activities {
		activity := &activities[i]
		sort.SliceStable(activity.Operations, func(i, j int) bool {
			return activity.Operations[i].ID > activity.Operations[j].ID
		})
		activity.RequestCount = len(activity.Operations)
		activity.StartedAt = activity.started.UTC().Format(time.RFC3339Nano)
		activity.EndedAt = activity.ended.UTC().Format(time.RFC3339Nano)
		activity.DurationMS = activity.ended.Sub(activity.started).Milliseconds()
		activity.ID = fmt.Sprintf("%s:%d", activity.AgentID,
			activity.Operations[len(activity.Operations)-1].ID)
		activity.Providers = uniqueOperationValues(activity.Operations, func(op Operation) string {
			return op.Provider
		})
		activity.Models = uniqueOperationValues(activity.Operations, func(op Operation) string {
			return op.Model
		})
	}
	sort.SliceStable(activities, func(i, j int) bool {
		return activities[i].ended.After(activities[j].ended)
	})
	return activities
}

func operationStart(operation Operation) time.Time {
	if parsed, err := time.Parse(time.RFC3339Nano, operation.StartedAt); err == nil {
		return parsed
	}
	return operationEnd(operation)
}

func operationEnd(operation Operation) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, operation.EndedAt)
	return parsed
}

func uniqueOperationValues(operations []Operation, value func(Operation) string) []string {
	seen := make(map[string]struct{})
	var values []string
	for _, operation := range operations {
		current := value(operation)
		if current == "" {
			continue
		}
		if _, found := seen[current]; found {
			continue
		}
		seen[current] = struct{}{}
		values = append(values, current)
	}
	sort.Strings(values)
	return values
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
				"agent_creds.agent_id":           op.AgentID,
				"agent_creds.agent_name":         op.AgentName,
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
		labels := fmt.Sprintf("agent_id=%q,agent_name=%q,provider=%q,model=%q,outcome=%q",
			metricLabel(row.AgentID), metricLabel(row.AgentName),
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
.grouping{color:#8f98a8;font-size:12px}.row{display:grid;grid-template-columns:165px minmax(240px,2fr) minmax(180px,1fr) minmax(190px,1fr) 120px 165px;gap:16px;padding:10px 12px}
.row>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.head{color:#8f98a8;border-bottom:1px solid #29303a}.tokens{color:#79c0ff}.dim{color:#8f98a8}
.activity{border-bottom:1px solid #29303a}.activity>summary{cursor:pointer;list-style:none}.activity>summary::-webkit-details-marker{display:none}.activity>summary:hover{background:#11151b}.activity[open]>summary{background:#10141a}
.activity .time:before{color:#8f98a8;content:"› ";display:inline-block;width:14px}.activity[open] .time:before{content:"⌄ "}.requests{background:#080a0d}.request{border-top:1px solid #1b2028;color:#c9cdd5}.request>span:first-child{padding-left:14px}.request-label{color:#687180}
@media(max-width:760px){body{padding:14px}.row{grid-template-columns:1fr 1fr}.head{display:none}.row>span:nth-child(n+5){display:none}}
</style></head><body>
<header><h1>GenAI activity</h1><span id="status" class="status">connecting…</span><span class="grouping" title="Requests from the same agent stay together until it has been idle for 45 seconds">grouped · 45s idle</span></header>
<main id="ops"></main>
<script>
const GAP=45000,root=document.getElementById("ops"),statusEl=document.getElementById("status");
let activities=[],seen=new Set();
function agentID(op){return op.agent_id||op.source}
function identity(value){return value.agent_name?value.agent_name+" · "+agentID(value):agentID(value)}
function unique(ops,key){return [...new Set(ops.map(op=>op[key]).filter(Boolean))].sort()}
function total(ops,key){return ops.reduce((sum,op)=>sum+(Number(op[key])||0),0)}
function summarize(activity){
 const ops=activity.operations.sort((a,b)=>b.id-a.id),starts=ops.map(op=>Date.parse(op.started_at)),ends=ops.map(op=>Date.parse(op.ended_at));
 activity.agent_id=agentID(ops[0]);activity.agent_name=ops.find(op=>op.agent_name)?.agent_name||"";
 activity.started_at=new Date(Math.min(...starts)).toISOString();activity.ended_at=new Date(Math.max(...ends)).toISOString();
 activity.duration_ms=Math.max(...ends)-Math.min(...starts);activity.request_count=ops.length;
 activity.providers=unique(ops,"provider");activity.models=unique(ops,"model");
 activity.input_tokens=total(ops,"input_tokens");activity.output_tokens=total(ops,"output_tokens");
 activity.outcome=ops.find(op=>op.outcome!=="success")?.outcome||"success";
 activity.id=activity.agent_id+":"+Math.min(...ops.map(op=>op.id));return activity
}
function canJoin(activity,op){
 if(activity.agent_id!==agentID(op))return false;
 const start=Date.parse(op.started_at),end=Date.parse(op.ended_at);
 return start<=Date.parse(activity.ended_at)+GAP&&end>=Date.parse(activity.started_at)-GAP
}
function merge(op){
 if(seen.has(op.id))return;seen.add(op.id);
 let activity=activities.find(current=>canJoin(current,op));
 if(activity)activity.operations.push(op);else{activity={operations:[op]};activities.push(activity)}
 summarize(activity);activities.sort((a,b)=>Date.parse(b.ended_at)-Date.parse(a.ended_at));trim();render()
}
function trim(){let count=0;activities=activities.filter(activity=>{count+=activity.operations.length;return count<=500||count===activity.operations.length})}
function cell(value,cls){const span=document.createElement("span");span.className=cls||"";span.textContent=value;span.title=value;return span}
function row(values,className){const element=document.createElement("div");element.className="row "+className;for(const value of values)element.appendChild(cell(value[0],value[1]));return element}
function duration(ms){if(ms<1000)return ms+" ms";if(ms<60000)return(ms/1000).toFixed(ms<10000?1:0)+" s";const minutes=Math.floor(ms/60000),seconds=Math.round(ms%60000/1000);return minutes+"m "+seconds+"s"}
function tokens(value){return Number(value).toLocaleString()}
function models(activity){return activity.models.length<=2?activity.models.join(" + "):activity.models.length+" models"}
function render(){
 const open=new Set([...root.querySelectorAll("details[open]")].map(node=>node.dataset.id));root.replaceChildren();
 root.appendChild(row([["time"],["agent"],["requests"],["models"],["elapsed"],["tokens in / out"]],"head"));
 for(const activity of activities){
  const details=document.createElement("details");details.className="activity";details.dataset.id=activity.id;details.open=open.has(activity.id);
  const summary=document.createElement("summary"),providers=activity.providers.join(" + ");summary.className="row activity-row";
  const requestSummary=activity.request_count+" request"+(activity.request_count===1?"":"s")+(providers?" · "+providers:"");
  for(const value of [[new Date(activity.ended_at).toLocaleTimeString(),"time dim"],[identity(activity),activity.outcome==="success"?"":"bad"],[requestSummary],[models(activity),"dim"],[duration(activity.duration_ms),"dim"],[tokens(activity.input_tokens)+" / "+tokens(activity.output_tokens),"tokens"]])summary.appendChild(cell(value[0],value[1]));
  details.appendChild(summary);const requests=document.createElement("div");requests.className="requests";
  for(const op of activity.operations)requests.appendChild(row([[new Date(op.ended_at).toLocaleTimeString(),"dim"],["request","request-label"],[op.provider+" · "+op.operation],[op.model,"dim"],[duration(op.duration_ms),"dim"],[tokens(op.input_tokens)+" / "+tokens(op.output_tokens),"tokens"]],"request"));
  details.appendChild(requests);root.appendChild(details)
 }
}
function connect(){const stream=new EventSource("/api/operations/stream");stream.addEventListener("ready",()=>{statusEl.textContent="live";statusEl.className="status ok"});stream.onmessage=e=>merge(JSON.parse(e.data));stream.onerror=()=>{statusEl.textContent="disconnected";statusEl.className="status bad"}}
fetch("/api/activities?limit=500").then(response=>response.json()).then(items=>{activities=items.map(summarize);for(const activity of activities)for(const op of activity.operations)seen.add(op.id);activities.sort((a,b)=>Date.parse(b.ended_at)-Date.parse(a.ended_at));render()}).catch(()=>{statusEl.textContent="load failed";statusEl.className="status bad"}).finally(connect);
</script></body></html>`
