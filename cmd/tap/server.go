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
	mux.HandleFunc("GET /api/running", s.running)
	mux.HandleFunc("GET /api/operations/stream", s.stream)
	mux.HandleFunc("GET /api/export/otel-genai.jsonl", s.exportJSONL)
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

func (s *Server) running(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.normalizer.Active())
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
	CostCredits      float64     `json:"cost_credits"`
	Outcome          string      `json:"outcome"`
	Operations       []Operation `json:"operations,omitempty"`

	started time.Time
	ended   time.Time
}

func (s *Server) activities(w http.ResponseWriter, request *http.Request) {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	var operations []Operation
	var err error
	if since := request.URL.Query().Get("since"); since != "" {
		started, parseErr := time.Parse(time.RFC3339Nano, since)
		if parseErr != nil {
			http.Error(w, "invalid since timestamp", http.StatusBadRequest)
			return
		}
		operations, err = s.store.Since(started, limit)
	} else {
		operations, err = s.store.Recent(limit)
	}
	if err != nil {
		http.Error(w, "database query failed", http.StatusInternalServerError)
		return
	}
	activities := groupOperations(operations, activityIdleGap)
	if request.URL.Query().Get("details") == "false" {
		for i := range activities {
			activities[i].Operations = nil
		}
	}
	writeJSON(w, http.StatusOK, activities)
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
		activity.CostCredits += operation.CostCredits
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
				"agent_creds.cost_credits":       op.CostCredits,
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
	fmt.Fprintln(w, "# HELP agent_creds_tap_cost_credits_total Provider-reported credits charged.")
	fmt.Fprintln(w, "# TYPE agent_creds_tap_cost_credits_total counter")
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
		fmt.Fprintf(w, "agent_creds_tap_cost_credits_total{%s} %.9f\n",
			labels, row.CostCredits)
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
<title>agent-creds activity</title>
<style>
:root{color-scheme:dark;background:#090b0e;color:#e7e9ee;font:14px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;--line:#29303a;--muted:#8f98a8;--panel:#0d1015;--green:#53d18b;--blue:#79c0ff}
*{box-sizing:border-box}body{margin:0 auto;max-width:1600px;padding:24px}header{display:flex;gap:18px;align-items:baseline;margin-bottom:22px}
h1{font:600 21px system-ui;margin:0}h2{font:600 15px system-ui;margin:0}.status,.dim{color:var(--muted)}.ok{color:var(--green)}.bad{color:#ff7b72}.tokens{color:var(--blue)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-bottom:18px;overflow:hidden}.section-head{align-items:center;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;min-height:46px;padding:10px 14px}.section-meta{color:var(--muted);font-size:12px}
.running-grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));padding:12px}.running-card{border:1px solid var(--line);border-left:3px solid var(--green);border-radius:6px;min-height:98px;padding:11px 12px}.running-title{align-items:center;display:flex;font-weight:600;gap:8px}.pulse{animation:pulse 1.6s infinite;background:var(--green);border-radius:50%;box-shadow:0 0 0 0 rgba(83,209,139,.5);height:7px;width:7px}.running-meta{color:var(--muted);margin:6px 0}.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{background:#171c24;border:1px solid #303844;border-radius:12px;color:#c8cdd6;font-size:11px;padding:2px 7px}.pending{color:#d2a8ff;font-size:11px;margin-top:7px}.empty{color:var(--muted);padding:22px;text-align:center}
@keyframes pulse{70%{box-shadow:0 0 0 7px rgba(83,209,139,0)}100%{box-shadow:0 0 0 0 rgba(83,209,139,0)}}
.window-controls{display:flex;gap:5px}.window-controls button{background:#11151b;border:1px solid var(--line);border-radius:4px;color:var(--muted);cursor:pointer;font:12px inherit;padding:3px 8px}.window-controls button.active{background:#1a2633;border-color:#426582;color:var(--blue)}
.timeline{min-height:110px;overflow-x:auto;padding:8px 0 12px}.axis,.lane{display:grid;grid-template-columns:230px minmax(700px,1fr)}.axis-label,.lane-label{border-right:1px solid var(--line);padding:0 12px}.axis-label{color:var(--muted);font-size:11px}.axis-track,.track{position:relative}.axis-track{height:25px}.tick{border-left:1px solid #242a33;height:100%;position:absolute;top:0}.tick span{color:#737d8d;font-size:10px;left:4px;position:absolute;top:0;white-space:nowrap}.tick:last-child span{left:auto;right:4px}.lane{border-top:1px solid #191e25;min-height:42px}.lane-label{align-self:stretch;min-width:0;padding-top:5px}.lane-name,.lane-id{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.lane-id{color:#697383;font-size:10px}.track{background:linear-gradient(90deg,transparent 24.9%,#171c23 25%,transparent 25.1%,transparent 49.9%,#171c23 50%,transparent 50.1%,transparent 74.9%,#171c23 75%,transparent 75.1%);height:41px}.bar{align-items:center;background:color-mix(in srgb,var(--agent) 52%,#111821);border:1px solid color-mix(in srgb,var(--agent) 75%,#26303b);border-radius:4px;color:#e8ebf0;cursor:pointer;display:flex;font-size:10px;height:24px;min-width:3px;overflow:hidden;padding:0 6px;position:absolute;text-overflow:ellipsis;top:8px;white-space:nowrap}.bar.error{border-color:#ff7b72}.bar.running{animation:activebar 1.8s ease-in-out infinite alternate;background:color-mix(in srgb,var(--agent) 70%,#183527);border-color:var(--green);cursor:default;z-index:3}.now-line{background:var(--green);height:100%;position:absolute;right:0;top:0;width:1px;z-index:4}.now-line:before{background:var(--green);border-radius:50%;content:"";height:5px;left:-2px;position:absolute;top:-2px;width:5px}@keyframes activebar{to{filter:brightness(1.25)}}
.history{border:1px solid var(--line);border-radius:8px;overflow:hidden}.grouping{color:var(--muted);font-size:11px}.row{display:grid;grid-template-columns:165px minmax(240px,2fr) minmax(180px,1fr) minmax(190px,1fr) 120px 165px;gap:16px;padding:10px 12px}.row>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.head{color:var(--muted);border-bottom:1px solid var(--line)}
.activity{border-bottom:1px solid var(--line)}.activity:last-child{border-bottom:0}.activity>summary{cursor:pointer;list-style:none}.activity>summary::-webkit-details-marker{display:none}.activity>summary:hover{background:#11151b}.activity[open]>summary{background:#10141a}.activity .time:before{color:var(--muted);content:"› ";display:inline-block;width:14px}.activity[open] .time:before{content:"⌄ "}.requests{background:#07090c}.request{border-top:1px solid #1b2028;color:#c9cdd5}.request>span:first-child{padding-left:14px}.request-label{color:#687180}
@media(max-width:760px){body{padding:12px}.running-grid{grid-template-columns:1fr}.axis,.lane{grid-template-columns:145px minmax(620px,1fr)}.row{grid-template-columns:1fr 1fr}.head{display:none}.row>span:nth-child(n+5){display:none}}
</style></head><body>
<header><h1>GenAI activity</h1><span id="status" class="status">connecting…</span><span class="section-meta">exact usage posts when a provider request completes</span></header>
<section class="panel"><div class="section-head"><h2>Running now</h2><span id="running-count" class="section-meta">checking…</span></div><div id="running" class="running-grid"></div></section>
<section class="panel"><div class="section-head"><h2>Agent timeline</h2><div id="window-controls" class="window-controls"><button data-window="3600000" class="active">1h</button><button data-window="21600000">6h</button><button data-window="86400000">24h</button></div></div><div id="timeline" class="timeline"></div></section>
<section class="history"><div class="section-head"><h2>Recent activity</h2><span class="grouping" title="Requests from the same agent stay together until it has been idle for 45 seconds">grouped by agent · 45s idle · click to expand</span></div><main id="history"></main></section>
<script>
const GAP=45000,statusEl=document.getElementById("status"),runningRoot=document.getElementById("running"),runningCount=document.getElementById("running-count"),timelineRoot=document.getElementById("timeline"),historyRoot=document.getElementById("history");
let activities=[],timelineActivities=[],running=[],seen=new Set(),timelineWindow=3600000,runningFetch=false,timelineFetch=false,timelineTimer;
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
 activity.input_tokens=total(ops,"input_tokens");activity.output_tokens=total(ops,"output_tokens");activity.cost_credits=total(ops,"cost_credits");
 activity.outcome=ops.find(op=>op.outcome!=="success")?.outcome||"success";
 activity.id=activity.agent_id+":"+Math.min(...ops.map(op=>op.id));return activity
}
function canJoin(activity,op){if(activity.agent_id!==agentID(op))return false;const start=Date.parse(op.started_at),end=Date.parse(op.ended_at);return start<=Date.parse(activity.ended_at)+GAP&&end>=Date.parse(activity.started_at)-GAP}
function merge(op){
 if(seen.has(op.id))return;seen.add(op.id);let activity=activities.find(current=>canJoin(current,op));
 if(activity)activity.operations.push(op);else{activity={operations:[op]};activities.push(activity)}
 summarize(activity);activities.sort((a,b)=>Date.parse(b.ended_at)-Date.parse(a.ended_at));trim();renderHistory();scheduleTimelineRefresh()
}
function trim(){let count=0;activities=activities.filter(activity=>{count+=activity.operations.length;return count<=1000||count===activity.operations.length})}
function cell(value,cls){const span=document.createElement("span");span.className=cls||"";span.textContent=value;span.title=value;return span}
function row(values,className){const element=document.createElement("div");element.className="row "+className;for(const value of values)element.appendChild(cell(value[0],value[1]));return element}
function duration(ms){if(ms<1000)return Math.max(0,ms)+" ms";if(ms<60000)return(ms/1000).toFixed(ms<10000?1:0)+" s";const minutes=Math.floor(ms/60000),seconds=Math.round(ms%60000/1000);return minutes+"m "+seconds+"s"}
function tokens(value){return Number(value).toLocaleString()}
function credits(value){if(!Number(value))return"";return Number(value).toLocaleString(undefined,{minimumFractionDigits:Number(value)<.01?6:2,maximumFractionDigits:6})+" cr"}
function usage(value){const tokenText=tokens(value.input_tokens)+" / "+tokens(value.output_tokens);return value.cost_credits?tokenText+" · "+credits(value.cost_credits):tokenText}
function models(activity){return activity.models.length<=2?activity.models.join(" + "):activity.models.length+" models"}
function agentColor(id){let hash=0;for(let i=0;i<id.length;i++)hash=(hash*31+id.charCodeAt(i))|0;return"hsl("+Math.abs(hash%360)+" 64% 58%)"}
function groupRunning(){
 const groups=new Map();for(const op of running){const id=agentID(op);if(!groups.has(id))groups.set(id,{agent_id:id,agent_name:op.agent_name||"",operations:[]});groups.get(id).operations.push(op)}
 return [...groups.values()].sort((a,b)=>Math.min(...a.operations.map(op=>Date.parse(op.started_at)))-Math.min(...b.operations.map(op=>Date.parse(op.started_at))))
}
function renderRunning(){
 const groups=groupRunning();runningRoot.replaceChildren();runningCount.textContent=running.length+" request"+(running.length===1?"":"s")+" in flight";
 if(!groups.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="No provider requests in flight";runningRoot.appendChild(empty);return}
 for(const group of groups){const card=document.createElement("article");card.className="running-card";card.style.borderLeftColor=agentColor(group.agent_id);
  const title=document.createElement("div");title.className="running-title";const pulse=document.createElement("span");pulse.className="pulse";title.appendChild(pulse);title.appendChild(cell(identity(group)));card.appendChild(title);
  const earliest=Math.min(...group.operations.map(op=>Date.parse(op.started_at))),meta=document.createElement("div");meta.className="running-meta";meta.textContent=group.operations.length+" request"+(group.operations.length===1?"":"s")+" · running "+duration(Date.now()-earliest);card.appendChild(meta);
  const chips=document.createElement("div");chips.className="chips";for(const op of group.operations){const chip=document.createElement("span");chip.className="chip";chip.textContent=op.provider+" · "+op.model+" · "+op.phase;chips.appendChild(chip)}card.appendChild(chips);
  const pending=document.createElement("div");pending.className="pending";pending.textContent="tokens and credits pending final provider packet";card.appendChild(pending);runningRoot.appendChild(card)
 }
}
function timelineAgent(value){return{agent_id:agentID(value),agent_name:value.agent_name||""}}
function renderTimeline(){
 const now=Date.now(),windowStart=now-timelineWindow,lanes=new Map();
 for(const activity of timelineActivities){if(Date.parse(activity.ended_at)<windowStart)continue;const id=activity.agent_id;if(!lanes.has(id))lanes.set(id,{identity:timelineAgent(activity),activities:[],running:[]});lanes.get(id).activities.push(activity)}
 for(const op of running){const id=agentID(op);if(!lanes.has(id))lanes.set(id,{identity:timelineAgent(op),activities:[],running:[]});lanes.get(id).running.push(op)}
 const ordered=[...lanes.values()].sort((a,b)=>identity(a.identity).localeCompare(identity(b.identity)));timelineRoot.replaceChildren();
 const axis=document.createElement("div");axis.className="axis";const axisLabel=document.createElement("div");axisLabel.className="axis-label";axisLabel.textContent=ordered.length+" agent"+(ordered.length===1?"":"s");axis.appendChild(axisLabel);const axisTrack=document.createElement("div");axisTrack.className="axis-track";
 for(const percent of [0,25,50,75,100]){const tick=document.createElement("div");tick.className="tick";tick.style.left=percent+"%";const label=document.createElement("span");label.textContent=new Date(windowStart+timelineWindow*percent/100).toLocaleTimeString([], {hour:"numeric",minute:"2-digit"});tick.appendChild(label);axisTrack.appendChild(tick)}axis.appendChild(axisTrack);timelineRoot.appendChild(axis);
 if(!ordered.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="No activity in this window";timelineRoot.appendChild(empty);return}
 for(const lane of ordered){const element=document.createElement("div");element.className="lane";const label=document.createElement("div");label.className="lane-label";const name=document.createElement("div");name.className="lane-name";name.textContent=lane.identity.agent_name||lane.identity.agent_id;const id=document.createElement("div");id.className="lane-id";id.textContent=lane.identity.agent_name?lane.identity.agent_id:"";label.appendChild(name);label.appendChild(id);element.appendChild(label);const track=document.createElement("div");track.className="track";const color=agentColor(lane.identity.agent_id);
  for(const activity of lane.activities){const start=Math.max(windowStart,Date.parse(activity.started_at)),end=Math.min(now,Date.parse(activity.ended_at)),bar=document.createElement("div");bar.className="bar"+(activity.outcome==="success"?"":" error");bar.style.setProperty("--agent",color);bar.style.left=Math.max(0,(start-windowStart)/timelineWindow*100)+"%";bar.style.width=Math.max(.25,(end-start)/timelineWindow*100)+"%";bar.textContent=activity.request_count+" req · "+(activity.cost_credits?credits(activity.cost_credits):tokens(activity.input_tokens+activity.output_tokens)+" tok");bar.title=identity(activity)+"\n"+new Date(activity.started_at).toLocaleString()+" – "+new Date(activity.ended_at).toLocaleTimeString()+"\n"+activity.request_count+" requests · "+usage(activity);bar.addEventListener("click",()=>openActivity(activity.id));track.appendChild(bar)}
  if(lane.running.length){const start=Math.max(windowStart,Math.min(...lane.running.map(op=>Date.parse(op.started_at)))),bar=document.createElement("div");bar.className="bar running";bar.style.setProperty("--agent",color);bar.style.left=Math.max(0,(start-windowStart)/timelineWindow*100)+"%";bar.style.width=Math.max(.35,(now-start)/timelineWindow*100)+"%";bar.textContent=lane.running.length+" live";bar.title=identity(lane.identity)+"\n"+lane.running.length+" request"+(lane.running.length===1?"":"s")+" in flight · usage pending";track.appendChild(bar)}
  const nowLine=document.createElement("div");nowLine.className="now-line";track.appendChild(nowLine);element.appendChild(track);timelineRoot.appendChild(element)
 }
}
function openActivity(id){const details=[...historyRoot.querySelectorAll("details")].find(node=>node.dataset.id===id);if(!details)return;details.open=true;details.scrollIntoView({behavior:"smooth",block:"center"})}
function renderHistory(){
 const open=new Set([...historyRoot.querySelectorAll("details[open]")].map(node=>node.dataset.id));historyRoot.replaceChildren();historyRoot.appendChild(row([["time"],["agent"],["requests"],["models"],["elapsed"],["tokens in / out · credits"]],"head"));
 for(const activity of activities){const details=document.createElement("details");details.className="activity";details.dataset.id=activity.id;details.open=open.has(activity.id);const summary=document.createElement("summary"),providers=activity.providers.join(" + ");summary.className="row activity-row";const requestSummary=activity.request_count+" request"+(activity.request_count===1?"":"s")+(providers?" · "+providers:"");for(const value of [[new Date(activity.ended_at).toLocaleTimeString(),"time dim"],[identity(activity),activity.outcome==="success"?"":"bad"],[requestSummary],[models(activity),"dim"],[duration(activity.duration_ms),"dim"],[usage(activity),"tokens"]])summary.appendChild(cell(value[0],value[1]));details.appendChild(summary);const requests=document.createElement("div");requests.className="requests";for(const op of activity.operations)requests.appendChild(row([[new Date(op.ended_at).toLocaleTimeString(),"dim"],["request","request-label"],[op.provider+" · "+op.operation],[op.model,"dim"],[duration(op.duration_ms),"dim"],[usage(op),"tokens"]],"request"));details.appendChild(requests);historyRoot.appendChild(details)}
}
async function refreshRunning(){if(runningFetch)return;runningFetch=true;try{const response=await fetch("/api/running",{cache:"no-store"});if(!response.ok)throw new Error("running");running=await response.json();renderRunning();renderTimeline()}catch(error){runningCount.textContent="active status unavailable"}finally{runningFetch=false}}
async function refreshTimeline(){if(timelineFetch)return;timelineFetch=true;try{const since=new Date(Date.now()-timelineWindow-GAP).toISOString(),response=await fetch("/api/activities?since="+encodeURIComponent(since)+"&details=false",{cache:"no-store"});if(!response.ok)throw new Error("timeline");timelineActivities=await response.json();renderTimeline()}finally{timelineFetch=false}}
function scheduleTimelineRefresh(){clearTimeout(timelineTimer);timelineTimer=setTimeout(refreshTimeline,200)}
function connect(){const stream=new EventSource("/api/operations/stream");stream.addEventListener("ready",()=>{statusEl.textContent="live";statusEl.className="status ok"});stream.onmessage=event=>merge(JSON.parse(event.data));stream.onerror=()=>{statusEl.textContent="disconnected";statusEl.className="status bad"}}
for(const button of document.querySelectorAll("[data-window]"))button.addEventListener("click",()=>{timelineWindow=Number(button.dataset.window);for(const current of document.querySelectorAll("[data-window]"))current.classList.toggle("active",current===button);refreshTimeline()});
fetch("/api/activities?limit=1000").then(response=>response.json()).then(items=>{activities=items.map(summarize);for(const activity of activities)for(const op of activity.operations)seen.add(op.id);activities.sort((a,b)=>Date.parse(b.ended_at)-Date.parse(a.ended_at));renderHistory()}).catch(()=>{statusEl.textContent="load failed";statusEl.className="status bad"}).finally(connect);
refreshRunning();refreshTimeline();setInterval(refreshRunning,1000);
</script></body></html>`
