package main

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var osReadFile = os.ReadFile

func main() {
	if len(os.Args) > 1 && os.Args[1] == "mock-provider" {
		runMockProvider()
		return
	}
	configPath := envOr("AGENT_CREDS_TAP_CONFIG", "/etc/agent-creds-tap/sources.json")
	dataDir := envOr("AGENT_CREDS_TAP_DATA_DIR", "/data")
	listen := envOr("AGENT_CREDS_TAP_LISTEN", ":8080")
	config, err := LoadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dataDir, "operations.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	hub := NewHub()
	normalizer := NewNormalizer(store, hub)
	sources := NewSourceManager(normalizer)
	sources.Run(ctx, config)
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
				updated, err := LoadConfig(configPath)
				if err != nil {
					log.Printf("tap source reload failed: %v", err)
					continue
				}
				sources.Reconcile(ctx, updated)
				log.Printf("tap source configuration reloaded with %d source(s)", len(updated.Sources))
			}
		}
	}()
	serverAPI := &Server{
		store: store, sources: sources, normalizer: normalizer, hub: hub,
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				normalizer.Reap()
			}
		}
	}()

	server := &http.Server{
		Addr: listen, Handler: serverAPI.Routes(), ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(
			context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("normalized operation tap listening on %s with %d source(s)", listen, len(config.Sources))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func runMockProvider() {
	listen := envOr("MOCK_PROVIDER_LISTEN", ":8081")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/responses", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxTraceBodyBytes+1))
		w.Header().Set("Content-Type", "text/event-stream")
		writeMockResponse(w, r, "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-lab\",\"usage\":{\"input_tokens\":23,\"output_tokens\":7,\"input_tokens_details\":{\"cached_tokens\":5},\"output_tokens_details\":{\"reasoning_tokens\":2}}}}\n\ndata: [DONE]\n\n")
	})
	mux.HandleFunc("POST /v1/messages", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxTraceBodyBytes+1))
		w.Header().Set("Content-Type", "text/event-stream")
		writeMockResponse(w, r, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-lab\",\"usage\":{\"input_tokens\":11,\"output_tokens\":1,\"cache_creation_input_tokens\":3,\"cache_read_input_tokens\":4}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	})
	mux.HandleFunc("POST /telemetry", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	log.Printf("mock provider listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func writeMockResponse(w http.ResponseWriter, r *http.Request, body string) {
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = io.WriteString(writer, body)
		_ = writer.Close()
		return
	}
	_, _ = io.WriteString(w, body)
}
