package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type statusRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn statusRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func statusClient(fn statusRoundTripFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func TestCheckVaultHTTPRequiresHealthyEndpoint(t *testing.T) {
	requestedPath := ""
	client := statusClient(func(request *http.Request) (*http.Response, error) {
		requestedPath = request.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})

	if !checkVaultHTTPWithClient(client, "http://vault.example") {
		t.Fatal("checkVaultHTTP reported a healthy Vault as down")
	}
	if requestedPath != "/health" {
		t.Fatalf("requested path = %q, want /health", requestedPath)
	}
}

func TestCheckVaultHTTPRejectsUnhealthyResponse(t *testing.T) {
	client := statusClient(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("not ready")),
		}, nil
	})

	if checkVaultHTTPWithClient(client, "http://vault.example") {
		t.Fatal("checkVaultHTTP accepted an unhealthy response")
	}
}
