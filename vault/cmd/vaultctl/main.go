package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxConfigBytes = 4 << 20

func main() {
	if len(os.Args) != 2 || os.Args[1] != "reload" {
		fmt.Fprintln(os.Stderr, "Usage: vaultctl reload < vault.yaml")
		os.Exit(2)
	}
	config, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
		os.Exit(1)
	}
	if len(config) > maxConfigBytes {
		fmt.Fprintln(os.Stderr, "Error: vault config exceeds 4 MiB")
		os.Exit(1)
	}

	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("VAULT_CONTROL_URL")), "/")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8034"
	}
	response, err := reloadConfig(http.DefaultClient, baseURL, config, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(response)
}

func reloadConfig(client *http.Client, baseURL string, config []byte, retryFor time.Duration) ([]byte, error) {
	deadline := time.Now().Add(retryFor)
	for {
		request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/config/reload", bytes.NewReader(config))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/yaml")
		response, err := client.Do(request)
		if err != nil {
			if time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("contacting Vault control service: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading Vault control response: %w", readErr)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			message := strings.TrimSpace(string(body))
			if message == "" {
				message = response.Status
			}
			return nil, fmt.Errorf("Vault rejected config: %s", message)
		}
		return body, nil
	}
}
