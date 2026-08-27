package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedRuntimeArtifactsAreInstanceScoped(t *testing.T) {
	root := t.TempDir()
	certs := filepath.Join(root, "generated", "certs")
	if err := os.MkdirAll(certs, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.key", "ca.crt"} {
		if err := os.WriteFile(filepath.Join(certs, name), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	serviceDir := filepath.Join(root, "generated", "instances", "service")
	clientDir := filepath.Join(root, "generated", "instances", "client")
	serviceCfg := ProjectConfig{
		Upstream: map[string]UpstreamConfig{"telemetry.internal": {}},
	}
	clientCfg := ProjectConfig{
		Upstream: map[string]UpstreamConfig{"service.internal": {}},
	}

	service, err := NewGenerator(root, serviceDir, serviceCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Generate(); err != nil {
		t.Fatal(err)
	}
	client, err := NewGenerator(root, clientDir, clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Generate(); err != nil {
		t.Fatal(err)
	}

	serviceDomains, err := os.ReadFile(filepath.Join(serviceDir, "domains.json"))
	if err != nil {
		t.Fatal(err)
	}
	clientDomains, err := os.ReadFile(filepath.Join(clientDir, "domains.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(serviceDomains), "telemetry.internal") ||
		strings.Contains(string(serviceDomains), "service.internal") {
		t.Fatalf("service domains were overwritten: %s", serviceDomains)
	}
	if !strings.Contains(string(clientDomains), "service.internal") ||
		strings.Contains(string(clientDomains), "telemetry.internal") {
		t.Fatalf("client domains were overwritten: %s", clientDomains)
	}

	if err := generateSandboxEnv(serviceDir, map[string]string{"SERVICE_TOKEN": "one"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := generateSandboxEnv(clientDir, map[string]string{"CLIENT_TOKEN": "two"}, nil); err != nil {
		t.Fatal(err)
	}
	serviceEnv, err := os.ReadFile(filepath.Join(serviceDir, "sandbox.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serviceEnv), "CLIENT_TOKEN") {
		t.Fatalf("client environment leaked into service environment: %s", serviceEnv)
	}
}
