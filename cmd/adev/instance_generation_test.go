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
	supportDir := filepath.Join(root, "generated", "instances", "support")
	serviceCfg := ProjectConfig{
		Upstream: map[string]UpstreamConfig{"telemetry.internal": {}},
	}
	supportCfg := ProjectConfig{
		Upstream: map[string]UpstreamConfig{"service.internal": {Mode: "identity"}},
	}

	service, err := NewGenerator(root, serviceDir, serviceCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Generate(); err != nil {
		t.Fatal(err)
	}
	support, err := NewGenerator(root, supportDir, supportCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := support.Generate(); err != nil {
		t.Fatal(err)
	}

	serviceDomains, err := os.ReadFile(filepath.Join(serviceDir, "domains.json"))
	if err != nil {
		t.Fatal(err)
	}
	supportDomains, err := os.ReadFile(filepath.Join(supportDir, "domains.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(serviceDomains), "telemetry.internal") ||
		strings.Contains(string(serviceDomains), "service.internal") {
		t.Fatalf("service domains were overwritten: %s", serviceDomains)
	}
	if !strings.Contains(string(supportDomains), "service.internal") ||
		strings.Contains(string(supportDomains), "telemetry.internal") {
		t.Fatalf("support domains were overwritten: %s", supportDomains)
	}

	if err := generateSandboxEnv(serviceDir, map[string]string{"SERVICE_TOKEN": "one"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := generateSandboxEnv(supportDir, map[string]string{"SUPPORT_TOKEN": "two"}, nil); err != nil {
		t.Fatal(err)
	}
	serviceEnv, err := os.ReadFile(filepath.Join(serviceDir, "sandbox.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serviceEnv), "SUPPORT_TOKEN") {
		t.Fatalf("support environment leaked into service environment: %s", serviceEnv)
	}
}
