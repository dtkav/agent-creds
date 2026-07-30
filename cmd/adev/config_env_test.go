package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeProjectConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent-creds.toml"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadProjectConfigStaticEnv(t *testing.T) {
	dir := writeProjectConfig(t, `
[env]
SERVICE_URL = "http://service.internal/graphql"
`)

	cfg, err := LoadProjectConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{"SERVICE_URL": "http://service.internal/graphql"}
	if !reflect.DeepEqual(cfg.StaticEnv, want) {
		t.Fatalf("StaticEnv = %#v, want %#v", cfg.StaticEnv, want)
	}
	if len(cfg.Env) != 0 {
		t.Fatalf("Env = %#v, want empty", cfg.Env)
	}
}

func TestLoadProjectConfigEnvEntries(t *testing.T) {
	dir := writeProjectConfig(t, `
[[env]]
name = "SERVICE_URL"
value = "http://service.internal/graphql"

[[env]]
name = "SERVICE_TOKEN"
value = "from-file:.support-token"
`)

	cfg, err := LoadProjectConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvConfig{
		{Name: "SERVICE_URL", Value: "http://service.internal/graphql"},
		{Name: "SERVICE_TOKEN", Value: "from-file:.support-token"},
	}
	if !reflect.DeepEqual(cfg.Env, want) {
		t.Fatalf("Env = %#v, want %#v", cfg.Env, want)
	}
	if len(cfg.StaticEnv) != 0 {
		t.Fatalf("StaticEnv = %#v, want empty", cfg.StaticEnv)
	}
}
