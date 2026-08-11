package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubCredentialHelperReadsRefreshedSandboxEnv(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "sandbox.env")
	if err := os.WriteFile(envFile, []byte(
		"GH_TOKEN=fresh-api\nGIT_GITHUB_TOKEN=fresh-git\n"), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join("..", "..", "plugins",
		"git-credential-agent-creds-github.sh")
	cmd := exec.Command("bash", helper, "get")
	cmd.Stdin = strings.NewReader("host=github.com\n\n")
	cmd.Env = append(os.Environ(),
		"AGENT_CREDS_ENV_FILE="+envFile,
		"GIT_GITHUB_TOKEN=stale-git")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("credential helper: %v\n%s", err, out)
	}
	if got := string(out); !strings.Contains(got, "password=fresh-git") ||
		strings.Contains(got, "stale-git") {
		t.Fatalf("credential helper output = %q", got)
	}
}

func TestGitHubCLIWrapperReadsRefreshedSandboxEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "sandbox.env")
	if err := os.WriteFile(envFile, []byte(
		"GH_TOKEN=fresh-api\nGIT_GITHUB_TOKEN=fresh-git\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeGH := filepath.Join(dir, "real-gh")
	if err := os.WriteFile(fakeGH, []byte(
		"#!/bin/sh\nprintf '%s\\n' \"$GH_TOKEN\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(
		"..", "..", "plugins", "gh-agent-creds.sh"))
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "gh")
	if err := os.WriteFile(wrapper, []byte(strings.ReplaceAll(
		string(source), "@gh@", fakeGH)), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", wrapper)
	cmd.Env = append(os.Environ(),
		"AGENT_CREDS_ENV_FILE="+envFile,
		"GH_TOKEN=stale-api")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gh wrapper: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "fresh-api" {
		t.Fatalf("gh wrapper token = %q, want refreshed token", got)
	}
}
