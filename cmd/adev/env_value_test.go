package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEnvValueFromProjectDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".session-token"), []byte("acm_test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := resolveEnvValueFrom("from-file:.session-token", dir); got != "acm_test" {
		t.Fatalf("resolved value = %q", got)
	}
}
