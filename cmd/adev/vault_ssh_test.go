package main

import "testing"

func TestShellQuote(t *testing.T) {
	for input, want := range map[string]string{
		"mint":              "'mint'",
		"records-context":   "'records-context'",
		"value with spaces": "'value with spaces'",
		"value'; command":   `'value'"'"'; command'`,
	} {
		if got := shellQuote(input); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}
