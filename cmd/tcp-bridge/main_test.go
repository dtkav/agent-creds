package main

import "testing"

func TestCallbackListenAddr(t *testing.T) {
	t.Setenv("CALLBACK_LISTEN_HOST", "10.0.2.100")
	if got := callbackListenAddr("43123"); got != "10.0.2.100:43123" {
		t.Fatalf("callbackListenAddr() = %q", got)
	}
}
