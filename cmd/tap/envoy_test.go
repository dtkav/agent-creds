package main

import (
	"context"
	"testing"
)

func TestSourceManagerReconcileAddsAndRemovesSources(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewSourceManager(nil)
	manager.Run(ctx, Config{Sources: []Source{
		{ID: "alpha", AdminURL: "unix:///missing/alpha.sock", ConfigID: "agent_creds_global_tap"},
		{ID: "beta", AdminURL: "unix:///missing/beta.sock", ConfigID: "agent_creds_global_tap"},
	}})
	status := manager.Status()
	if len(status) != 2 {
		t.Fatalf("initial source count = %d", len(status))
	}

	manager.Reconcile(ctx, Config{Sources: []Source{
		{ID: "beta", AdminURL: "unix:///missing/beta.sock", ConfigID: "agent_creds_global_tap"},
		{ID: "gamma", AdminURL: "unix:///missing/gamma.sock", ConfigID: "agent_creds_global_tap"},
	}})
	status = manager.Status()
	if len(status) != 2 {
		t.Fatalf("reconciled source count = %d", len(status))
	}
	if _, ok := status["alpha"]; ok {
		t.Fatal("removed source alpha is still registered")
	}
	if _, ok := status["beta"]; !ok {
		t.Fatal("unchanged source beta was removed")
	}
	if _, ok := status["gamma"]; !ok {
		t.Fatal("new source gamma was not registered")
	}
}
