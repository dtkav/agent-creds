package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func runStop(args []string) {
	workDir, _ := os.Getwd()

	// Determine instance name
	var name string
	if len(args) > 0 {
		name = args[0]
	} else {
		// Default to current directory name
		name = filepath.Base(workDir)
	}
	slug := Slug(name)

	// Get scriptDir
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe))

	mgr := NewInstanceManager(scriptDir)
	inst := mgr.GetInstance(slug)

	if inst == nil {
		fmt.Printf("No instance '%s' found\n", slug)
		return
	}

	fmt.Printf("Stopping '%s'...\n", slug)
	if err := mgr.CleanupInstance(inst); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping instance: %v\n", err)
		os.Exit(1)
	}

	// Clean up sockets
	os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-browser.sock", slug)))
	os.Remove(filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-cdp.sock", slug)))

	fmt.Println("Done")
}
