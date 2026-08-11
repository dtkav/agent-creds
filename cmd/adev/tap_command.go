package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func runTap(args []string) {
	if len(args) == 0 {
		runTapStatus()
		return
	}
	switch args[0] {
	case "enable":
		runTapEnable(args[1:])
	case "disable":
		runTapDisable(args[1:])
	case "status":
		runTapStatus()
	default:
		fmt.Fprintln(os.Stderr, "Usage: adev tap [enable [--ui-port PORT]|disable|status]")
		os.Exit(2)
	}
}

func tapScriptDir() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	return filepath.Dir(filepath.Dir(executable)), nil
}

func runTapEnable(args []string) {
	config, err := loadGlobalTapConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	flags := flag.NewFlagSet("adev tap enable", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	uiPort := flags.Int("ui-port", config.Port(), "host-loopback UI port")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Usage: adev tap enable [--ui-port PORT]")
		os.Exit(2)
	}
	config.Enabled = true
	config.UIPort = *uiPort
	if err := saveGlobalTapConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	scriptDir, err := tapScriptDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding installation: %v\n", err)
		os.Exit(1)
	}
	spinner := NewSpinner()
	spinner.Start()
	if err := startGlobalTapService(scriptDir, config, spinner, true); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error enabling global traffic tap: %v\n", err)
		os.Exit(1)
	}
	spinner.Stop()
	fmt.Printf("Global traffic tap enabled: http://127.0.0.1:%d\n", config.Port())
	fmt.Println("Restart running instances so their Envoy tap filters are active.")
}

func runTapDisable(args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "Usage: adev tap disable")
		os.Exit(2)
	}
	config, err := loadGlobalTapConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	config.Enabled = false
	if err := saveGlobalTapConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	_ = run("docker", "rm", "-f", tapContainer)
	_ = run("docker", "network", "rm", tapNetwork)
	fmt.Println("Global traffic tap disabled. Existing normalized metrics were retained.")
}

func runTapStatus() {
	config, err := loadGlobalTapConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	scriptDir, err := tapScriptDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding installation: %v\n", err)
		os.Exit(1)
	}
	state := "disabled"
	if config.Enabled {
		state = "enabled, stopped"
		if globalTapRunning() {
			state = "enabled, running"
		}
	}
	sources := 0
	if entries, err := os.ReadDir(tapSourcesDir(scriptDir)); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				sources++
			}
		}
	}
	fmt.Printf("Global traffic tap: %s\n", state)
	fmt.Printf("UI: http://127.0.0.1:%d\n", config.Port())
	fmt.Printf("Registered sources: %d\n", sources)
	fmt.Printf("Data: %s\n", filepath.Join(tapDataDir(scriptDir), "operations.db"))
}
