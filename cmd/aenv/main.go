package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ANSI colors
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
)

type Domain struct {
	Host   string `json:"host"`
	EnvVar string `json:"env_var"`
}

func main() {
	// Read domains.json
	data, err := os.ReadFile("/etc/aenv/domains.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading domains.json: %v\n", err)
		os.Exit(1)
	}

	var domains map[string]Domain
	if err := json.Unmarshal(data, &domains); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing domains.json: %v\n", err)
		os.Exit(1)
	}

	// Build host list
	var hosts []string
	for _, d := range domains {
		hosts = append(hosts, d.Host)
	}

	// Print MOTD
	fmt.Println()
	fmt.Printf("%s%s agent-creds sandbox %s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s%s\n", Dim, strings.Repeat("─", 40), Reset)
	fmt.Println()
	fmt.Printf("%s%s PROXIED HOSTS%s\n", Bold, Green, Reset)
	for _, host := range hosts {
		fmt.Printf("  %s•%s %s\n", Green, Reset, host)
	}
	fmt.Println()
	fmt.Printf("%sTLS terminated with custom CA. Credentials injected automatically.%s\n", Dim, Reset)
	fmt.Println()
}
