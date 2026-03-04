package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func init() {
	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(true)
}

func usage() {
	fmt.Println("Usage: actl [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  (none)    Launch interactive TUI (default)")
	fmt.Println("  status    Show container, connectivity, and identity status")
	fmt.Println("  ssh       Connect to authz SSH server (pass args through)")
	fmt.Println("  secrets   Manage SOPS-encrypted vault secrets")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  actl                  # interactive TUI")
	fmt.Println("  actl status")
	fmt.Println("  actl ssh whoami")
	fmt.Println("  actl ssh mint api.stripe.com")
	fmt.Println("  actl secrets init")
	fmt.Println("  actl secrets set STRIPE_API_KEY=sk_test_xxx")
}

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	cfg, err := LoadProjectConfig(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	switch cmd {
	case "":
		// Default: launch interactive TUI
		runTUI()
	case "status":
		runStatus(cfg)
	case "ssh":
		runSSH(cfg, os.Args[2:])
	case "secrets":
		runSecrets(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		fmt.Fprintln(os.Stderr)
		usage()
		os.Exit(1)
	}
}
