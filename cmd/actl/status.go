package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type containerStatus struct {
	Name   string
	Status string // "running", "exited", etc. or "" if not found
}

func checkContainer(name string) containerStatus {
	out, err := exec.Command("docker", "inspect", "--format", "{{.State.Status}}", name).Output()
	if err != nil {
		return containerStatus{Name: name}
	}
	return containerStatus{Name: name, Status: strings.TrimSpace(string(out))}
}

func checkContainers(slug string) []containerStatus {
	names := []string{
		"adev-" + slug + "-net",
		"adev-" + slug + "-envoy",
		"adev-" + slug + "-obsidian",
	}

	results := make([]containerStatus, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			results[i] = checkContainer(name)
		}(i, name)
	}
	wg.Wait()
	return results
}

type identityInfo struct {
	Fingerprint string
	Status      string
	Connected   bool
	Error       string
}

func checkIdentity(sshAddr string) identityInfo {
	if sshAddr == "" {
		return identityInfo{Error: "no vault configured"}
	}

	// Split host:port
	host := sshAddr
	port := "22"
	if idx := strings.LastIndex(sshAddr, ":"); idx != -1 {
		host = sshAddr[:idx]
		port = sshAddr[idx+1:]
	}

	out, err := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5",
		"-p", port,
		host,
		"whoami",
	).CombinedOutput()
	if err != nil {
		return identityInfo{Error: "not connected"}
	}

	info := identityInfo{Connected: true}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Fingerprint:") {
			info.Fingerprint = strings.TrimSpace(strings.TrimPrefix(line, "Fingerprint:"))
		}
		if strings.HasPrefix(line, "Status:") {
			info.Status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		}
	}
	return info
}

func checkVaultHTTP(url string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func runStatus(cfg ProjectConfig) {
	slug := Slug(cfg.Sandbox.Name)
	if slug == "default" && cfg.Sandbox.Name == "" {
		slug = "default"
	}

	projectName := cfg.Sandbox.Name
	if projectName == "" {
		projectName = "default"
	}

	// Start parallel checks
	var wg sync.WaitGroup
	var containers []containerStatus
	var identity identityInfo
	var vaultUp bool

	wg.Add(1)
	go func() {
		defer wg.Done()
		containers = checkContainers(slug)
	}()

	vaultAddr := cfg.Vault.HTTPAddr()
	wg.Add(1)
	go func() {
		defer wg.Done()
		vaultUp = checkVaultHTTP(vaultAddr)
	}()

	sshAddr := cfg.Vault.SSHAddr()
	if sshAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			identity = checkIdentity(sshAddr)
		}()
	}

	wg.Wait()

	// === Render ===

	// Header
	vaultLine := dimStyle.Render("local")
	if cfg.Vault.Host != "" {
		vaultLine = cfg.Vault.Host
	}
	header := headerStyle.Render("actl · " + projectName)
	fmt.Println()
	fmt.Println(header)
	fmt.Println(indent.Render(dimStyle.Render("vault: ") + vaultLine))

	// Containers section
	fmt.Println()
	fmt.Println(indent.Render(sectionStyle.Render("Containers")))
	for _, c := range containers {
		shortName := c.Name
		var line string
		if c.Status == "running" {
			line = fmt.Sprintf("  %s  %-30s %s", okStyle.Render("●"), shortName, okStyle.Render("running"))
		} else if c.Status != "" {
			line = fmt.Sprintf("  %s  %-30s %s", warnStyle.Render("●"), shortName, warnStyle.Render(c.Status))
		} else {
			line = fmt.Sprintf("  %s  %-30s %s", dimStyle.Render("○"), shortName, dimStyle.Render("not found"))
		}
		fmt.Println(indent.Render(line))
	}

	// Connectivity section
	fmt.Println()
	fmt.Println(indent.Render(sectionStyle.Render("Connectivity")))

	// Vault HTTP
	if vaultUp {
		fmt.Println(indent.Render(fmt.Sprintf("  %s  %-30s %s", okStyle.Render("●"), "vault "+dimStyle.Render(vaultAddr), okStyle.Render("✓ up"))))
	} else {
		fmt.Println(indent.Render(fmt.Sprintf("  %s  %-30s %s", warnStyle.Render("○"), "vault "+dimStyle.Render(vaultAddr), warnStyle.Render("✗ down"))))
	}

	// SSH connectivity
	if sshAddr != "" {
		if identity.Connected {
			fmt.Println(indent.Render(fmt.Sprintf("  %s  %-30s %s", okStyle.Render("●"), "ssh "+dimStyle.Render(sshAddr), okStyle.Render("✓ connected"))))
		} else {
			fmt.Println(indent.Render(fmt.Sprintf("  %s  %-30s %s", warnStyle.Render("○"), "ssh "+dimStyle.Render(sshAddr), warnStyle.Render("✗ "+identity.Error))))
		}
	}

	// Identity section (remote vault only)
	if sshAddr != "" {
		fmt.Println()
		fmt.Println(indent.Render(sectionStyle.Render("Identity")))
		if identity.Connected {
			fp := identity.Fingerprint
			if fp == "" {
				fp = dimStyle.Render("unknown")
			}
			st := identity.Status
			if st == "" {
				st = dimStyle.Render("unknown")
			}
			fmt.Println(indent.Render(fmt.Sprintf("  %-15s %s", dimStyle.Render("fingerprint"), fp)))
			fmt.Println(indent.Render(fmt.Sprintf("  %-15s %s", dimStyle.Render("status"), st)))
		} else {
			fmt.Println(indent.Render(fmt.Sprintf("  %s", warnStyle.Render("not connected"))))
		}
	}

	fmt.Println()
}

// lipgloss styles (shared palette from aenv)
var (
	subtle    = lipgloss.Color("#888")
	highlight = lipgloss.Color("#7D56F4")
	green     = lipgloss.Color("#02BF87")
	yellow    = lipgloss.Color("#FFCC00")

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D7FF")).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(highlight).
			Padding(0, 2)

	sectionStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Bold(true)

	okStyle   = lipgloss.NewStyle().Foreground(green)
	warnStyle = lipgloss.NewStyle().Foreground(yellow)
	dimStyle  = lipgloss.NewStyle().Foreground(subtle)

	indent = lipgloss.NewStyle().PaddingLeft(2)
)
