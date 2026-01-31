package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/superfly/macaroon"
)

// Color palette (static to avoid terminal queries)
var (
	subtle    = lipgloss.Color("#888")
	highlight = lipgloss.Color("#7D56F4")
	green     = lipgloss.Color("#02BF87")
	yellow    = lipgloss.Color("#FFCC00")
	red       = lipgloss.Color("#FF6B8A")
	cyan      = lipgloss.Color("#00D7FF")
)

// Styles
var (
	// Header box
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(highlight).
			Padding(0, 2)

	// Section title
	sectionStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Bold(true).
			MarginTop(1).
			MarginBottom(0)

	// Host styles
	hostOkStyle   = lipgloss.NewStyle().Foreground(green).Bold(true)
	hostWarnStyle = lipgloss.NewStyle().Foreground(yellow).Bold(true)

	// Status indicators
	okStyle   = lipgloss.NewStyle().Foreground(green)
	warnStyle = lipgloss.NewStyle().Foreground(yellow)
	errStyle  = lipgloss.NewStyle().Foreground(red)
	dimStyle  = lipgloss.NewStyle().Foreground(subtle)

	// Token row
	tokenNameStyle = lipgloss.NewStyle().Foreground(highlight)
	separatorStyle = lipgloss.NewStyle().Foreground(subtle)

	// Indentation
	indent = lipgloss.NewStyle().PaddingLeft(2)
)

const TokenPrefix = "sk_"

const (
	CavAPIHost   macaroon.CaveatType = 1<<32 + 1
	CavAPIMethod macaroon.CaveatType = 1<<32 + 2
	CavAPIPath   macaroon.CaveatType = 1<<32 + 3
)

func init() {
	// Disable all terminal queries to prevent escape sequence leakage
	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(true)

	macaroon.RegisterCaveatType(&HostCaveat{})
	macaroon.RegisterCaveatType(&MethodCaveat{})
	macaroon.RegisterCaveatType(&PathCaveat{})
}

type HostCaveat struct{ Hosts []string `json:"hosts"` }

func (c *HostCaveat) CaveatType() macaroon.CaveatType { return CavAPIHost }
func (c *HostCaveat) Name() string                    { return "APIHost" }
func (c *HostCaveat) Prohibits(macaroon.Access) error { return nil }

type MethodCaveat struct{ Methods []string `json:"methods"` }

func (c *MethodCaveat) CaveatType() macaroon.CaveatType { return CavAPIMethod }
func (c *MethodCaveat) Name() string                    { return "APIMethod" }
func (c *MethodCaveat) Prohibits(macaroon.Access) error { return nil }

type PathCaveat struct{ Patterns []string `json:"patterns"` }

func (c *PathCaveat) CaveatType() macaroon.CaveatType { return CavAPIPath }
func (c *PathCaveat) Name() string                    { return "APIPath" }
func (c *PathCaveat) Prohibits(macaroon.Access) error { return nil }

type VaultConfig struct {
	Host string `toml:"host"`
}

type UpstreamConfig struct {
	Akey string `toml:"akey"`
}

type ProjectConfig struct {
	Vault    VaultConfig                `toml:"vault"`
	Upstream map[string]UpstreamConfig  `toml:"upstream"`
}

type TokenInfo struct {
	Source, Error         string
	Hosts, Methods, Paths []string
	ValidUntil            time.Time
	Attestation           bool
}

func (t *TokenInfo) matchesHost(host string) bool {
	if len(t.Hosts) == 0 {
		return true
	}
	for _, h := range t.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

func decodeToken(token string) (*macaroon.Macaroon, error) {
	if len(token) < len(TokenPrefix) {
		return nil, fmt.Errorf("token too short")
	}
	if token[:len(TokenPrefix)] != TokenPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token[len(TokenPrefix):])
	if err != nil {
		return nil, err
	}
	return macaroon.Decode(decoded)
}

func extractTokenInfo(source, tokenStr string) TokenInfo {
	tokenStr = strings.TrimSpace(tokenStr)
	parts := strings.Split(tokenStr, ",")
	mainToken := strings.TrimSpace(parts[0])
	info := TokenInfo{Source: source}

	m, err := decodeToken(mainToken)
	if err != nil {
		info.Error = err.Error()
		return info
	}

	for _, c := range m.UnsafeCaveats.Caveats {
		switch cv := c.(type) {
		case *macaroon.ValidityWindow:
			info.ValidUntil = time.Unix(cv.NotAfter, 0)
		case *HostCaveat:
			info.Hosts = cv.Hosts
		case *MethodCaveat:
			info.Methods = cv.Methods
		case *PathCaveat:
			info.Paths = cv.Patterns
		case *macaroon.Caveat3P:
			info.Attestation = true
		}
	}
	return info
}

func findAkeyFiles() []string {
	configDir := filepath.Join(os.Getenv("HOME"), ".config", "agent-creds")
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".akey") {
			files = append(files, filepath.Join(configDir, e.Name()))
		}
	}
	return files
}

func formatDuration(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	days := int(d.Hours() / 24)
	if days < 7 {
		return fmt.Sprintf("%dd", days)
	}
	if days < 365 {
		return fmt.Sprintf("%dw", days/7)
	}
	return fmt.Sprintf("%dy", days/365)
}

func renderTokenLine(t TokenInfo) string {
	source := strings.TrimSuffix(t.Source, ".akey")
	sep := separatorStyle.Render("│")

	if t.Error != "" {
		return fmt.Sprintf("    %s %s", tokenNameStyle.Render(source), errStyle.Render("✗ "+t.Error))
	}

	var parts []string

	// Validity with icon
	now := time.Now()
	if !t.ValidUntil.IsZero() {
		remaining := t.ValidUntil.Sub(now)
		if remaining < 0 {
			parts = append(parts, errStyle.Render("✗ expired"))
		} else if remaining < time.Hour {
			parts = append(parts, warnStyle.Render(fmt.Sprintf("⏳ %s", formatDuration(remaining))))
		} else {
			parts = append(parts, okStyle.Render(fmt.Sprintf("✓ %s", formatDuration(remaining))))
		}
	}

	// Methods
	if len(t.Methods) > 0 {
		parts = append(parts, strings.Join(t.Methods, ","))
	}

	// Paths
	if len(t.Paths) > 0 {
		pathStr := strings.Join(t.Paths, ", ")
		if len(pathStr) > 30 {
			pathStr = pathStr[:27] + "..."
		}
		parts = append(parts, dimStyle.Render(pathStr))
	}

	// Attestation
	if t.Attestation {
		parts = append(parts, warnStyle.Render("🔐"))
	}

	return fmt.Sprintf("    %s %s", tokenNameStyle.Render(source), strings.Join(parts, " "+sep+" "))
}

func checkBrowserForward() string {
	sock := "/run/browser-forward.sock"
	if _, err := os.Stat(sock); err != nil {
		return ""
	}
	// Try connecting to verify it's alive
	conn, err := net.DialTimeout("unix", sock, 500*time.Millisecond)
	if err != nil {
		return "dead"
	}
	conn.Close()
	return "ok"
}

type CDPTarget struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

type CDPInfo struct {
	Status  string // "", "no-remote", or browser version
	Targets []CDPTarget
}

func checkCDP() CDPInfo {
	sock := "/run/cdp-forward.sock"
	if _, err := os.Stat(sock); err != nil {
		// Also check if cdp-proxy is listening on 9222 directly
		conn, err := net.DialTimeout("tcp", "127.0.0.1:9222", 500*time.Millisecond)
		if err != nil {
			return CDPInfo{}
		}
		conn.Close()
	}

	client := &http.Client{Timeout: time.Second}

	// Try /json/version via the TCP port (cdp-proxy -> socket -> host Chrome)
	var info CDPInfo
	resp, err := client.Get("http://127.0.0.1:9222/json/version")
	if err != nil {
		info.Status = "no-remote"
		return info
	}
	defer resp.Body.Close()

	var version struct {
		Browser string `json:"Browser"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		info.Status = "connected"
	} else if version.Browser != "" {
		info.Status = version.Browser
	} else {
		info.Status = "connected"
	}

	// Fetch target list
	resp2, err := client.Get("http://127.0.0.1:9222/json/list")
	if err != nil {
		return info
	}
	defer resp2.Body.Close()
	json.NewDecoder(resp2.Body).Decode(&info.Targets)

	return info
}

func main() {
	var cfg ProjectConfig
	if _, err := toml.DecodeFile("/etc/aenv/agent-creds.toml", &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading agent-creds.toml: %v\n", err)
		os.Exit(1)
	}

	// Sort upstream hosts
	var hosts []string
	for host := range cfg.Upstream {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	var allTokens []TokenInfo
	for _, path := range findAkeyFiles() {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		allTokens = append(allTokens, extractTokenInfo(filepath.Base(path), string(content)))
	}

	// Separate into credentialed and passthrough
	var credHosts, passthroughHosts []string
	for _, host := range hosts {
		if cfg.Upstream[host].Akey != "" {
			credHosts = append(credHosts, host)
		} else {
			passthroughHosts = append(passthroughHosts, host)
		}
	}

	// Build left column: Allowlist (all accessible hosts)
	var leftLines []string
	leftLines = append(leftLines, sectionStyle.Render("Allowlist"))
	leftLines = append(leftLines, "")
	for _, host := range hosts {
		leftLines = append(leftLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render(host)))
	}

	// Build right column: Credentials
	var rightLines []string
	rightLines = append(rightLines, sectionStyle.Render("Credentials"))
	rightLines = append(rightLines, "")

	for _, host := range credHosts {
		var matching []TokenInfo
		for _, t := range allTokens {
			if t.matchesHost(host) {
				matching = append(matching, t)
			}
		}

		if len(matching) == 0 {
			rightLines = append(rightLines, fmt.Sprintf("  %s %s %s", warnStyle.Render("○"), hostWarnStyle.Render(host), dimStyle.Render("— no token")))
			continue
		}

		rightLines = append(rightLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), hostOkStyle.Render(host)))
		for _, t := range matching {
			rightLines = append(rightLines, renderTokenLine(t))
		}
	}

	// Build third column: Host Access
	var thirdLines []string
	thirdLines = append(thirdLines, sectionStyle.Render("Host Access"))
	thirdLines = append(thirdLines, "")

	// Browser forward
	switch checkBrowserForward() {
	case "ok":
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render("browser forward")))
	case "dead":
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", errStyle.Render("◉"), dimStyle.Render("browser forward (dead)")))
	default:
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", dimStyle.Render("○"), dimStyle.Render("browser forward")))
	}

	// CDP
	cdp := checkCDP()
	switch cdp.Status {
	case "":
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", dimStyle.Render("○"), dimStyle.Render("cdp")))
	case "no-remote":
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", warnStyle.Render("◉"), dimStyle.Render("cdp (no remote browser)")))
	default:
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render("cdp → "+cdp.Status)))
		for _, t := range cdp.Targets {
			title := t.Title
			if len(title) > 35 {
				title = title[:32] + "..."
			}
			if title == "" {
				title = t.URL
				if len(title) > 35 {
					title = title[:32] + "..."
				}
			}
			thirdLines = append(thirdLines, fmt.Sprintf("    %s %s", dimStyle.Render("·"), dimStyle.Render(title)))
		}
	}

	// Vault info
	vaultText := "local"
	if cfg.Vault.Host != "" {
		vaultText = cfg.Vault.Host
	}
	vaultBox := headerStyle.Render("🏛 vault " + vaultText)

	// Column styles
	leftCol := lipgloss.NewStyle().
		Width(30).
		MarginRight(4)

	rightCol := lipgloss.NewStyle().
		Width(50).
		MarginRight(4)

	thirdCol := lipgloss.NewStyle().
		Width(35)

	// Render
	leftContent := leftCol.Render(strings.Join(leftLines, "\n"))
	rightContent := rightCol.Render(strings.Join(rightLines, "\n"))
	thirdContent := thirdCol.Render(strings.Join(thirdLines, "\n"))

	fmt.Println()
	fmt.Println(headerStyle.Render("🔑 agent-creds") + "  " + vaultBox)
	fmt.Println()
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Top, leftContent, rightContent, thirdContent))
	fmt.Println()
}
