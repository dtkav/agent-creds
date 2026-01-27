package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

type Domain struct {
	Host     string `json:"host"`
	AuthType string `json:"auth_type"`
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

func main() {
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

	var names []string
	for name := range domains {
		names = append(names, name)
	}
	sort.Strings(names)

	var allTokens []TokenInfo
	for _, path := range findAkeyFiles() {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		allTokens = append(allTokens, extractTokenInfo(filepath.Base(path), string(content)))
	}

	// Separate domains into token-configured and passthrough
	var tokenDomains, passthroughDomains []string
	for _, name := range names {
		d := domains[name]
		authType := d.AuthType
		if authType == "" {
			authType = "static"
		}
		if authType == "passthrough" {
			passthroughDomains = append(passthroughDomains, name)
		} else {
			tokenDomains = append(tokenDomains, name)
		}
	}

	// Build left column: Allowlist (all accessible hosts)
	var leftLines []string
	leftLines = append(leftLines, sectionStyle.Render("Allowlist"))
	leftLines = append(leftLines, "")

	// Include all domains in allowlist
	for _, name := range names {
		d := domains[name]
		leftLines = append(leftLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render(d.Host)))
	}

	// Build right column: Credentials
	var rightLines []string
	rightLines = append(rightLines, sectionStyle.Render("Credentials"))
	rightLines = append(rightLines, "")

	for _, name := range tokenDomains {
		d := domains[name]

		var matching []TokenInfo
		for _, t := range allTokens {
			if t.matchesHost(d.Host) {
				matching = append(matching, t)
			}
		}

		if len(matching) == 0 {
			rightLines = append(rightLines, fmt.Sprintf("  %s %s %s", warnStyle.Render("○"), hostWarnStyle.Render(d.Host), dimStyle.Render("— no token")))
			continue
		}

		rightLines = append(rightLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), hostOkStyle.Render(d.Host)))
		for _, t := range matching {
			rightLines = append(rightLines, renderTokenLine(t))
		}
	}

	// Column styles
	leftCol := lipgloss.NewStyle().
		Width(30).
		MarginRight(4)

	rightCol := lipgloss.NewStyle().
		Width(50)

	// Render columns
	leftContent := leftCol.Render(strings.Join(leftLines, "\n"))
	rightContent := rightCol.Render(strings.Join(rightLines, "\n"))

	// Header and columns
	fmt.Println()
	fmt.Println(headerStyle.Render("🔑 agent-creds"))
	fmt.Println()
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Top, leftContent, rightContent))
	fmt.Println()
}
