package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

const TokenPrefix = "acm_"

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

type CDPTargetConfig struct {
	Port  int    `toml:"port"`
	Type  string `toml:"type"`
	Title string `toml:"title"`
	URL   string `toml:"url"`
}

type BrowserTargetConfig struct {
	URL string `toml:"url"`
}

type ProjectConfig struct {
	Vault          VaultConfig                `toml:"vault"`
	Upstream       map[string]UpstreamConfig  `toml:"upstream"`
	CDPTargets     []CDPTargetConfig          `toml:"cdp_target"`
	BrowserTargets []BrowserTargetConfig      `toml:"browser_target"`
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
	// tcp-bridge creates this socket
	sock := "/tmp/browser-forward.sock"
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

// matchGlob performs simple glob matching where * matches any characters.
// Pattern must match the entire string (anchored).
func matchGlob(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	re := regexp.QuoteMeta(pattern)
	re = strings.ReplaceAll(re, `\*`, `.*`)
	re = "^" + re + "$"
	matched, _ := regexp.MatchString(re, value)
	return matched
}

// isTargetAllowed checks if a CDP target matches any of the configured patterns.
func isTargetAllowed(target CDPTarget, configs []CDPTargetConfig) bool {
	for _, cfg := range configs {
		typeMatch := matchGlob(cfg.Type, target.Type)
		titleMatch := matchGlob(cfg.Title, target.Title)
		urlMatch := matchGlob(cfg.URL, target.URL)
		if typeMatch && titleMatch && urlMatch {
			return true
		}
	}
	return false
}

type CDPInfo struct {
	Status  string // "", "no-remote", or browser version
	Port    int
	Targets []CDPTarget
}

func checkCDP() CDPInfo {
	port := 9222 // always connect to the proxy, which merges all upstreams

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// Check if cdp-proxy is listening (tcp-bridge creates /tmp/cdp-*.sock, cdp-proxy listens on TCP)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return CDPInfo{}
	}
	conn.Close()

	client := &http.Client{Timeout: time.Second}

	// Try /json/version via the TCP port (cdp-proxy -> socket -> host Chrome)
	info := CDPInfo{Port: port}
	resp, err := client.Get(fmt.Sprintf("http://%s/json/version", addr))
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
	resp2, err := client.Get(fmt.Sprintf("http://%s/json/list", addr))
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
	sort.Slice(hosts, func(i, j int) bool {
		return reverseDomain(hosts[i]) < reverseDomain(hosts[j])
	})

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

	// Build left column: Allowlist (grouped by base domain)
	var leftLines []string
	leftLines = append(leftLines, sectionStyle.Render("Allowlist"))
	leftLines = append(leftLines, "")
	for _, group := range groupByBaseDomain(hosts) {
		if len(group.subs) == 0 {
			// Standalone domain
			leftLines = append(leftLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render(group.base)))
		} else {
			// Base domain with subdomains listed inline
			leftLines = append(leftLines, fmt.Sprintf("  %s %s  %s",
				okStyle.Render("◉"), dimStyle.Render(group.base),
				dimStyle.Render(strings.Join(group.subs, ", "))))
		}
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
	browserStatus := checkBrowserForward()
	hasBrowserConfig := len(cfg.BrowserTargets) > 0
	switch browserStatus {
	case "ok":
		if hasBrowserConfig {
			thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render(fmt.Sprintf("browser forward (%d patterns)", len(cfg.BrowserTargets)))))
		} else {
			thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", warnStyle.Render("◉"), dimStyle.Render("browser forward (all blocked)")))
			thirdLines = append(thirdLines, dimStyle.Render("    add [[browser_target]] to config"))
		}
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
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", warnStyle.Render("◉"), dimStyle.Render(fmt.Sprintf("cdp :%d (no remote browser)", cdp.Port))))
	default:
		// Shorten browser version (e.g., "Chrome/144.0.7559.109" -> "Chrome/144")
		browserVer := cdp.Status
		if idx := strings.Index(browserVer, "."); idx > 0 {
			browserVer = browserVer[:idx]
		}
		thirdLines = append(thirdLines, fmt.Sprintf("  %s %s", okStyle.Render("◉"), dimStyle.Render(fmt.Sprintf("cdp :%d → %s", cdp.Port, browserVer))))

		// Check if CDP targets are configured
		hasCDPConfig := len(cfg.CDPTargets) > 0

		for _, t := range cdp.Targets {
			// Skip internal Chrome pages
			if strings.HasPrefix(t.URL, "chrome://") ||
				strings.HasPrefix(t.URL, "chrome-untrusted://") ||
				strings.HasPrefix(t.URL, "devtools://") ||
				strings.HasPrefix(t.URL, "about:") {
				continue
			}

			// Determine display name from title
			displayName := t.Title
			if len(displayName) > 25 {
				displayName = displayName[:22] + "..."
			}
			if displayName == "" {
				displayName = t.URL
				if len(displayName) > 25 {
					displayName = displayName[:22] + "..."
				}
			}

			allowed := hasCDPConfig && isTargetAllowed(t, cfg.CDPTargets)

			if allowed {
				thirdLines = append(thirdLines, fmt.Sprintf("    %s %s", okStyle.Render("◉"), dimStyle.Render(displayName)))
			} else {
				thirdLines = append(thirdLines, fmt.Sprintf("    %s %s", dimStyle.Render("○"), dimStyle.Render(displayName)))
			}
		}

		// If no CDP targets are configured, show hint
		if !hasCDPConfig && len(cdp.Targets) > 0 {
			thirdLines = append(thirdLines, dimStyle.Render("    add [[cdp_target]] to config"))
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
		Width(28).
		MarginRight(2)

	rightCol := lipgloss.NewStyle().
		Width(45).
		MarginRight(2)

	thirdCol := lipgloss.NewStyle().
		Width(40)

	// Render
	leftContent := leftCol.Render(strings.Join(leftLines, "\n"))
	rightContent := rightCol.Render(strings.Join(rightLines, "\n"))
	thirdContent := thirdCol.Render(strings.Join(thirdLines, "\n"))

	fmt.Println()
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Top, headerStyle.Render("🔑 agent-creds"), "  ", vaultBox))
	fmt.Println()
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Top, leftContent, rightContent, thirdContent))
	fmt.Println()
}

type domainGroup struct {
	base string   // e.g. "anthropic.com"
	subs []string // e.g. ["api", "events", "statsig"]
}

// groupByBaseDomain groups a sorted domain list by base domain.
// The input must already be sorted by reverseDomain.
func groupByBaseDomain(hosts []string) []domainGroup {
	var groups []domainGroup
	groupIdx := make(map[string]int) // base domain → index in groups

	for _, host := range hosts {
		base := baseDomain(host)
		if base == host {
			// This is the base domain itself
			if idx, ok := groupIdx[base]; ok {
				// Already have a group from a subdomain seen earlier — weird but handle it
				_ = idx
			} else {
				groupIdx[base] = len(groups)
				groups = append(groups, domainGroup{base: base})
			}
		} else {
			// Subdomain — find or create the group
			sub := strings.TrimSuffix(host, "."+base)
			if idx, ok := groupIdx[base]; ok {
				groups[idx].subs = append(groups[idx].subs, sub)
			} else {
				groupIdx[base] = len(groups)
				groups = append(groups, domainGroup{base: base, subs: []string{sub}})
			}
		}
	}
	return groups
}

// baseDomain extracts the registrable domain (last two labels, or three for known TLDs).
func baseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// reverseDomain reverses domain labels for sorting: "api.stripe.com" → "com.stripe.api"
func reverseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	return strings.Join(parts, ".")
}
