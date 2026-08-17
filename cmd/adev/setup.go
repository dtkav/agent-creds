package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/BurntSushi/toml"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// setupView represents which screen the TUI is showing.
type setupView int

const (
	viewCredentialSelect setupView = iota
	viewEndpointConfig
	viewReview
	viewNLInput
	viewNLProposal
)

// credential represents a vault credential available for selection.
type credential struct {
	Path     string
	Info     *CredentialInfo
	Selected bool
	// Per-credential endpoint config
	Methods []string
	Paths   []string
}

// setupModel is the bubbletea model for the setup TUI.
type setupModel struct {
	view        setupView
	credentials []credential
	cursor      int
	vaultCfg    VaultConfig
	projectDir  string
	existing    map[string]UpstreamConfig // existing upstream config
	err         error
	quitting    bool

	// endpoint config sub-view
	endpointCursor int
	editingField   int // 0 = methods, 1 = paths
	inputBuf       string

	// natural language sub-view
	nlInput     string
	nlProposals []nlProposal
	nlCursor    int
	nlLoading   bool
	nlError     string
}

// nlProposal represents a proposed upstream config from NL interpretation.
type nlProposal struct {
	Host       string   `json:"host"`
	Credential string   `json:"credential"`
	Methods    []string `json:"methods"`
	Paths      []string `json:"paths"`
	Accepted   bool
}

// nlResponse is the expected JSON output from claude -p.
type nlResponse struct {
	Upstreams []nlProposal `json:"upstreams"`
}

// Available HTTP methods for toggling
var httpMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

func runSetup(args []string) {
	workDir, _ := os.Getwd()
	cfg, err := LoadProjectConfig(workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Fetch available credentials from vault
	creds, err := fetchCredentials(cfg.Vault)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching credentials from vault: %v\n", err)
		fmt.Fprintf(os.Stderr, "Make sure the vault is running (make up)\n")
		os.Exit(1)
	}

	// Mark credentials that are already configured
	existing := cfg.Upstream
	if existing == nil {
		existing = make(map[string]UpstreamConfig)
	}

	for i := range creds {
		for _, u := range existing {
			if u.Credential == creds[i].Path {
				creds[i].Selected = true
				creds[i].Methods = u.Methods
				creds[i].Paths = u.Paths
				break
			}
		}
	}

	m := setupModel{
		view:        viewCredentialSelect,
		credentials: creds,
		vaultCfg:    cfg.Vault,
		projectDir:  workDir,
		existing:    existing,
	}

	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fm := finalModel.(setupModel)
	if fm.quitting {
		return
	}
}

// fetchCredentials queries vault-ssh for available credential paths.
// It tries common credential paths by listing via info command.
func fetchCredentials(vaultCfg VaultConfig) ([]credential, error) {
	// Use vault-ssh to list credentials
	output, err := vaultSSHRun(vaultCfg, "list")
	if err != nil {
		return nil, err
	}

	var creds []credential
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Each line is a credential path
		info, err := vaultSSHInfo(vaultCfg, line)
		if err != nil {
			continue // skip credentials we can't inspect
		}
		creds = append(creds, credential{
			Path: line,
			Info: info,
		})
	}

	return creds, nil
}

func (m setupModel) Init() tea.Cmd {
	return nil
}

// nlResultMsg carries the result of the claude -p invocation.
type nlResultMsg struct {
	proposals []nlProposal
	err       error
}

func (m setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case nlResultMsg:
		m.nlLoading = false
		if msg.err != nil {
			m.nlError = msg.err.Error()
			return m, nil
		}
		m.nlProposals = msg.proposals
		for i := range m.nlProposals {
			m.nlProposals[i].Accepted = true
		}
		m.nlCursor = 0
		m.view = viewNLProposal
		return m, nil
	case tea.KeyMsg:
		switch m.view {
		case viewCredentialSelect:
			return m.updateCredentialSelect(msg)
		case viewEndpointConfig:
			return m.updateEndpointConfig(msg)
		case viewReview:
			return m.updateReview(msg)
		case viewNLInput:
			return m.updateNLInput(msg)
		case viewNLProposal:
			return m.updateNLProposal(msg)
		}
	}
	return m, nil
}

func (m setupModel) updateCredentialSelect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.credentials)-1 {
			m.cursor++
		}
	case " ":
		if m.cursor < len(m.credentials) {
			m.credentials[m.cursor].Selected = !m.credentials[m.cursor].Selected
		}
	case "enter":
		if m.cursor < len(m.credentials) && m.credentials[m.cursor].Selected {
			m.view = viewEndpointConfig
			m.endpointCursor = 0
			m.editingField = -1
			m.inputBuf = ""
		}
	case "/":
		m.view = viewNLInput
		m.nlInput = ""
		m.nlError = ""
		return m, nil
	case "tab":
		// Move to review if any credentials selected
		hasSelected := false
		for _, c := range m.credentials {
			if c.Selected {
				hasSelected = true
				break
			}
		}
		if hasSelected {
			m.view = viewReview
		}
	}
	return m, nil
}

// hasCapabilities returns true if the credential has endpoint capabilities defined.
func (c *credential) hasCapabilities() bool {
	return c.Info != nil && len(c.Info.Endpoints) > 0
}

// endpointKey returns a unique string key for an endpoint capability.
func endpointKey(ep EndpointInfo) string {
	return strings.Join(ep.Methods, ",") + ":" + strings.Join(ep.Paths, ",")
}

// isEndpointSelected checks if a capability endpoint's methods and paths are all selected.
func (c *credential) isEndpointSelected(ep EndpointInfo) bool {
	for _, m := range ep.Methods {
		if !containsStr(c.Methods, m) {
			return false
		}
	}
	for _, p := range ep.Paths {
		if !containsStr(c.Paths, p) {
			return false
		}
	}
	return true
}

// toggleEndpoint adds or removes a capability endpoint's methods and paths.
func (c *credential) toggleEndpoint(ep EndpointInfo) {
	if c.isEndpointSelected(ep) {
		// Remove
		for _, m := range ep.Methods {
			c.Methods = removeStr(c.Methods, m)
		}
		for _, p := range ep.Paths {
			c.Paths = removeStr(c.Paths, p)
		}
	} else {
		// Add
		for _, m := range ep.Methods {
			if !containsStr(c.Methods, m) {
				c.Methods = append(c.Methods, m)
			}
		}
		for _, p := range ep.Paths {
			if !containsStr(c.Paths, p) {
				c.Paths = append(c.Paths, p)
			}
		}
	}
}

func (m setupModel) updateEndpointConfig(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := &m.credentials[m.cursor]

	// Credentials with capabilities use endpoint selection
	if c.hasCapabilities() {
		return m.updateEndpointConfigCaps(msg, c)
	}

	// Free-form endpoint entry for credentials without capabilities
	if m.editingField >= 0 {
		// Editing a field
		switch msg.String() {
		case "enter":
			if m.editingField == 0 {
				c.Methods = parseCSV(m.inputBuf)
			} else {
				c.Paths = parseCSV(m.inputBuf)
			}
			m.editingField = -1
			m.inputBuf = ""
		case "esc":
			m.editingField = -1
			m.inputBuf = ""
		case "backspace":
			if len(m.inputBuf) > 0 {
				m.inputBuf = m.inputBuf[:len(m.inputBuf)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.inputBuf += msg.String()
			}
		}
		return m, nil
	}

	switch msg.String() {
	case "esc":
		m.view = viewCredentialSelect
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		if m.endpointCursor > 0 {
			m.endpointCursor--
		}
	case "down", "j":
		if m.endpointCursor < len(httpMethods) {
			m.endpointCursor++
		}
	case " ":
		// Toggle HTTP method
		if m.endpointCursor < len(httpMethods) {
			method := httpMethods[m.endpointCursor]
			if containsStr(c.Methods, method) {
				c.Methods = removeStr(c.Methods, method)
			} else {
				c.Methods = append(c.Methods, method)
			}
		}
	case "p":
		// Edit paths
		m.editingField = 1
		m.inputBuf = strings.Join(c.Paths, ", ")
	case "enter":
		m.view = viewCredentialSelect
	}
	return m, nil
}

func (m setupModel) updateEndpointConfigCaps(msg tea.KeyMsg, c *credential) (tea.Model, tea.Cmd) {
	endpoints := c.Info.Endpoints
	switch msg.String() {
	case "esc":
		m.view = viewCredentialSelect
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		if m.endpointCursor > 0 {
			m.endpointCursor--
		}
	case "down", "j":
		if m.endpointCursor < len(endpoints)-1 {
			m.endpointCursor++
		}
	case " ":
		if m.endpointCursor < len(endpoints) {
			c.toggleEndpoint(endpoints[m.endpointCursor])
		}
	case "enter":
		m.view = viewCredentialSelect
	}
	return m, nil
}

func (m setupModel) updateReview(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.view = viewCredentialSelect
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "enter":
		// Apply changes
		if err := m.writeConfig(); err != nil {
			m.err = err
			return m, nil
		}
		return m, tea.Quit
	}
	return m, nil
}

func (m setupModel) updateNLInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.view = viewCredentialSelect
		m.nlError = ""
	case "enter":
		if strings.TrimSpace(m.nlInput) == "" {
			return m, nil
		}
		m.nlLoading = true
		m.nlError = ""
		input := m.nlInput
		creds := m.credentials
		return m, func() tea.Msg {
			proposals, err := runClaudeNL(input, creds)
			return nlResultMsg{proposals: proposals, err: err}
		}
	case "backspace":
		if len(m.nlInput) > 0 {
			m.nlInput = m.nlInput[:len(m.nlInput)-1]
		}
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	default:
		if len(msg.String()) == 1 {
			m.nlInput += msg.String()
		}
	}
	return m, nil
}

func (m setupModel) updateNLProposal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.view = viewCredentialSelect
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		if m.nlCursor > 0 {
			m.nlCursor--
		}
	case "down", "j":
		if m.nlCursor < len(m.nlProposals)-1 {
			m.nlCursor++
		}
	case " ":
		if m.nlCursor < len(m.nlProposals) {
			m.nlProposals[m.nlCursor].Accepted = !m.nlProposals[m.nlCursor].Accepted
		}
	case "/":
		// Refine: go back to NL input keeping existing proposals
		m.view = viewNLInput
		m.nlInput = ""
		m.nlError = ""
	case "enter":
		// Apply accepted proposals to credentials
		m.applyNLProposals()
		m.view = viewReview
	}
	return m, nil
}

func (m *setupModel) applyNLProposals() {
	for _, p := range m.nlProposals {
		if !p.Accepted {
			continue
		}
		// Find matching credential
		for i := range m.credentials {
			if m.credentials[i].Path == p.Credential {
				m.credentials[i].Selected = true
				m.credentials[i].Methods = p.Methods
				m.credentials[i].Paths = p.Paths
				break
			}
		}
	}
}

// runClaudeNL shells out to claude -p with credential context and parses the response.
func runClaudeNL(description string, creds []credential) ([]nlProposal, error) {
	// Build context about available credentials
	var ctx strings.Builder
	ctx.WriteString("Available credentials:\n")
	for _, c := range creds {
		ctx.WriteString(fmt.Sprintf("- Path: %s", c.Path))
		if c.Info != nil {
			ctx.WriteString(fmt.Sprintf(", Type: %s", c.Info.Type))
			if len(c.Info.Hosts) > 0 {
				ctx.WriteString(fmt.Sprintf(", Hosts: %s", strings.Join(c.Info.Hosts, ", ")))
			}
		}
		ctx.WriteString("\n")
	}

	prompt := fmt.Sprintf(`You are configuring API access for an AI agent sandbox. Given the user's description and available credentials, output a JSON object with an "upstreams" array. Each entry has: "host" (API hostname), "credential" (credential path from the list), "methods" (HTTP methods like GET, POST, etc.), "paths" (URL path patterns with ** for wildcards).

%s
User request: %s

Respond with ONLY valid JSON, no markdown fences or explanation.`, ctx.String(), description)

	cmd := exec.Command("claude", "-p", prompt)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("claude -p failed: %w", err)
	}

	// Parse JSON response
	var resp nlResponse
	// Try to extract JSON from response (claude may add extra text)
	output := strings.TrimSpace(string(out))
	// Find first { and last }
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start >= 0 && end > start {
		output = output[start : end+1]
	}

	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Validate proposals reference known credentials
	credPaths := make(map[string]bool)
	for _, c := range creds {
		credPaths[c.Path] = true
	}
	var valid []nlProposal
	for _, p := range resp.Upstreams {
		if credPaths[p.Credential] {
			valid = append(valid, p)
		}
	}

	return valid, nil
}

func (m setupModel) View() string {
	switch m.view {
	case viewCredentialSelect:
		return m.viewCredentialSelect()
	case viewEndpointConfig:
		return m.viewEndpointConfig()
	case viewReview:
		return m.viewReview()
	case viewNLInput:
		return m.viewNLInput()
	case viewNLProposal:
		return m.viewNLProposal()
	}
	return ""
}

var (
	setupTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(cyan).MarginBottom(1)
	setupBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(cyan).
				Padding(1, 2)
	setupSelectedStyle = lipgloss.NewStyle().Foreground(green)
	setupDimStyle      = lipgloss.NewStyle().Foreground(dim)
	setupHelpStyle     = lipgloss.NewStyle().Foreground(dim).MarginTop(1)
)

func (m setupModel) viewCredentialSelect() string {
	var b strings.Builder
	b.WriteString(setupTitleStyle.Render("agent-creds setup"))
	b.WriteString("\n\n")
	b.WriteString("  Available credentials (from vault):\n\n")

	for i, c := range m.credentials {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}

		marker := "○"
		style := setupDimStyle
		if c.Selected {
			marker = "●"
			style = setupSelectedStyle
		}

		typStr := ""
		if c.Info != nil {
			typStr = c.Info.Type
		}

		hosts := ""
		if c.Info != nil && len(c.Info.Hosts) > 0 {
			hosts = strings.Join(c.Info.Hosts, ", ")
		}

		line := fmt.Sprintf("%s%s %-24s %-10s %s", cursor, marker, c.Path, typStr, hosts)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	b.WriteString(setupHelpStyle.Render("\n  [space] toggle  [enter] configure endpoints  [/] describe access  [tab] review  [q] quit"))

	return setupBorderStyle.Render(b.String())
}

func (m setupModel) viewEndpointConfig() string {
	c := m.credentials[m.cursor]
	var b strings.Builder

	b.WriteString(setupTitleStyle.Render(fmt.Sprintf("Configure: %s", c.Path)))
	b.WriteString("\n\n")

	if c.Info != nil {
		b.WriteString(fmt.Sprintf("  Type: %s\n", c.Info.Type))
		if len(c.Info.Hosts) > 0 {
			b.WriteString(fmt.Sprintf("  Hosts: %s\n", strings.Join(c.Info.Hosts, ", ")))
		}
		b.WriteString("\n")
	}

	if c.hasCapabilities() {
		// Show capability endpoints as selectable items
		b.WriteString("  Endpoints:\n\n")
		for i, ep := range c.Info.Endpoints {
			cursor := "  "
			if i == m.endpointCursor {
				cursor = "> "
			}
			marker := "○"
			if c.isEndpointSelected(ep) {
				marker = "●"
			}

			methods := strings.Join(ep.Methods, ", ")
			paths := strings.Join(ep.Paths, ", ")
			b.WriteString(fmt.Sprintf("  %s%s %s  %s\n", cursor, marker, methods, paths))
			if ep.Description != "" {
				b.WriteString(setupDimStyle.Render(fmt.Sprintf("       %s", ep.Description)))
				b.WriteString("\n")
			}
		}

		b.WriteString(setupHelpStyle.Render("\n  [space] toggle endpoint  [enter] save  [esc] back"))
	} else {
		// Free-form entry
		b.WriteString("  HTTP Methods:\n\n")
		for i, method := range httpMethods {
			cursor := "  "
			if i == m.endpointCursor {
				cursor = "> "
			}
			marker := "○"
			if containsStr(c.Methods, method) {
				marker = "●"
			}
			b.WriteString(fmt.Sprintf("  %s%s %s\n", cursor, marker, method))
		}

		// Paths section
		cursor := "  "
		if m.endpointCursor == len(httpMethods) {
			cursor = "> "
		}
		pathsStr := "(all)"
		if len(c.Paths) > 0 {
			pathsStr = strings.Join(c.Paths, ", ")
		}
		b.WriteString(fmt.Sprintf("\n  %sPaths: %s\n", cursor, pathsStr))

		if m.editingField == 1 {
			b.WriteString(fmt.Sprintf("\n  Edit paths (comma-separated): %s█\n", m.inputBuf))
		}

		b.WriteString(setupHelpStyle.Render("\n  [space] toggle method  [p] edit paths  [enter] save  [esc] back"))
	}

	return setupBorderStyle.Render(b.String())
}

func (m setupModel) viewReview() string {
	var b strings.Builder
	b.WriteString(setupTitleStyle.Render("Review proposed changes"))
	b.WriteString("\n\n")

	tomlStr := m.generateTOML()
	if tomlStr == "" {
		b.WriteString("  No changes to apply.\n")
	} else {
		for _, line := range strings.Split(tomlStr, "\n") {
			b.WriteString("  " + line + "\n")
		}
	}

	if m.err != nil {
		b.WriteString(fmt.Sprintf("\n  Error: %v\n", m.err))
	}

	b.WriteString(setupHelpStyle.Render("\n  [enter] apply  [esc] back  [q] quit"))

	return setupBorderStyle.Render(b.String())
}

func (m setupModel) viewNLInput() string {
	var b strings.Builder
	b.WriteString(setupTitleStyle.Render("Describe access"))
	b.WriteString("\n\n")
	b.WriteString("  What should the agent be able to do?\n\n")
	b.WriteString(fmt.Sprintf("  > %s█\n", m.nlInput))

	if m.nlLoading {
		b.WriteString("\n  Interpreting with claude...\n")
	}
	if m.nlError != "" {
		b.WriteString(fmt.Sprintf("\n  Error: %s\n", m.nlError))
	}

	b.WriteString(setupHelpStyle.Render("\n  [enter] submit  [esc] back"))

	return setupBorderStyle.Render(b.String())
}

func (m setupModel) viewNLProposal() string {
	var b strings.Builder
	b.WriteString(setupTitleStyle.Render("Proposed configuration"))
	b.WriteString("\n\n")

	if len(m.nlProposals) == 0 {
		b.WriteString("  No matching configuration found.\n")
	} else {
		for i, p := range m.nlProposals {
			cursor := "  "
			if i == m.nlCursor {
				cursor = "> "
			}
			marker := "●"
			style := setupSelectedStyle
			if !p.Accepted {
				marker = "○"
				style = setupDimStyle
			}

			b.WriteString(style.Render(fmt.Sprintf("%s%s %s (using %s)", cursor, marker, p.Host, p.Credential)))
			b.WriteString("\n")

			for _, method := range p.Methods {
				paths := "/**"
				if len(p.Paths) > 0 {
					paths = strings.Join(p.Paths, ", ")
				}
				b.WriteString(style.Render(fmt.Sprintf("      %-6s %s", method, paths)))
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString(setupHelpStyle.Render("  [space] toggle  [enter] accept  [/] refine  [esc] cancel"))

	return setupBorderStyle.Render(b.String())
}

func (m setupModel) generateTOML() string {
	var b strings.Builder

	for _, c := range m.credentials {
		if !c.Selected {
			continue
		}
		if c.Info == nil || len(c.Info.Hosts) == 0 {
			continue
		}

		for _, host := range c.Info.Hosts {
			b.WriteString(fmt.Sprintf("[upstream.%q]\n", host))
			b.WriteString(fmt.Sprintf("credential = %q\n", c.Path))
			if len(c.Methods) > 0 {
				b.WriteString(fmt.Sprintf("methods = [%s]\n", setupQuotedList(c.Methods)))
			}
			if len(c.Paths) > 0 {
				b.WriteString(fmt.Sprintf("paths = [%s]\n", setupQuotedList(c.Paths)))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func (m setupModel) writeConfig() error {
	path, _, err := projectConfigPath(m.projectDir)
	if err != nil {
		return err
	}

	// Read existing config
	cfg, err := LoadProjectConfig(m.projectDir)
	if err != nil {
		return err
	}

	if cfg.Upstream == nil {
		cfg.Upstream = make(map[string]UpstreamConfig)
	}

	// Update upstreams from selected credentials
	for _, c := range m.credentials {
		if !c.Selected || c.Info == nil {
			continue
		}
		for _, host := range c.Info.Hosts {
			upstream := cfg.Upstream[host]
			upstream.Credential = c.Path
			upstream.Methods = c.Methods
			upstream.Paths = c.Paths
			cfg.Upstream[host] = upstream
		}
	}

	// Remove upstreams for deselected credentials
	for _, c := range m.credentials {
		if c.Selected || c.Info == nil {
			continue
		}
		for _, host := range c.Info.Hosts {
			if u, ok := cfg.Upstream[host]; ok && u.Credential == c.Path {
				delete(cfg.Upstream, host)
			}
		}
	}

	// Write TOML to temp file, validate, then rename
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("encoding TOML: %w", err)
	}
	f.Close()

	// Validate written config can be parsed back
	var check ProjectConfig
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("reading back config: %w", err)
	}
	if err := toml.Unmarshal(data, &check); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("validating written config: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return nil
}

// Helper functions

func parseCSV(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func removeStr(slice []string, s string) []string {
	var result []string
	for _, v := range slice {
		if v != s {
			result = append(result, v)
		}
	}
	return result
}

func setupQuotedList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", item)
	}
	return strings.Join(quoted, ", ")
}
