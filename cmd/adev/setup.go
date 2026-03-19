package main

import (
	"fmt"
	"os"
	"path/filepath"
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
)

// credential represents a vault credential available for selection.
type credential struct {
	Path    string
	Info    *CredentialInfo
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

func (m setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.view {
		case viewCredentialSelect:
			return m.updateCredentialSelect(msg)
		case viewEndpointConfig:
			return m.updateEndpointConfig(msg)
		case viewReview:
			return m.updateReview(msg)
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

func (m setupModel) updateEndpointConfig(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := &m.credentials[m.cursor]

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

func (m setupModel) View() string {
	switch m.view {
	case viewCredentialSelect:
		return m.viewCredentialSelect()
	case viewEndpointConfig:
		return m.viewEndpointConfig()
	case viewReview:
		return m.viewReview()
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

	b.WriteString(setupHelpStyle.Render("\n  [space] toggle  [enter] configure endpoints  [tab] review  [q] quit"))

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
	path := filepath.Join(m.projectDir, "agent-creds.toml")

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
			cfg.Upstream[host] = UpstreamConfig{
				Credential: c.Path,
				Methods:    c.Methods,
				Paths:      c.Paths,
			}
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

	// Write TOML
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
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
