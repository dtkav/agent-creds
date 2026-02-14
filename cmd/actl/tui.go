package main

import (
	"fmt"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const refreshInterval = 2 * time.Second

// Styles for the TUI
var (
	cyan = lipgloss.Color("#00D7FF")
	dim  = lipgloss.Color("#888")

	tuiSelectedStyle   = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	tuiUnselectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	tuiRunningStyle    = lipgloss.NewStyle().Foreground(green)
	tuiPartialStyle    = lipgloss.NewStyle().Foreground(yellow)
	tuiStoppedStyle    = lipgloss.NewStyle().Foreground(dim)
	tuiHelpStyle       = lipgloss.NewStyle().Foreground(dim)
	tuiHeaderStyle     = lipgloss.NewStyle().Bold(true).Foreground(cyan)
	tuiTreeStyle       = lipgloss.NewStyle().Foreground(dim)
	tuiRuntimeStyle    = lipgloss.NewStyle().Foreground(dim)
	tuiConfirmStyle    = lipgloss.NewStyle().Foreground(yellow).Bold(true)
	tuiUpdateStyle     = lipgloss.NewStyle().Foreground(yellow)
)

// containerInfo holds details about a container
type containerInfo struct {
	Name    string
	Type    string // "sandbox", "envoy", "net"
	Status  string // "running", "exited"
	Runtime string // "runc", "runsc"
}

// instanceInfo represents an adev instance
type instanceInfo struct {
	Slug       string
	Status     string // "running", "partial", "stopped"
	Containers []containerInfo
}

// tickMsg is sent periodically to trigger background refresh
type tickMsg time.Time

// refreshMsg carries new instance data from background refresh
type refreshMsg struct {
	instances []instanceInfo
}

// tuiModel is the bubbletea model for the TUI
type tuiModel struct {
	instances        []instanceInfo
	pendingInstances []instanceInfo // new data waiting to be applied
	hasUpdates       bool           // true when pendingInstances differs from instances
	selected         int
	expanded         map[int]bool // which instances are expanded
	confirming       bool         // kill confirmation mode
	quitting         bool
	width            int
	height           int
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(tickCmd(), doRefresh())
}

// tickCmd returns a command that ticks after the refresh interval
func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// doRefresh fetches instance data in the background
func doRefresh() tea.Cmd {
	return func() tea.Msg {
		return refreshMsg{instances: listInstances()}
	}
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		// Schedule next tick and background refresh
		return m, tea.Batch(tickCmd(), doRefresh())

	case refreshMsg:
		// Check if data changed
		if !instancesEqual(m.instances, msg.instances) {
			m.pendingInstances = msg.instances
			m.hasUpdates = true
		}
		return m, nil

	case tea.KeyMsg:
		if m.confirming {
			switch msg.String() {
			case "y", "Y":
				// Kill the selected instance
				if m.selected < len(m.instances) {
					killInstance(m.instances[m.selected].Slug)
					// Force immediate refresh after kill
					m.instances = listInstances()
					m.pendingInstances = nil
					m.hasUpdates = false
					if m.selected >= len(m.instances) {
						m.selected = len(m.instances) - 1
					}
					if m.selected < 0 {
						m.selected = 0
					}
				}
				m.confirming = false
			case "n", "N", "esc":
				m.confirming = false
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.selected < len(m.instances)-1 {
				m.selected++
			}
		case "enter":
			// Toggle expand/collapse
			if m.selected < len(m.instances) {
				m.expanded[m.selected] = !m.expanded[m.selected]
			}
		case "x":
			// Kill confirmation
			if m.selected < len(m.instances) {
				m.confirming = true
			}
		case "r":
			// Apply pending updates (or force refresh if none pending)
			if m.hasUpdates && m.pendingInstances != nil {
				m.instances = m.pendingInstances
				m.pendingInstances = nil
				m.hasUpdates = false
				// Adjust selection if needed
				if m.selected >= len(m.instances) {
					m.selected = len(m.instances) - 1
				}
				if m.selected < 0 {
					m.selected = 0
				}
				// Rebuild expanded map based on slugs
				newExpanded := make(map[int]bool)
				oldSlugs := make(map[string]bool)
				for idx, expanded := range m.expanded {
					if expanded && idx < len(m.instances) {
						oldSlugs[m.instances[idx].Slug] = true
					}
				}
				for i, inst := range m.instances {
					if oldSlugs[inst.Slug] {
						newExpanded[i] = true
					}
				}
				m.expanded = newExpanded
			}
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.quitting {
		return ""
	}

	var s strings.Builder

	// Header
	s.WriteString(tuiHeaderStyle.Render("actl · agent-creds"))
	s.WriteString("\n\n")

	// Section header with help and update indicator
	s.WriteString(tuiUnselectedStyle.Render("Instances"))
	if m.hasUpdates {
		s.WriteString("  ")
		s.WriteString(tuiUpdateStyle.Render("● updates available"))
	}
	s.WriteString(strings.Repeat(" ", 20))
	s.WriteString(tuiHelpStyle.Render("r: refresh  q: quit"))
	s.WriteString("\n\n")

	if len(m.instances) == 0 {
		s.WriteString(tuiHelpStyle.Render("  No adev instances found"))
		s.WriteString("\n")
	} else {
		for i, inst := range m.instances {
			cursor := "  "
			nameStyle := tuiUnselectedStyle
			if i == m.selected {
				cursor = "> "
				nameStyle = tuiSelectedStyle
			}

			// Status styling
			statusStyle := tuiRunningStyle
			statusText := "running"
			switch inst.Status {
			case "partial":
				statusStyle = tuiPartialStyle
				statusText = "partial"
			case "stopped":
				statusStyle = tuiStoppedStyle
				statusText = "stopped"
			}

			// Instance line
			s.WriteString(cursor)
			s.WriteString(nameStyle.Render(inst.Slug))
			// Pad to align status
			padding := 40 - len(inst.Slug)
			if padding < 1 {
				padding = 1
			}
			s.WriteString(strings.Repeat(" ", padding))
			s.WriteString("[")
			s.WriteString(statusStyle.Render(statusText))
			s.WriteString("]")
			s.WriteString("\n")

			// Show containers if expanded
			if m.expanded[i] {
				for j, c := range inst.Containers {
					prefix := "  ├── "
					if j == len(inst.Containers)-1 {
						prefix = "  └── "
					}

					// Container status styling
					cStatusStyle := tuiRunningStyle
					if c.Status != "running" {
						cStatusStyle = tuiStoppedStyle
					}

					// Format: prefix + name + runtime + status
					line := tuiTreeStyle.Render(prefix)
					line += fmt.Sprintf("%-30s", c.Name)
					line += tuiRuntimeStyle.Render(fmt.Sprintf("%-10s", c.Runtime))
					line += cStatusStyle.Render(c.Status)
					s.WriteString(line)
					s.WriteString("\n")
				}
				s.WriteString("\n")
			}
		}
	}

	// Confirmation dialog
	if m.confirming && m.selected < len(m.instances) {
		s.WriteString("\n")
		s.WriteString(tuiConfirmStyle.Render(fmt.Sprintf("Kill instance '%s'? (y/n)", m.instances[m.selected].Slug)))
		s.WriteString("\n")
	}

	// Help footer
	s.WriteString("\n")
	s.WriteString(tuiHelpStyle.Render("↑/↓/j/k: navigate  enter: expand  x: kill  q: quit"))

	return s.String()
}

// instancesEqual compares two instance slices for equality
func instancesEqual(a, b []instanceInfo) bool {
	if len(a) != len(b) {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// listInstances queries docker for all adev instances
func listInstances() []instanceInfo {
	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "name=adev-",
		"--format", "{{.Names}}\t{{.Status}}").Output()
	if err != nil {
		return nil
	}

	// Group containers by slug
	instanceMap := make(map[string]*instanceInfo)

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		status := parts[1]

		// Parse container name: adev-{slug}-{type}
		if !strings.HasPrefix(name, "adev-") {
			continue
		}
		rest := strings.TrimPrefix(name, "adev-")

		var slug, containerType string
		if strings.HasSuffix(rest, "-sandbox") {
			slug = strings.TrimSuffix(rest, "-sandbox")
			containerType = "sandbox"
		} else if strings.HasSuffix(rest, "-envoy") {
			slug = strings.TrimSuffix(rest, "-envoy")
			containerType = "envoy"
		} else if strings.HasSuffix(rest, "-net") {
			slug = strings.TrimSuffix(rest, "-net")
			containerType = "net"
		} else {
			continue
		}

		if slug == "" {
			continue
		}

		inst, ok := instanceMap[slug]
		if !ok {
			inst = &instanceInfo{
				Slug:       slug,
				Containers: []containerInfo{},
			}
			instanceMap[slug] = inst
		}

		isRunning := strings.HasPrefix(status, "Up")
		containerStatus := "exited"
		if isRunning {
			containerStatus = "running"
		}

		// Get runtime
		runtime := getContainerRuntime(name)

		inst.Containers = append(inst.Containers, containerInfo{
			Name:    name,
			Type:    containerType,
			Status:  containerStatus,
			Runtime: runtime,
		})
	}

	// Determine overall status for each instance
	for _, inst := range instanceMap {
		sandboxRunning := false
		envoyRunning := false
		netRunning := false

		for _, c := range inst.Containers {
			if c.Status == "running" {
				switch c.Type {
				case "sandbox":
					sandboxRunning = true
				case "envoy":
					envoyRunning = true
				case "net":
					netRunning = true
				}
			}
		}

		if sandboxRunning && envoyRunning && netRunning {
			inst.Status = "running"
		} else if sandboxRunning || envoyRunning || netRunning {
			inst.Status = "partial"
		} else {
			inst.Status = "stopped"
		}

		// Sort containers: sandbox, envoy, net
		sort.Slice(inst.Containers, func(i, j int) bool {
			order := map[string]int{"sandbox": 0, "envoy": 1, "net": 2}
			return order[inst.Containers[i].Type] < order[inst.Containers[j].Type]
		})
	}

	// Convert to slice and sort by slug
	var result []instanceInfo
	for _, inst := range instanceMap {
		result = append(result, *inst)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Slug < result[j].Slug
	})

	return result
}

// getContainerRuntime returns the runtime for a container ("runc" or "runsc")
func getContainerRuntime(name string) string {
	out, err := exec.Command("docker", "inspect", "--format", "{{.HostConfig.Runtime}}", name).Output()
	if err != nil {
		return "runc"
	}
	runtime := strings.TrimSpace(string(out))
	if runtime == "" {
		return "runc"
	}
	return runtime
}

// killInstance removes all containers and network for an instance
func killInstance(slug string) {
	sandboxName := "adev-" + slug + "-sandbox"
	netName := "adev-" + slug + "-net"
	envoyName := "adev-" + slug + "-envoy"
	networkName := "adev-" + slug

	// Stop containers gracefully (allows cleanup traps to run)
	exec.Command("docker", "stop", netName).Run()
	exec.Command("docker", "stop", sandboxName).Run()
	exec.Command("docker", "stop", envoyName).Run()

	// Remove containers
	exec.Command("docker", "rm", "-f", sandboxName).Run()
	exec.Command("docker", "rm", "-f", netName).Run()
	exec.Command("docker", "rm", "-f", envoyName).Run()

	// Remove network
	exec.Command("docker", "network", "rm", networkName).Run()
}

// runTUI launches the interactive TUI
func runTUI() {
	instances := listInstances()

	m := tuiModel{
		instances: instances,
		expanded:  make(map[int]bool),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
	}
}
