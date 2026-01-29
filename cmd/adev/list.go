package main

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	selectedStyle   = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	unselectedStyle = lipgloss.NewStyle().Foreground(dim)
	runningStyle    = lipgloss.NewStyle().Foreground(green)
	partialStyle    = lipgloss.NewStyle().Foreground(yellow)
	helpStyle       = lipgloss.NewStyle().Foreground(dim)
)

type listModel struct {
	instances []Instance
	selected  int
	quitting  bool
	action    string // "attach" or ""
	mgr       *InstanceManager
}

func (m listModel) Init() tea.Cmd {
	return nil
}

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
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
			if len(m.instances) > 0 {
				m.action = "attach"
				m.quitting = true
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m listModel) View() string {
	if m.quitting {
		return ""
	}

	s := "adev instances\n\n"

	if len(m.instances) == 0 {
		s += unselectedStyle.Render("  No running instances") + "\n"
	} else {
		for i, inst := range m.instances {
			cursor := "  "
			style := unselectedStyle
			if i == m.selected {
				cursor = "> "
				style = selectedStyle
			}

			statusStyle := runningStyle
			if inst.Status == "partial" {
				statusStyle = partialStyle
			}

			name := style.Render(inst.Slug)
			status := statusStyle.Render(inst.Status)
			s += fmt.Sprintf("%s%-20s %s\n", cursor, name, status)
		}
	}

	s += "\n" + helpStyle.Render("↑/↓: navigate  enter: attach  q: quit")
	return s
}

func runList() {
	// Get scriptDir
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe))

	mgr := NewInstanceManager(scriptDir)
	instances := mgr.ListInstances()

	// Filter to only running or partial instances
	var runningInstances []Instance
	for _, inst := range instances {
		if inst.Status == "running" || inst.Status == "partial" {
			runningInstances = append(runningInstances, inst)
		}
	}

	m := listModel{
		instances: runningInstances,
		mgr:       mgr,
	}

	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Handle action after TUI exits
	fm := finalModel.(listModel)
	if fm.action == "attach" && len(fm.instances) > 0 {
		selected := fm.instances[fm.selected]
		if mgr.CanAttach(&selected) {
			fmt.Printf("Attaching to '%s'...\n", selected.Slug)
			if err := mgr.AttachToInstance(&selected); err != nil {
				fmt.Fprintf(os.Stderr, "Error attaching: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Cannot attach to '%s' (no running sandbox)\n", selected.Slug)
			os.Exit(1)
		}
	}
}
