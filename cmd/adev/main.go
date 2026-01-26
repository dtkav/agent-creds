package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func init() {
	// Disable terminal queries to prevent escape sequence leakage
	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(true)
}

var (
	cyan   = lipgloss.Color("#00D7FF")
	green  = lipgloss.Color("#02BF87")
	yellow = lipgloss.Color("#FFCC00")
	dim    = lipgloss.Color("#888")

	spinnerStyle = lipgloss.NewStyle().Foreground(cyan)
	statusStyle  = lipgloss.NewStyle().Foreground(dim)
	doneStyle    = lipgloss.NewStyle().Foreground(green)
	warnStyle    = lipgloss.NewStyle().Foreground(yellow)
)

var spinnerChars = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

type Spinner struct {
	stop   chan struct{}
	status string
}

func NewSpinner() *Spinner {
	return &Spinner{stop: make(chan struct{})}
}

func (s *Spinner) Start() {
	go func() {
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Print("\r\033[K")
				return
			default:
				char := string(spinnerChars[i%len(spinnerChars)])
				fmt.Printf("\r%s %s", spinnerStyle.Render(char), statusStyle.Render(s.status))
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

func (s *Spinner) Status(msg string) {
	s.status = msg
}

func (s *Spinner) Stop() {
	close(s.stop)
	time.Sleep(50 * time.Millisecond) // Let goroutine clean up
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func runOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func fileNewer(a, b string) bool {
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return true
	}
	return infoA.ModTime().After(infoB.ModTime())
}

func imageExists(name string) bool {
	return run("docker", "image", "inspect", name) == nil
}

func proxyRunning() bool {
	out, err := runOutput("docker", "compose", "ps", "--status", "running")
	if err != nil {
		return false
	}
	return len(out) > 0 && exec.Command("grep", "-q", "envoy").Run() == nil
}

func main() {
	// Get directories
	workDir, _ := os.Getwd()

	// Get the actual executable path (resolves symlinks)
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
		os.Exit(1)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	scriptDir := filepath.Dir(filepath.Dir(exe)) // go up from bin/

	if err := os.Chdir(scriptDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error changing to %s: %v\n", scriptDir, err)
		os.Exit(1)
	}

	spinner := NewSpinner()
	spinner.Status("starting")
	spinner.Start()

	// Handle cleanup on interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		spinner.Stop()
		run("docker", "rm", "-f", "sandbox-net")
		os.Exit(1)
	}()

	// Run generator to ensure configs are up to date
	spinner.Status("generating configs...")
	gen, err := NewGenerator(scriptDir)
	if err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if err := gen.Generate(); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error generating configs: %v\n", err)
		os.Exit(1)
	}

	// Ensure proxy is running
	out, _ := runOutput("docker", "compose", "ps", "--status", "running")
	if len(out) == 0 || !contains(string(out), "envoy") {
		spinner.Status("starting proxy...")
		if err := run("docker", "compose", "up", "-d", "--build", "--quiet-pull"); err != nil {
			spinner.Stop()
			fmt.Fprintf(os.Stderr, "Error starting proxy: %v\n", err)
			os.Exit(1)
		}
	}

	// Build aenv if needed
	aenvBin := "generated/aenv"
	aenvSrc := "cmd/aenv/main.go"
	if !fileExists(aenvBin) || fileNewer(aenvSrc, aenvBin) {
		spinner.Status("building aenv...")
		cmd := exec.Command("go", "build", "-o", "../../generated/aenv", ".")
		cmd.Dir = "cmd/aenv"
		cmd.Run()
	}

	// Build sandbox if needed
	needsBuild := !imageExists("sandbox")
	if !needsBuild {
		marker := "generated/.sandbox-built"
		needsBuild = fileNewer("claude-dev/Dockerfile", marker) ||
			fileNewer("claude-dev/entrypoint.sh", marker) ||
			fileNewer("generated/aenv", marker) ||
			fileNewer("generated/certs/ca.crt", marker) ||
			fileNewer("generated/hosts", marker) ||
			fileNewer("generated/domains.json", marker)
	}
	if needsBuild {
		spinner.Status("building sandbox...")
		uid := fmt.Sprintf("%d", os.Getuid())
		gid := fmt.Sprintf("%d", os.Getgid())
		run("docker", "build", "-q", "-t", "sandbox",
			"--build-arg", "USER_UID="+uid,
			"--build-arg", "USER_GID="+gid,
			"-f", "claude-dev/Dockerfile", ".")
		os.WriteFile("generated/.sandbox-built", []byte{}, 0644)
	}

	// Build sandbox-net if needed
	needsNetBuild := !imageExists("sandbox-net")
	if !needsNetBuild {
		marker := "generated/.sandbox-net-built"
		needsNetBuild = fileNewer("claude-dev/sandbox-net/Dockerfile", marker) ||
			fileNewer("claude-dev/sandbox-net/entrypoint.sh", marker)
	}
	if needsNetBuild {
		spinner.Status("building sandbox-net...")
		run("docker", "build", "-q", "-t", "sandbox-net",
			"-f", "claude-dev/sandbox-net/Dockerfile", "claude-dev/sandbox-net")
		os.WriteFile("generated/.sandbox-net-built", []byte{}, 0644)
	}

	// Creds mount
	var credsMounts []string
	if fileExists("creds") {
		credsMounts = []string{"-v", scriptDir + "/creds:/creds:ro"}
	}

	// Pip cache mount (speeds up pip installs)
	var pipCacheMounts []string
	homeDir, _ := os.UserHomeDir()
	pipCache := filepath.Join(homeDir, ".cache", "pip")
	if fileExists(pipCache) {
		pipCacheMounts = []string{"-v", pipCache + ":/home/devuser/.cache/pip"}
	}

	// Create claude config dir
	os.MkdirAll(filepath.Join(scriptDir, "claude-dev/claude-config"), 0755)

	// Stop any existing sandbox-net
	runQuiet("docker", "rm", "-f", "sandbox-net")

	// Start sandbox-net
	spinner.Status("starting network filter...")
	if err := run("docker", "run", "-d", "--rm",
		"--name", "sandbox-net",
		"--network=agent-creds_agent-creds",
		"--cap-add=NET_ADMIN",
		"sandbox-net"); err != nil {
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "Error starting sandbox-net: %v\n", err)
		os.Exit(1)
	}

	time.Sleep(500 * time.Millisecond)

	// Stop spinner
	spinner.Stop()

	// Run sandbox
	args := []string{"run", "-it", "--rm",
		"--network=container:sandbox-net",
		"-e", "CLAUDE_CONFIG_DIR=/home/devuser/.claude",
		"-v", workDir + ":/workspace",
		"-v", scriptDir + "/claude-dev/claude-config:/home/devuser/.claude",
	}
	args = append(args, credsMounts...)
	args = append(args, pipCacheMounts...)
	args = append(args, "sandbox")

	cmd := exec.Command("docker", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	// Cleanup
	run("docker", "rm", "-f", "sandbox-net")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsImpl(s, substr)))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
