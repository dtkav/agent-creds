package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// ForwardState tracks a forwarder's listener and socket path for cleanup.
type ForwardState struct {
	Listener net.Listener
	SockPath string
}

func (f *ForwardState) Close() {
	if f.Listener != nil {
		f.Listener.Close()
	}
	if f.SockPath != "" {
		os.Remove(f.SockPath)
	}
}

func startBrowserForward(netContainerName, slug string, targets []BrowserTargetConfig) (*ForwardState, error) {
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-browser.sock", slug))
	os.Remove(sockPath) // clean up stale socket

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	// Make socket accessible from container (runs as different uid)
	os.Chmod(sockPath, 0666)

	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawURL := r.URL.Query().Get("url")
		if rawURL == "" {
			http.Error(w, "missing url parameter", http.StatusBadRequest)
			return
		}

		// Check URL against allow-list (empty list = all blocked)
		allowed := false
		for _, t := range targets {
			if MatchGlob(t.URL, rawURL) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "url not allowed", http.StatusForbidden)
			return
		}

		// If the URL points to localhost with a port, set up a TCP proxy
		// so the host browser's OAuth callback can reach the sandbox container.
		if parsed, err := url.Parse(rawURL); err == nil {
			host := parsed.Hostname()
			port := parsed.Port()
			if port != "" && (host == "localhost" || host == "127.0.0.1") {
				go proxyLocalPort(netContainerName, port)
				// Small delay to let the listener start before the browser navigates back
				time.Sleep(100 * time.Millisecond)
			}
		}

		cmd := exec.Command("xdg-open", rawURL)
		if err := cmd.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go cmd.Wait()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	return &ForwardState{Listener: listener, SockPath: sockPath}, nil
}

func startCDPForward(slug string, port int) (*ForwardState, error) {
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("adev-%s-cdp.sock", slug))
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	os.Chmod(sockPath, 0666)

	addr := fmt.Sprintf("localhost:%d", port)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				upstream, err := net.Dial("tcp", addr)
				if err != nil {
					return
				}
				defer upstream.Close()
				go io.Copy(upstream, c)
				io.Copy(c, upstream)
			}(conn)
		}
	}()

	return &ForwardState{Listener: listener, SockPath: sockPath}, nil
}

// proxyLocalPort creates a temporary TCP listener on the host at the given port,
// forwarding connections to the same port inside the net container. This allows
// OAuth callbacks (host browser -> localhost:PORT) to reach the sandbox.
func proxyLocalPort(containerName, port string) {
	// Get the container's IP address
	out, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerName).Output()
	if err != nil {
		return
	}
	containerIP := strings.TrimSpace(string(out))
	if containerIP == "" {
		return
	}

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return
	}

	// Auto-close after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go func(c net.Conn) {
			defer c.Close()
			upstream, err := net.DialTimeout("tcp", containerIP+":"+port, 5*time.Second)
			if err != nil {
				return
			}
			defer upstream.Close()
			go io.Copy(upstream, c)
			io.Copy(c, upstream)
		}(conn)
		// Close listener after first connection completes
		ln.Close()
		return
	}
}

func main() {
	cmd := "list" // default: show TUI
	args := os.Args[1:]

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "list", "ls":
		runList()
	case "console", "c":
		runConsole(args)
	case "stop":
		runStop(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		// Unknown subcommand: treat as instance name for console
		runConsole(os.Args[1:])
	}
}

func printUsage() {
	fmt.Println(`adev - agent-creds development environment

Usage:
  adev [command] [options]

Commands:
  list, ls        Interactive TUI showing running instances (default)
  console [name]  Start or attach to a sandbox
  stop [name]     Stop a running instance
  help            Show this help

The default instance name is the current directory name.

Examples:
  adev              Show running instances (TUI)
  adev console      Start/attach to sandbox for current directory
  adev console foo  Start/attach to sandbox named "foo"
  adev stop         Stop the sandbox for current directory
  adev stop foo     Stop the sandbox named "foo"`)
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
