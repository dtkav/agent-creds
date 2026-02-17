package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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

// ForwardState tracks a forwarder's listener for cleanup.
type ForwardState struct {
	Listener net.Listener
}

func (f *ForwardState) Close() {
	if f.Listener != nil {
		f.Listener.Close()
	}
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
	fmt.Fprintf(os.Stderr, "[oauth-proxy] localhost:%s -> %s:%s\n", port, containerIP, port)

	// Auto-close after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			upstream, err := net.DialTimeout("tcp", containerIP+":"+port, 5*time.Second)
			if err != nil {
				return
			}
			defer upstream.Close()

			done := make(chan struct{}, 2)
			go func() {
				io.Copy(upstream, c)
				if tc, ok := upstream.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			go func() {
				io.Copy(c, upstream)
				if tc, ok := c.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			<-done
			<-done
		}(conn)
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

// GetContainerIP returns the IP address of a container on a specific network.
func GetContainerIP(containerName, networkName string) (string, error) {
	template := fmt.Sprintf(`{{(index .NetworkSettings.Networks "%s").IPAddress}}`, networkName)
	out, err := exec.Command("docker", "inspect", "-f", template, containerName).Output()
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("no IP found for %s on network %s", containerName, networkName)
	}
	return ip, nil
}

// GetNetworkGateway returns the gateway IP of a Docker network.
func GetNetworkGateway(networkName string) (string, error) {
	out, err := exec.Command("docker", "network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", networkName).Output()
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("no gateway found for network %s", networkName)
	}
	return ip, nil
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
