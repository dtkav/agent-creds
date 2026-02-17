// tcp-bridge creates Unix sockets inside a gVisor container and proxies
// connections to the host via TCP. This allows browser forwarding and CDP
// forwarding to work in gVisor mode where Unix socket bind mounts don't work.
//
// For browser forwarding, it also inspects the URL for redirect_uri parameters
// and sets up callback proxies (0.0.0.0:port -> 127.0.0.1:port) so OAuth
// callbacks from the host browser can reach the sandbox's localhost listener.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	browserSockPath = "/tmp/browser-forward.sock"
	cdpSockPath     = "/tmp/cdp-forward.sock"
)

func main() {
	// Log to file so we can debug (container stderr isn't visible)
	logFile, err := os.OpenFile("/tmp/tcp-bridge.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}

	browserPort := os.Getenv("TCP_BROWSER_PORT")
	cdpPort := os.Getenv("TCP_CDP_PORT")

	if browserPort == "" && cdpPort == "" {
		log.Println("tcp-bridge: no TCP_BROWSER_PORT or TCP_CDP_PORT set, exiting")
		return
	}

	// Get gateway IP from default route
	gatewayIP := getGatewayIP()
	if gatewayIP == "" {
		log.Fatal("tcp-bridge: could not determine gateway IP")
	}
	log.Printf("tcp-bridge: gateway IP is %s", gatewayIP)

	var wg sync.WaitGroup

	if browserPort != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%s", gatewayIP, browserPort)
			if err := browserBridge(browserSockPath, addr); err != nil {
				log.Printf("browser bridge error: %v", err)
			}
		}()
	}

	if cdpPort != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%s", gatewayIP, cdpPort)
			if err := bridge(cdpSockPath, addr); err != nil {
				log.Printf("CDP bridge error: %v", err)
			}
		}()
	}

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	// Cleanup sockets
	os.Remove(browserSockPath)
	os.Remove(cdpSockPath)
}

// getGatewayIP reads the default gateway from /proc/net/route
func getGatewayIP() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "00000000" {
			// Default route - gateway is in hex, little-endian (bytes reversed)
			gw := fields[2]
			if len(gw) == 8 {
				var ip [4]byte
				fmt.Sscanf(gw, "%02X%02X%02X%02X", &ip[0], &ip[1], &ip[2], &ip[3])
				return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
			}
		}
	}
	return ""
}

// bridge creates a Unix socket at sockPath and proxies connections to TCP addr.
func bridge(sockPath string, tcpAddr string) error {
	// Remove any stale socket
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(sockPath)

	// Make socket world-writable for any user in the container
	os.Chmod(sockPath, 0666)

	log.Printf("tcp-bridge: %s -> %s", sockPath, tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go proxy(conn, tcpAddr)
	}
}

// browserBridge is like bridge but inspects HTTP requests for redirect_uri
// and sets up callback proxies for OAuth flows.
func browserBridge(sockPath string, tcpAddr string) error {
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(sockPath)

	os.Chmod(sockPath, 0666)
	log.Printf("tcp-bridge: %s -> %s (with OAuth callback detection)", sockPath, tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go browserProxy(conn, tcpAddr)
	}
}

// browserProxy reads the HTTP request, extracts redirect_uri for OAuth callback
// proxying, then forwards the request to adev.
func browserProxy(downstream net.Conn, tcpAddr string) {
	defer downstream.Close()

	// Read the HTTP request line and headers
	reader := bufio.NewReader(downstream)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Parse request line: GET /?url=... HTTP/1.1
	// Extract the url parameter and set up callback proxies for localhost ports
	parts := strings.Fields(requestLine)
	if len(parts) >= 2 {
		if parsed, err := url.Parse(parts[1]); err == nil {
			if browserURL := parsed.Query().Get("url"); browserURL != "" {
				extractAndProxyCallbackPorts(browserURL)
			}
		}
	}

	// Read remaining headers until blank line
	var headers []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		headers = append(headers, line)
	}

	// Connect to adev and forward the full request
	upstream, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		log.Printf("browser proxy: failed to connect to %s: %v", tcpAddr, err)
		return
	}
	defer upstream.Close()

	// Write request line and headers
	fmt.Fprint(upstream, requestLine)
	for _, h := range headers {
		fmt.Fprint(upstream, h)
	}
	fmt.Fprint(upstream, "\r\n")

	// Bidirectional copy for any remaining data
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, reader)
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(downstream, upstream)
		if tc, ok := downstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// extractAndProxyCallbackPorts parses a URL for localhost callback ports
// and starts proxies so external connections can reach localhost listeners.
func extractAndProxyCallbackPorts(rawURL string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	// Check main URL for localhost with port
	if port := parsed.Port(); port != "" {
		if host := parsed.Hostname(); host == "localhost" || host == "127.0.0.1" {
			go startCallbackProxy(port)
		}
	}

	// Check redirect_uri parameter (OAuth flows)
	if redirectURI := parsed.Query().Get("redirect_uri"); redirectURI != "" {
		if redirectParsed, err := url.Parse(redirectURI); err == nil {
			if port := redirectParsed.Port(); port != "" {
				if host := redirectParsed.Hostname(); host == "localhost" || host == "127.0.0.1" {
					go startCallbackProxy(port)
				}
			}
		}
	}
}

// isPortListening checks if any process is listening on the given port on localhost.
// Checks both IPv4 (/proc/net/tcp) and IPv6 (/proc/net/tcp6).
func isPortListening(port string) bool {
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)
	if portNum == 0 {
		return false
	}
	portHex := fmt.Sprintf("%04X", portNum)

	// Check IPv6 first (Claude Code typically binds to ::1)
	for _, procFile := range []string{"/proc/net/tcp6", "/proc/net/tcp"} {
		f, err := os.Open(procFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			// local_address is field[1], format is IP:PORT in hex
			// state is field[3], 0A = LISTEN
			localAddr := fields[1]
			state := fields[3]
			if state != "0A" { // Not LISTEN state
				continue
			}
			// Extract port from local_address (after the colon)
			parts := strings.Split(localAddr, ":")
			if len(parts) == 2 && parts[1] == portHex {
				// Check if it's localhost (127.0.0.1 or ::1)
				// IPv4 localhost: 0100007F
				// IPv6 localhost: 00000000000000000000000001000000
				ip := parts[0]
				if ip == "0100007F" || ip == "00000000000000000000000001000000" {
					f.Close()
					return true
				}
			}
		}
		f.Close()
	}
	return false
}

// startCallbackProxy listens on 0.0.0.0:<port> and forwards to localhost:<port>.
// Tries both IPv4 (127.0.0.1) and IPv6 (::1) since some apps bind to one or the other.
// Closes automatically when the upstream listener goes away.
func startCallbackProxy(port string) {
	listenAddr := "0.0.0.0:" + port

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		// Port might already be proxied or in use
		return
	}
	log.Printf("callback proxy: listening on %s", listenAddr)

	// Close when upstream listener goes away (poll every 2 seconds)
	go func() {
		for {
			time.Sleep(2 * time.Second)
			if !isPortListening(port) {
				log.Printf("callback proxy: upstream listener on port %s gone, closing", port)
				ln.Close()
				return
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}

		go func(c net.Conn) {
			defer c.Close()

			// Try IPv6 first (Claude Code binds to ::1), then IPv4
			targets := []string{"[::1]:" + port, "127.0.0.1:" + port}
			var upstream net.Conn
			for _, target := range targets {
				upstream, _ = net.Dial("tcp", target)
				if upstream != nil {
					break
				}
			}
			if upstream == nil {
				log.Printf("callback proxy: failed to connect to localhost:%s", port)
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

func proxy(downstream net.Conn, tcpAddr string) {
	defer downstream.Close()

	upstream, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		log.Printf("tcp dial error: %v", err)
		return
	}
	defer upstream.Close()

	// Bidirectional copy - wait for both directions
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, downstream)
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(downstream, upstream)
		if tc, ok := downstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
