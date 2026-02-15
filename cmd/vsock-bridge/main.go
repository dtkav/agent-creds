// tcp-bridge creates Unix sockets inside a gVisor container and proxies
// connections to the host via TCP. This allows browser forwarding and CDP
// forwarding to work in gVisor mode where Unix socket bind mounts don't work.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

const (
	browserSockPath = "/tmp/browser-forward.sock"
	cdpSockPath     = "/tmp/cdp-forward.sock"
)

func main() {
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
			if err := bridge(browserSockPath, addr); err != nil {
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

func proxy(downstream net.Conn, tcpAddr string) {
	defer downstream.Close()

	upstream, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		log.Printf("tcp dial error: %v", err)
		return
	}
	defer upstream.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, downstream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(downstream, upstream)
		done <- struct{}{}
	}()
	<-done
}
