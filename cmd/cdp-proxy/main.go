// cdp-proxy listens on a TCP port and forwards connections to /run/cdp-forward.sock.
// This runs inside the sandbox so that tools expecting localhost:<port> can reach
// the host's Chrome DevTools via the unix socket forwarded by adev.
//
// The port is configured via the CDP_PORT environment variable (default: 9222).
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

func main() {
	port := 9222
	if p := os.Getenv("CDP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			port = v
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go proxy(conn)
	}
}

func proxy(c net.Conn) {
	defer c.Close()
	upstream, err := net.Dial("unix", "/run/cdp-forward.sock")
	if err != nil {
		return
	}
	defer upstream.Close()
	go io.Copy(upstream, c)
	io.Copy(c, upstream)
}
