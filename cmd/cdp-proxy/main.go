// cdp-proxy listens on tcp:9222 and forwards connections to /run/cdp-forward.sock.
// This runs inside the sandbox so that tools expecting localhost:9222 can reach
// the host's Chrome DevTools via the unix socket forwarded by adev.
package main

import (
	"io"
	"net"
	"os"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:9222")
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
