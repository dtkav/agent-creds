package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type domainEntry struct {
	Host string `json:"host"`
}

func main() {
	ip := flag.String("ip", "", "IPv4 address to return for all A queries")
	ip6 := flag.String("ip6", "", "IPv6 address to return for all AAAA queries (optional)")
	domainsFile := flag.String("domains", "", "Path to domains.json for allowed/not-in-allowlist logging")
	logFile := flag.String("log", "", "Path to write network log")
	flag.Parse()

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "Usage: dns-responder -ip <IPv4> [-ip6 <IPv6>] [-domains <domains.json>] [-log <path>]")
		os.Exit(1)
	}

	responseIPv4 := net.ParseIP(*ip).To4()
	if responseIPv4 == nil {
		log.Fatalf("Invalid IPv4 address: %s", *ip)
	}

	var responseIPv6 net.IP
	if *ip6 != "" {
		responseIPv6 = net.ParseIP(*ip6).To16()
		if responseIPv6 == nil {
			log.Fatalf("Invalid IPv6 address: %s", *ip6)
		}
	}

	// Load allowed domains
	allowed := make(map[string]bool)
	if *domainsFile != "" {
		data, err := os.ReadFile(*domainsFile)
		if err == nil {
			var entries []domainEntry
			if json.Unmarshal(data, &entries) == nil {
				for _, e := range entries {
					allowed[strings.ToLower(e.Host)] = true
				}
			}
		}
	}

	// Open log file
	var logMu sync.Mutex
	var logFd *os.File
	if *logFile != "" {
		var err error
		logFd, err = os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer logFd.Close()
	}

	writeLog := func(domain, status string) {
		if logFd == nil {
			return
		}
		logMu.Lock()
		defer logMu.Unlock()
		ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		fmt.Fprintf(logFd, "%s DNS %s (%s)\n", ts, domain, status)
	}

	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatalf("Failed to listen on UDP :53: %v", err)
	}
	defer conn.Close()
	log.Printf("dns-responder listening on :53, answering with %s", *ip)

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n < 12 {
			continue
		}

		pkt := buf[:n]
		domain, qtype := parseQuestion(pkt)

		// Log
		domainLower := strings.ToLower(strings.TrimSuffix(domain, "."))
		if allowed[domainLower] {
			writeLog(domainLower, "allowed")
		} else if domainLower != "" {
			writeLog(domainLower, "not in allowlist")
		}

		var resp []byte
		switch qtype {
		case 1: // A
			resp = buildResponse(pkt, domain, 1, responseIPv4)
		case 28: // AAAA
			if responseIPv6 != nil {
				resp = buildResponse(pkt, domain, 28, responseIPv6)
			} else {
				resp = buildEmptyResponse(pkt)
			}
		default:
			resp = buildEmptyResponse(pkt)
		}

		conn.WriteTo(resp, addr)
	}
}

// parseQuestion extracts the first question's domain name and qtype from a DNS packet.
func parseQuestion(pkt []byte) (string, uint16) {
	if len(pkt) < 12 {
		return "", 0
	}
	offset := 12
	var parts []string
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			offset++
			break
		}
		offset++
		if offset+length > len(pkt) {
			return "", 0
		}
		parts = append(parts, string(pkt[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(pkt) {
		return strings.Join(parts, "."), 0
	}
	qtype := binary.BigEndian.Uint16(pkt[offset:])
	return strings.Join(parts, "."), qtype
}

// buildResponse builds a DNS response with a single answer record.
func buildResponse(query []byte, domain string, qtype uint16, ip net.IP) []byte {
	resp := make([]byte, 0, 512)

	// Header: copy ID, set QR=1, OPCODE=0, AA=1, RA=1, RCODE=0
	resp = append(resp, query[0], query[1])       // ID
	resp = append(resp, 0x84, 0x00)               // Flags: QR=1, AA=1
	resp = append(resp, 0x00, 0x01)               // QDCOUNT=1
	resp = append(resp, 0x00, 0x01)               // ANCOUNT=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)   // NSCOUNT=0, ARCOUNT=0

	// Question section: copy from query
	resp = appendQuestion(resp, domain, qtype)

	// Answer section: name pointer to question
	resp = append(resp, 0xC0, 0x0C) // pointer to offset 12 (domain in question)
	resp = binary.BigEndian.AppendUint16(resp, qtype)
	resp = binary.BigEndian.AppendUint16(resp, 1) // CLASS IN
	resp = binary.BigEndian.AppendUint32(resp, 60) // TTL 60s
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(ip)))
	resp = append(resp, ip...)

	return resp
}

// buildEmptyResponse builds a DNS response with no answer records.
func buildEmptyResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	// Copy the entire query, flip QR bit, set ANCOUNT=0
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x84 // QR=1, AA=1
	resp[3] = 0x00
	resp[6] = 0x00 // ANCOUNT=0
	resp[7] = 0x00
	return resp
}

// appendQuestion writes a DNS question section.
func appendQuestion(buf []byte, domain string, qtype uint16) []byte {
	for _, label := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, 1) // CLASS IN
	return buf
}
