package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func dnsQuery(name string, qtype uint16) []byte {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[4:], 1)
	for _, label := range splitLabels(name) {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0)
	pkt = binary.BigEndian.AppendUint16(pkt, qtype)
	pkt = binary.BigEndian.AppendUint16(pkt, 1)
	return pkt
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

func TestDNSResponses(t *testing.T) {
	query := dnsQuery("service.internal", 1)
	domain, qtype := parseQuestion(query)
	if domain != "service.internal" || qtype != 1 {
		t.Fatalf("parsed (%q, %d)", domain, qtype)
	}
	answer := buildResponse(query, domain, qtype, net.ParseIP("192.0.2.1").To4())
	if got := binary.BigEndian.Uint16(answer[6:8]); got != 1 {
		t.Fatalf("answer count = %d", got)
	}
	empty := buildEmptyResponse(query)
	if got := binary.BigEndian.Uint16(empty[6:8]); got != 0 {
		t.Fatalf("empty answer count = %d", got)
	}
}
