#!/bin/sh
set -e

# Host-mode sandbox-net: sets up iptables on the host to route traffic from sandbox to envoy
# Usage: entrypoint-host.sh <sandbox-ip> <envoy-ip> <chain-name>
#
# This script runs in a container with --network=host --cap-add=NET_ADMIN
# It modifies the HOST's iptables to redirect traffic from the sandbox container.

SANDBOX_IP="$1"
ENVOY_IP="$2"
CHAIN_NAME="$3"

if [ -z "$SANDBOX_IP" ] || [ -z "$ENVOY_IP" ] || [ -z "$CHAIN_NAME" ]; then
    echo "Usage: $0 <sandbox-ip> <envoy-ip> <chain-name>"
    exit 1
fi

NAT_CHAIN="${CHAIN_NAME}-NAT"
FILTER_CHAIN="${CHAIN_NAME}-FILTER"

echo "Setting up host iptables: sandbox=$SANDBOX_IP envoy=$ENVOY_IP chain=$CHAIN_NAME"

cleanup() {
    echo "Cleaning up iptables rules..."
    # Remove from PREROUTING, POSTROUTING, and FORWARD
    iptables -t nat -D PREROUTING -s "$SANDBOX_IP" -j "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SANDBOX_IP" -d "$ENVOY_IP" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -s "$SANDBOX_IP" -j "$FILTER_CHAIN" 2>/dev/null || true
    # Flush and delete chains
    iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
    iptables -F "$FILTER_CHAIN" 2>/dev/null || true
    iptables -X "$FILTER_CHAIN" 2>/dev/null || true
    echo "Cleanup complete"
}

# Clean up on exit
trap cleanup EXIT INT TERM

# Create NAT chain for DNAT rules
iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || iptables -t nat -F "$NAT_CHAIN"

# NAT rules: redirect all TCP to envoy (but not if already going to envoy)
iptables -t nat -A "$NAT_CHAIN" -d "$ENVOY_IP" -j RETURN
iptables -t nat -A "$NAT_CHAIN" -p tcp -j DNAT --to-destination "$ENVOY_IP:443"

# Insert into PREROUTING for traffic from sandbox
iptables -t nat -I PREROUTING -s "$SANDBOX_IP" -j "$NAT_CHAIN"

# MASQUERADE for hairpin NAT (so replies go back through NAT)
iptables -t nat -A POSTROUTING -s "$SANDBOX_IP" -d "$ENVOY_IP" -j MASQUERADE

# Create filter chain for DROP rules
iptables -N "$FILTER_CHAIN" 2>/dev/null || iptables -F "$FILTER_CHAIN"

# Filter rules: allow DNS, envoy, established; drop rest
iptables -A "$FILTER_CHAIN" -d "$ENVOY_IP" -j ACCEPT
iptables -A "$FILTER_CHAIN" -p udp --dport 53 -j ACCEPT
iptables -A "$FILTER_CHAIN" -p tcp --dport 53 -j ACCEPT
iptables -A "$FILTER_CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A "$FILTER_CHAIN" -j DROP

# Insert into FORWARD for traffic from sandbox
iptables -I FORWARD -s "$SANDBOX_IP" -j "$FILTER_CHAIN"

echo "Host iptables configured. Waiting for shutdown signal..."
exec sleep infinity
