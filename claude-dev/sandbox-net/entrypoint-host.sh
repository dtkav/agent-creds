#!/bin/sh
set -e

# Host-mode sandbox-net: sets up iptables on the host to route traffic from sandbox to envoy
# Usage: entrypoint-host.sh <subnet> <envoy-ip> <chain-name> <gateway-ip> [<subnet6> <envoy-ip6> <gateway-ip6>]
#
# This script runs in a container with --network=host --cap-add=NET_ADMIN
# It modifies the HOST's iptables (IPv4 and IPv6) to redirect traffic from the sandbox subnet.

SUBNET="$1"
ENVOY_IP="$2"
CHAIN_NAME="$3"
GATEWAY_IP="$4"
SUBNET6="$5"
ENVOY_IP6="$6"
GATEWAY_IP6="$7"

if [ -z "$SUBNET" ] || [ -z "$ENVOY_IP" ] || [ -z "$CHAIN_NAME" ] || [ -z "$GATEWAY_IP" ]; then
    echo "Usage: $0 <subnet> <envoy-ip> <chain-name> <gateway-ip> [<subnet6> <envoy-ip6> <gateway-ip6>]"
    exit 1
fi

NAT_CHAIN="${CHAIN_NAME}-NAT"
FILTER_CHAIN="${CHAIN_NAME}-FILTER"
NAT6_CHAIN="${CHAIN_NAME}-NAT6"
FILTER6_CHAIN="${CHAIN_NAME}-FILTER6"

echo "Setting up host iptables: subnet=$SUBNET envoy=$ENVOY_IP gateway=$GATEWAY_IP chain=$CHAIN_NAME"
[ -n "$SUBNET6" ] && echo "  IPv6: subnet6=$SUBNET6 envoy6=$ENVOY_IP6 gateway6=$GATEWAY_IP6"

# Remove ALL references to our chains (from previous runs where cleanup didn't run).
# Previous runs may have used different subnets/IPs, so we purge by chain name target,
# not by source address. Uses line-number deletion (always deleting the first match,
# re-scanning after each delete since line numbers shift).
purge_stale() {
    # IPv4: remove all PREROUTING rules jumping to our NAT chain
    while true; do
        line=$(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep " $NAT_CHAIN " | head -1 | awk '{print $1}')
        [ -z "$line" ] && break
        iptables -t nat -D PREROUTING "$line" 2>/dev/null || break
    done
    # IPv4: remove all FORWARD rules jumping to our FILTER chain
    while true; do
        line=$(iptables -L FORWARD --line-numbers -n 2>/dev/null | grep " $FILTER_CHAIN " | head -1 | awk '{print $1}')
        [ -z "$line" ] && break
        iptables -D FORWARD "$line" 2>/dev/null || break
    done
    # Flush and delete our custom chains (also clears POSTROUTING/FORWARD ACCEPT via -D below)
    iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
    iptables -F "$FILTER_CHAIN" 2>/dev/null || true
    iptables -X "$FILTER_CHAIN" 2>/dev/null || true
    # Clean up POSTROUTING and FORWARD ACCEPT rules (best-effort with current IPs)
    while iptables -t nat -D POSTROUTING -s "$SUBNET" -d "$ENVOY_IP" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -D FORWARD -s "$ENVOY_IP" -j ACCEPT 2>/dev/null; do :; done

    # IPv6: same logic
    while true; do
        line=$(ip6tables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep " $NAT6_CHAIN " | head -1 | awk '{print $1}')
        [ -z "$line" ] && break
        ip6tables -t nat -D PREROUTING "$line" 2>/dev/null || break
    done
    while true; do
        line=$(ip6tables -L FORWARD --line-numbers -n 2>/dev/null | grep " $FILTER6_CHAIN " | head -1 | awk '{print $1}')
        [ -z "$line" ] && break
        ip6tables -D FORWARD "$line" 2>/dev/null || break
    done
    ip6tables -t nat -F "$NAT6_CHAIN" 2>/dev/null || true
    ip6tables -t nat -X "$NAT6_CHAIN" 2>/dev/null || true
    ip6tables -F "$FILTER6_CHAIN" 2>/dev/null || true
    ip6tables -X "$FILTER6_CHAIN" 2>/dev/null || true
    while ip6tables -t nat -D POSTROUTING -s "$SUBNET6" -d "$ENVOY_IP6" -j MASQUERADE 2>/dev/null; do :; done
    while ip6tables -D FORWARD -s "$ENVOY_IP6" -j ACCEPT 2>/dev/null; do :; done
}

purge_stale

cleanup() {
    echo "Cleaning up iptables rules..."
    # Reuse purge_stale — it removes all references to our chains
    purge_stale
    echo "Cleanup complete"
}

# Clean up on exit
trap cleanup EXIT INT TERM

# ---- IPv4 ----

# Create NAT chain for DNAT rules
iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || iptables -t nat -F "$NAT_CHAIN"

# NAT rules: redirect sandbox TCP to envoy
# Skip DNAT for envoy's own outbound traffic (prevents loop: envoy is also on the subnet)
iptables -t nat -A "$NAT_CHAIN" -s "$ENVOY_IP" -j RETURN
iptables -t nat -A "$NAT_CHAIN" -d "$ENVOY_IP" -j RETURN
iptables -t nat -A "$NAT_CHAIN" -d "$GATEWAY_IP" -j RETURN
iptables -t nat -A "$NAT_CHAIN" -p tcp -j DNAT --to-destination "$ENVOY_IP:443"

# Insert into PREROUTING for traffic from sandbox subnet
iptables -t nat -I PREROUTING -s "$SUBNET" -j "$NAT_CHAIN"

# MASQUERADE for hairpin NAT (so replies go back through NAT)
iptables -t nat -A POSTROUTING -s "$SUBNET" -d "$ENVOY_IP" -j MASQUERADE

# Create filter chain for DROP rules
iptables -N "$FILTER_CHAIN" 2>/dev/null || iptables -F "$FILTER_CHAIN"

# Filter rules: allow gateway (for browser/cdp forward), DNS, envoy, established; drop rest
iptables -A "$FILTER_CHAIN" -d "$GATEWAY_IP" -j ACCEPT
iptables -A "$FILTER_CHAIN" -d "$ENVOY_IP" -j ACCEPT
iptables -A "$FILTER_CHAIN" -p udp --dport 53 -j ACCEPT
iptables -A "$FILTER_CHAIN" -p tcp --dport 53 -j ACCEPT
iptables -A "$FILTER_CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A "$FILTER_CHAIN" -j DROP

# Insert into FORWARD for subnet (pos 1), then insert envoy ACCEPT (pos 1, pushing subnet to pos 2).
# Result: [envoy→ACCEPT, subnet→FILTER_CHAIN]
# Envoy's outbound traffic hits ACCEPT before FILTER_CHAIN (envoy proxies to external APIs).
iptables -I FORWARD -s "$SUBNET" -j "$FILTER_CHAIN"
iptables -I FORWARD -s "$ENVOY_IP" -j ACCEPT

# ---- IPv6 (parallel path, same logic) ----

if [ -n "$SUBNET6" ] && [ -n "$ENVOY_IP6" ]; then
    ip6tables -t nat -N "$NAT6_CHAIN" 2>/dev/null || ip6tables -t nat -F "$NAT6_CHAIN"

    ip6tables -t nat -A "$NAT6_CHAIN" -s "$ENVOY_IP6" -j RETURN
    ip6tables -t nat -A "$NAT6_CHAIN" -d "$ENVOY_IP6" -j RETURN
    [ -n "$GATEWAY_IP6" ] && ip6tables -t nat -A "$NAT6_CHAIN" -d "$GATEWAY_IP6" -j RETURN
    ip6tables -t nat -A "$NAT6_CHAIN" -p tcp -j DNAT --to-destination "[$ENVOY_IP6]:443"

    ip6tables -t nat -I PREROUTING -s "$SUBNET6" -j "$NAT6_CHAIN"
    ip6tables -t nat -A POSTROUTING -s "$SUBNET6" -d "$ENVOY_IP6" -j MASQUERADE

    ip6tables -N "$FILTER6_CHAIN" 2>/dev/null || ip6tables -F "$FILTER6_CHAIN"
    [ -n "$GATEWAY_IP6" ] && ip6tables -A "$FILTER6_CHAIN" -d "$GATEWAY_IP6" -j ACCEPT
    ip6tables -A "$FILTER6_CHAIN" -d "$ENVOY_IP6" -j ACCEPT
    ip6tables -A "$FILTER6_CHAIN" -p udp --dport 53 -j ACCEPT
    ip6tables -A "$FILTER6_CHAIN" -p tcp --dport 53 -j ACCEPT
    ip6tables -A "$FILTER6_CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A "$FILTER6_CHAIN" -j DROP

    ip6tables -I FORWARD -s "$SUBNET6" -j "$FILTER6_CHAIN"
    ip6tables -I FORWARD -s "$ENVOY_IP6" -j ACCEPT
fi

echo "Host iptables configured. Waiting for shutdown signal..."
exec sleep infinity
