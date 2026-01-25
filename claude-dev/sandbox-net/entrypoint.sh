#!/bin/sh
set -e

# Resolve envoy hostname to IP
PROXY_IP=$(getent hosts envoy | head -1 | awk '{print $1}')

if [ -z "$PROXY_IP" ]; then
    echo "ERROR: Could not resolve 'envoy' hostname"
    exit 1
fi

echo "Setting up iptables: redirecting all :443 traffic to envoy ($PROXY_IP)"

# Allow traffic already destined for the proxy (avoid loops)
iptables -t nat -A OUTPUT -p tcp --dport 443 -d "$PROXY_IP" -j ACCEPT

# Redirect all other outbound HTTPS to the proxy
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$PROXY_IP:443"

echo "Transparent proxy configured. Sleeping..."

# Keep the container running (and the network namespace alive)
exec sleep infinity
