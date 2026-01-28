#!/bin/sh
set -e

# Resolve envoy IPv4 and IPv6 addresses
PROXY_IP4=$(getent ahostsv4 envoy | head -1 | awk '{print $1}')
PROXY_IP6=$(getent ahostsv6 envoy | head -1 | awk '{print $1}')

if [ -z "$PROXY_IP4" ] && [ -z "$PROXY_IP6" ]; then
    echo "ERROR: Could not resolve 'envoy' hostname"
    exit 1
fi

echo "Setting up firewall: DNS allowed, :443 -> envoy (v4=$PROXY_IP4 v6=$PROXY_IP6), rest dropped"

# --- IPv4 rules ---
if [ -n "$PROXY_IP4" ]; then
    iptables -t nat -A OUTPUT -p tcp --dport 443 -d "$PROXY_IP4" -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$PROXY_IP4:443"
fi

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
[ -n "$PROXY_IP4" ] && iptables -A OUTPUT -d "$PROXY_IP4" -j ACCEPT
iptables -A OUTPUT -j DROP

# --- IPv6 rules ---
if [ -n "$PROXY_IP6" ]; then
    ip6tables -t nat -A OUTPUT -p tcp --dport 443 -d "$PROXY_IP6" -j ACCEPT
    ip6tables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "[$PROXY_IP6]:443"
fi

ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT
ip6tables -A OUTPUT -p tcp --dport 53 -j ACCEPT
[ -n "$PROXY_IP6" ] && ip6tables -A OUTPUT -d "$PROXY_IP6" -j ACCEPT
ip6tables -A OUTPUT -j DROP

echo "Firewall configured. Sleeping..."
exec sleep infinity
