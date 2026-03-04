#!/bin/sh
set -e

# Resolve envoy addresses using getent (more reliable with Docker's embedded DNS)
# getent returns lines like: "172.26.0.2  envoy" or "fd42:...::2  envoy"
PROXY_IP4=$(getent ahostsv4 envoy 2>/dev/null | awk '{print $1; exit}')
PROXY_IP6=$(getent ahostsv6 envoy 2>/dev/null | awk '{print $1; exit}')

if [ -z "$PROXY_IP4" ] && [ -z "$PROXY_IP6" ]; then
    echo "ERROR: Could not resolve 'envoy' hostname"
    exit 1
fi

echo "Setting up firewall: :443 + :53 -> envoy (v4=$PROXY_IP4 v6=$PROXY_IP6), rest dropped"

# --- IPv4 rules ---
if [ -n "$PROXY_IP4" ]; then
    # DNAT port 443 (HTTPS) to envoy
    iptables -t nat -A OUTPUT -p tcp --dport 443 -d "$PROXY_IP4" -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$PROXY_IP4:443"
    # DNAT port 53 (DNS) to envoy (dns-responder runs there)
    iptables -t nat -A OUTPUT -p udp --dport 53 -d "$PROXY_IP4" -j ACCEPT
    iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination "$PROXY_IP4:53"
    iptables -t nat -A OUTPUT -p tcp --dport 53 -d "$PROXY_IP4" -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to-destination "$PROXY_IP4:53"
fi

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
[ -n "$PROXY_IP4" ] && iptables -A OUTPUT -d "$PROXY_IP4" -j ACCEPT
iptables -A OUTPUT -j DROP

# --- IPv6 rules ---
if [ -n "$PROXY_IP6" ]; then
    # DNAT port 443 (HTTPS) to envoy
    ip6tables -t nat -A OUTPUT -p tcp --dport 443 -d "$PROXY_IP6" -j ACCEPT
    ip6tables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "[$PROXY_IP6]:443"
    # DNAT port 53 (DNS) to envoy (dns-responder runs there)
    ip6tables -t nat -A OUTPUT -p udp --dport 53 -d "$PROXY_IP6" -j ACCEPT
    ip6tables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination "[$PROXY_IP6]:53"
    ip6tables -t nat -A OUTPUT -p tcp --dport 53 -d "$PROXY_IP6" -j ACCEPT
    ip6tables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to-destination "[$PROXY_IP6]:53"
fi

ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
[ -n "$PROXY_IP6" ] && ip6tables -A OUTPUT -d "$PROXY_IP6" -j ACCEPT
ip6tables -A OUTPUT -j DROP

echo "Firewall configured. Sleeping..."
exec sleep infinity
