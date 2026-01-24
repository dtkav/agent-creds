#!/bin/bash
set -e

# Set up overlay filesystem if source is mounted
if [ -d /src-ro ] && [ "$(ls -A /src-ro 2>/dev/null)" ]; then
    sudo mount -t overlay overlay \
        -o lowerdir=/src-ro,upperdir=/src-upper,workdir=/src-work \
        /workspace
    echo "Overlay mounted: changes will be written to /src-upper"
fi

# Add hosts entries for proxied domains
if [ -f /etc/proxy-hosts ]; then
    # Get the proxy hostname from the first non-comment line
    PROXY_HOST=$(grep -v '^#' /etc/proxy-hosts | head -1 | awk '{print $1}')

    if [ -z "$PROXY_HOST" ]; then
        echo "WARNING: No proxy host found in /etc/proxy-hosts"
    elif echo "$PROXY_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        # Already an IPv4 address, use directly
        sudo sh -c "cat /etc/proxy-hosts >> /etc/hosts"
    elif echo "$PROXY_HOST" | grep -qE '^[0-9a-fA-F:]+$'; then
        # Already an IPv6 address, use directly
        sudo sh -c "cat /etc/proxy-hosts >> /etc/hosts"
    else
        # Hostname - need to resolve it first
        PROXY_IP=$(getent hosts "$PROXY_HOST" 2>/dev/null | head -1 | awk '{print $1}')
        if [ -z "$PROXY_IP" ]; then
            PROXY_IP=$(dig +short "$PROXY_HOST" A 2>/dev/null | head -1)
        fi
        if [ -z "$PROXY_IP" ]; then
            PROXY_IP=$(dig +short "$PROXY_HOST" AAAA 2>/dev/null | head -1)
        fi

        if [ -n "$PROXY_IP" ]; then
            sudo sh -c "sed 's/^${PROXY_HOST}/${PROXY_IP}/g' /etc/proxy-hosts >> /etc/hosts"
        else
            echo "WARNING: Could not resolve $PROXY_HOST"
        fi
    fi
fi

# Show MOTD
aenv

# Execute the main command
exec "$@"
