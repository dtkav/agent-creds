#!/bin/bash
# Runs as root (gVisor doesn't honor setuid — dropbear needs root for PTY allocation).
# s6-svscan supervises dropbear (SSH), tcp-bridge, and cdp-proxy.
# SSH sessions run as devuser (dropbear handles user switching).
set -e

export TERM=xterm-256color
export COLORTERM=truecolor

# --- One-time setup (runs before s6 takes over as PID 1) ---

# Export container env vars for SSH sessions.
# dropbear creates a clean environment, so SSH shells lose Docker-level env vars.
# Write them to /tmp/adev-env.sh which .bashrc sources.
{
    # Env vars set by Docker (flake.nix config.Env) that SSH sessions need
    for var in TERMINFO_DIRS XDG_DATA_DIRS SSL_CERT_FILE NIX_SSL_CERT_FILE NODE_EXTRA_CA_CERTS COLORTERM BROWSER TCP_BROWSER_PORT TCP_CDP_PORT CDP_PORT; do
        val="${!var:-}"
        [ -n "$val" ] && printf 'export %s="%s"\n' "$var" "$val"
    done
} > /tmp/adev-env.sh

# Build combined CA bundle so tools (including Node.js) trust the proxy CA.
# Overrides SSL_CERT_FILE/NIX_SSL_CERT_FILE written above.
SSL_CERT_FILE="${SSL_CERT_FILE:-}"
if [ -f /etc/ssl/agent-creds-ca.crt ] && [ -n "$SSL_CERT_FILE" ]; then
    cat "$SSL_CERT_FILE" /etc/ssl/agent-creds-ca.crt > /tmp/ca-bundle.crt
    printf 'export SSL_CERT_FILE=/tmp/ca-bundle.crt\nexport NIX_SSL_CERT_FILE=/tmp/ca-bundle.crt\nexport NODE_OPTIONS="--use-openssl-ca"\n' \
        >> /tmp/adev-env.sh
fi

# Generate dropbear host key
mkdir -p /tmp/dropbear
if [ ! -f /tmp/dropbear/dropbear_ed25519_host_key ]; then
    dropbearkey -t ed25519 -f /tmp/dropbear/dropbear_ed25519_host_key 2>/dev/null
fi

# Install authorized key from host (mounted at /etc/adev/pubkey by console.go)
if [ -f /etc/adev/pubkey ]; then
    mkdir -p /home/devuser/.ssh
    chmod 700 /home/devuser/.ssh
    cp /etc/adev/pubkey /home/devuser/.ssh/authorized_keys
    chmod 600 /home/devuser/.ssh/authorized_keys
    chown -R devuser:devuser /home/devuser/.ssh
fi

# --- Create s6 service directory tree ---

S6DIR=/run/s6/services
mkdir -p "$S6DIR"

# dropbear: SSH server on port 2222 (runs as root for PTY allocation, sessions are devuser)
mkdir -p "$S6DIR/dropbear"
cat > "$S6DIR/dropbear/run" <<'EOF'
#!/bin/bash
exec dropbear -F -E -s -g -p 2222 \
    -r /tmp/dropbear/dropbear_ed25519_host_key \
    -w -j -k 2>&1
EOF
chmod +x "$S6DIR/dropbear/run"

# tcp-bridge: only if TCP_BROWSER_PORT or TCP_CDP_PORT is set
if [ -n "${TCP_BROWSER_PORT:-}" ] || [ -n "${TCP_CDP_PORT:-}" ]; then
    mkdir -p "$S6DIR/tcp-bridge"
    cat > "$S6DIR/tcp-bridge/run" <<'EOF'
#!/bin/bash
exec tcp-bridge 2>&1
EOF
    chmod +x "$S6DIR/tcp-bridge/run"
fi

# cdp-proxy: only if tcp-bridge is running (creates the socket)
if [ -n "${TCP_CDP_PORT:-}" ]; then
    mkdir -p "$S6DIR/cdp-proxy"
    cat > "$S6DIR/cdp-proxy/run" <<'EOF'
#!/bin/bash
# Wait for tcp-bridge to create the socket
while [ ! -S /tmp/cdp-forward.sock ] && [ ! -S /run/cdp-forward.sock ]; do
    sleep 0.2
done
exec cdp-proxy 2>&1
EOF
    chmod +x "$S6DIR/cdp-proxy/run"
fi

mkdir -p "$S6DIR/.s6-svscan"
cat > "$S6DIR/.s6-svscan/finish" <<'EOF'
#!/bin/bash
exec true
EOF
chmod +x "$S6DIR/.s6-svscan/finish"

# Signal readiness after a brief delay (dropbear needs a moment to bind)
(sleep 0.5; touch /tmp/adev-ready) &

# --- Hand off to s6 ---
exec s6-svscan "$S6DIR"
