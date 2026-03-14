#!/bin/sh
# Runs as root (gVisor doesn't honor setuid — dropbear needs root for PTY allocation).
# s6-svscan supervises dropbear (SSH), tcp-bridge, and cdp-proxy.
# SSH sessions run as devuser (dropbear handles user switching).
#
# Two modes:
# 1. SANDBOX_ENV set: base image is a thin skeleton (busybox only). All packages
#    live in $SANDBOX_ENV, a Nix buildEnv store path mounted from host at /nix.
# 2. SANDBOX_ENV unset: registry image with packages baked in (legacy).
set -e

# --- Bootstrap from $SANDBOX_ENV (local Nix builds only) ---
if [ -n "$SANDBOX_ENV" ]; then
    # The base image has only busybox. Create symlinks and config files pointing
    # to the real packages in the mounted Nix store.

    # /bin/bash — needed by everything (s6 run scripts, .bashrc, interactive shells)
    ln -sf "$SANDBOX_ENV/bin/bash" /bin/bash

    # /etc/shells: dropbear validates user shells against this list.
    # Without it, dropbear rejects logins with "invalid shell".
    printf '%s\n' "$SANDBOX_ENV/bin/bash" "/bin/bash" "/bin/sh" > /etc/shells

    # PAM config for sudo: pam_permit allows everything (dev sandbox, no real auth needed).
    # Use full store paths since /lib/security/ doesn't exist in the base image.
    pamlib="$SANDBOX_ENV/lib/security"
    mkdir -p /etc/pam.d
    printf 'auth     sufficient %s/pam_permit.so\naccount  sufficient %s/pam_permit.so\nsession  sufficient %s/pam_permit.so\n' \
        "$pamlib" "$pamlib" "$pamlib" > /etc/pam.d/sudo

    # bash-completion: symlink to stable path sourced by .bashrc
    ln -sf "$SANDBOX_ENV/share/bash-completion/bash_completion" /etc/bash_completion

    # sudo: Nix store is read-only, can't set setuid there. Copy to writable location.
    cp "$SANDBOX_ENV/bin/sudo" /usr/local/bin/sudo
    chmod u+s /usr/local/bin/sudo

    # sudoers: copy from the env so sudo can find its config
    cp "$SANDBOX_ENV/etc/sudoers" /etc/sudoers 2>/dev/null || true
    chmod 440 /etc/sudoers 2>/dev/null || true

    # Set environment from $SANDBOX_ENV
    export PATH="$SANDBOX_ENV/bin:/usr/local/bin:/bin:/usr/bin:/home/devuser/.local/bin:/home/devuser/.cargo/bin:/home/devuser/go/bin"
    export TERMINFO_DIRS="$SANDBOX_ENV/share/terminfo:/usr/share/terminfo"
    export XDG_DATA_DIRS="$SANDBOX_ENV/share:/usr/share:/share"
    export SSL_CERT_FILE="$SANDBOX_ENV/etc/ssl/certs/ca-bundle.crt"
    export NIX_SSL_CERT_FILE="$SANDBOX_ENV/etc/ssl/certs/ca-bundle.crt"
fi

export TERM=xterm-256color
export COLORTERM=truecolor

# --- Export env vars for SSH sessions ---
# dropbear creates a clean environment, so SSH shells lose all env vars above.
# Write them to /tmp/adev-env.sh which .bashrc sources.
{
    for var in PATH TERMINFO_DIRS XDG_DATA_DIRS SSL_CERT_FILE NIX_SSL_CERT_FILE SANDBOX_ENV COLORTERM BROWSER TCP_BROWSER_PORT CDP_PORT_MAP NODE_EXTRA_CA_CERTS; do
        eval "val=\${$var:-}"
        [ -n "$val" ] && printf 'export %s="%s"\n' "$var" "$val"
    done
} > /tmp/adev-env.sh

# Build combined CA bundle so tools (including Node.js) trust the proxy CA.
# Overrides SSL_CERT_FILE/NIX_SSL_CERT_FILE written above.
if [ -f /etc/ssl/agent-creds-ca.crt ] && [ -n "$SSL_CERT_FILE" ]; then
    cat "$SSL_CERT_FILE" /etc/ssl/agent-creds-ca.crt > /tmp/ca-bundle.crt
    cat >> /tmp/adev-env.sh <<'CAEOF'
export SSL_CERT_FILE=/tmp/ca-bundle.crt
export NIX_SSL_CERT_FILE=/tmp/ca-bundle.crt
export NODE_OPTIONS="--use-openssl-ca"
export REQUESTS_CA_BUNDLE=/tmp/ca-bundle.crt
export PIP_CERT=/tmp/ca-bundle.crt
export CURL_CA_BUNDLE=/tmp/ca-bundle.crt
CAEOF
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

# tcp-bridge: only if TCP_BROWSER_PORT or CDP_PORT_MAP is set
if [ -n "${TCP_BROWSER_PORT:-}" ] || [ -n "${CDP_PORT_MAP:-}" ]; then
    mkdir -p "$S6DIR/tcp-bridge"
    cat > "$S6DIR/tcp-bridge/run" <<'EOF'
#!/bin/bash
exec tcp-bridge 2>&1
EOF
    chmod +x "$S6DIR/tcp-bridge/run"
fi

# cdp-proxy: only if CDP_PORT_MAP is set (tcp-bridge creates the sockets)
if [ -n "${CDP_PORT_MAP:-}" ]; then
    mkdir -p "$S6DIR/cdp-proxy"
    cat > "$S6DIR/cdp-proxy/run" <<'PROXYEOF'
#!/bin/bash
# Wait for tcp-bridge to create at least one CDP socket
while ! ls /tmp/cdp-*.sock >/dev/null 2>&1; do
    sleep 0.2
done
exec cdp-proxy 2>&1
PROXYEOF
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
