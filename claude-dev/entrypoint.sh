#!/bin/bash
set -e

export PATH="$HOME/.local/bin:$PATH"
export TERM=xterm-256color

# Update CA certificates if mounted (allows hot-reload without rebuild)
if [ -f /usr/local/share/ca-certificates/agent-creds-ca.crt ]; then
    sudo update-ca-certificates 2>/dev/null || true
fi

# Set up overlay filesystem if source is mounted
if [ -d /src-ro ] && [ "$(ls -A /src-ro 2>/dev/null)" ]; then
    sudo mount -t overlay overlay \
        -o lowerdir=/src-ro,upperdir=/src-upper,workdir=/src-work \
        /workspace
fi

# Session name
SESSION="${ABDUCO_SESSION:-claude}"

# Create bash init that launches claude
cat > /tmp/claude-init.sh << 'EOF'
# Prevent terminal escape sequence queries
export TERM=xterm-256color
export COLORTERM=truecolor
export TERM_PROGRAM=""

# Source normal bashrc for prompt, aliases, etc (but not in login mode to skip some queries)
[ -f ~/.bashrc ] && source ~/.bashrc

export PATH="$HOME/.local/bin:$PATH"
cd /workspace

# Show MOTD
aenv

# Launch claude
claude
EOF

# Session runs interactive bash with our init
cat > /tmp/claude-session << 'EOF'
#!/bin/bash
exec bash --init-file /tmp/claude-init.sh
EOF
chmod +x /tmp/claude-session

# Interactive: use abduco for session management
# Detach with Ctrl-\ (keeps Ctrl-A/Ctrl-Q for claude)
if [ -t 0 ]; then
    exec abduco -A -e '^\' "$SESSION" /tmp/claude-session
else
    # Non-interactive: run command directly
    exec "$@"
fi
