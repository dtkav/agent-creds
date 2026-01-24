FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Build args for user creation (defaults match common Linux setups)
ARG USER_UID=1000
ARG USER_GID=1000

# Install base dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    ca-certificates \
    python3 \
    python3-pip \
    nodejs \
    npm \
    sudo \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Create user with matching UID/GID
RUN groupadd --gid $USER_GID --force devuser || true \
    && useradd --uid $USER_UID --gid $USER_GID -m devuser 2>/dev/null \
    || usermod -l devuser -d /home/devuser -m ubuntu 2>/dev/null || true \
    && echo "devuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Copy CA cert and add to system trust store
COPY generated/certs/ca.crt /usr/local/share/ca-certificates/agent-creds-ca.crt
RUN update-ca-certificates

# Copy hosts file for runtime
COPY generated/hosts /etc/proxy-hosts

# Copy aenv binary and config
COPY generated/aenv /usr/local/bin/aenv
COPY generated/domains.json /etc/aenv/domains.json

# Copy entrypoint
COPY claude-dev/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create overlay directories
RUN mkdir -p /src-ro /src-upper /src-work /workspace \
    && chown devuser:devuser /src-upper /src-work /workspace

# Switch to user
USER devuser
ENV HOME=/home/devuser
WORKDIR /workspace

# Node.js also needs to trust the CA
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/agent-creds-ca.crt

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
