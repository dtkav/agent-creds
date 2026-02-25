#!/usr/bin/env bash
set -euo pipefail

# Build sandbox image using Nix inside Docker

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_NAME="${1:-sandbox-local}"
NIX_IMAGE="nixos/nix:2.24.10"

# Build Go binaries first (added as Docker layer after Nix build)
# CGO_ENABLED=0 produces static binaries (no /lib64/ld-linux-x86-64.so.2 needed)
echo "Building Go binaries..."
(cd "$PROJECT_DIR/cmd/aenv" && CGO_ENABLED=0 go build -o ../../generated/aenv .)
(cd "$PROJECT_DIR/cmd/cdp-proxy" && CGO_ENABLED=0 go build -o ../../generated/cdp-proxy .)
(cd "$PROJECT_DIR/cmd/tcp-bridge" && CGO_ENABLED=0 go build -o ../../generated/tcp-bridge .)

# Create/reuse persistent Nix store volume for caching
docker volume create nix-store 2>/dev/null || true

echo "Building base image with Nix..."

# Build Nix image and load it
docker run --rm \
  -v nix-store:/nix \
  -v "$PROJECT_DIR":/src:ro \
  "$NIX_IMAGE" \
  sh -c '
    # Enable flakes
    mkdir -p ~/.config/nix
    echo "experimental-features = nix-command flakes" > ~/.config/nix/nix.conf

    # Copy source to a clean directory (avoids dirty git tree issues)
    cp -r /src /workspace
    cd /workspace

    # Initialize git if needed (flakes require git)
    git init -q 2>/dev/null || true
    git add -A 2>/dev/null || true
    # Force-add generated/packages.nix even though generated/ is gitignored
    git add -f generated/packages.nix 2>/dev/null || true

    # Build the image and stream it to stdout
    nix build .#sandbox --no-link --print-out-paths | xargs cat
  ' | docker load

# Add Go binaries and fix permissions as a layer
echo "Adding Go binaries layer..."
cat > /tmp/Dockerfile.binaries << 'EOF'
FROM sandbox:latest
USER root
# Fix /tmp permissions and set sudo setuid (Nix store is immutable, setuid must be set in a Docker layer)
RUN chmod 1777 /tmp && chmod u+s $(readlink -f $(which sudo))
COPY generated/aenv /usr/local/bin/aenv
COPY generated/cdp-proxy /usr/local/bin/cdp-proxy
COPY generated/tcp-bridge /usr/local/bin/tcp-bridge
EOF

docker build -t "$IMAGE_NAME" -f /tmp/Dockerfile.binaries "$PROJECT_DIR"

echo "Done! Image available as: $IMAGE_NAME"
