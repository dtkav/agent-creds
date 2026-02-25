#!/usr/bin/env bash
set -euo pipefail

# Build sandbox components using Nix inside Docker.
#
# Subcommands:
#   base  - Build sandbox-base Docker image (thin skeleton, no packages)
#   env   - Build sandbox-env into host Nix store (all packages)
#   (no args) - Build both

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

NIX_IMAGE="nixos/nix:2.24.10"
NIX_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/agent-creds/nix"

build_base() {
    local image_name="${1:-sandbox-base}"

    # Go binaries (aenv, cdp-proxy, tcp-bridge) must exist in generated/ before
    # running this script. When called from adev, build.go handles this.
    # When called standalone (make build-nix-base), build them if missing.
    for bin in aenv cdp-proxy tcp-bridge; do
        if [ ! -f "$PROJECT_DIR/generated/$bin" ]; then
            echo "Building Go binary: $bin..."
            (cd "$PROJECT_DIR/cmd/$bin" && CGO_ENABLED=0 go build -o "../../generated/$bin" .)
        fi
    done

    # Create/reuse throwaway Nix store volume (just for building the image tarball)
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

        # Build the base image and stream it to stdout
        nix build .#sandbox-base --no-link --print-out-paths | xargs cat
      ' | docker load

    # Add Go binaries and fix permissions as a layer
    echo "Adding Go binaries layer..."
    cat > /tmp/Dockerfile.binaries << 'EOF'
FROM sandbox-base:latest
USER root
# Fix /tmp permissions
RUN chmod 1777 /tmp
COPY generated/aenv /usr/local/bin/aenv
COPY generated/cdp-proxy /usr/local/bin/cdp-proxy
COPY generated/tcp-bridge /usr/local/bin/tcp-bridge
EOF

    docker build -t "$image_name" -f /tmp/Dockerfile.binaries "$PROJECT_DIR"

    echo "Done! Base image available as: $image_name"
}

build_env() {
    # Ensure host Nix store directory exists
    mkdir -p "$NIX_DIR/store" "$NIX_DIR/var/nix/profiles"

    echo "Building sandbox env into host Nix store..." >&2

    # We can't mount the host dir directly as /nix during the build because
    # the nixos/nix image needs its own /nix/store to run. Instead:
    # 1. Use the nix-store Docker volume for the build (has nix toolchain cached)
    # 2. Export the env closure and unpack it into the host store
    docker volume create nix-store 2>/dev/null || true

    # Build sandbox-env and copy its closure to the host store.
    # Uses the nix-store Docker volume for the build (has nix toolchain),
    # then copies all required store paths to the host-mounted directory.
    local env_path
    env_path=$(docker run --rm \
      -v nix-store:/nix \
      -v "$NIX_DIR/store":/host-store \
      -v "$NIX_DIR/var":/host-var \
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

        # Build sandbox-env
        env_path=$(nix build .#sandbox-env --no-link --print-out-paths)

        # Copy the full closure to the host store directory.
        # nix-store -qR lists all store paths in the closure.
        for p in $(nix-store -qR "$env_path"); do
            base=$(basename "$p")
            if [ ! -e "/host-store/$base" ]; then
                cp -a "$p" "/host-store/$base"
            fi
        done

        # Create a profile symlink
        mkdir -p /host-var/nix/profiles
        ln -sfn "$env_path" /host-var/nix/profiles/sandbox-env

        echo "$env_path"
      ')

    # Write env path to a file for adev to read
    echo "$env_path" > "$NIX_DIR/current-env"

    echo "Done! Env path: $env_path" >&2
    # Print just the path to stdout for callers to capture
    echo "$env_path"
}

case "${1:-all}" in
    base)
        build_base "${2:-sandbox-base}"
        ;;
    env)
        build_env
        ;;
    all)
        build_base "${2:-sandbox-base}"
        build_env
        ;;
    *)
        echo "Usage: $0 {base|env|all} [image-name]" >&2
        exit 1
        ;;
esac
