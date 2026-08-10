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
        set -eu

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
    local env_key="${1:-0000000000000000}"
    case "$env_key" in
        *[!0-9a-f]*|'')
            echo "invalid sandbox env cache key: $env_key" >&2
            exit 2
            ;;
    esac
    if [ "${#env_key}" -ne 16 ]; then
        echo "invalid sandbox env cache key length: $env_key" >&2
        exit 2
    fi

    # Each environment is a real, self-contained chroot Nix store. Mounting
    # that store as /nix/store keeps absolute store symlinks valid without
    # exposing the host's global store or copying paths out of a build store.
    local private_root="$NIX_DIR/envs/$env_key"
    mkdir -p "$private_root/nix/store" "$private_root/nix/var/nix" \
        "$NIX_DIR/var/nix/stores"

    echo "Building sandbox env into host Nix store..." >&2

    # The image keeps its own /nix store so the Nix CLI can run. --store points
    # the build at the separately mounted chroot store owned by this env key.
    docker volume create nix-store 2>/dev/null || true

    local env_path
    env_path=$(docker run --rm \
      -v nix-store:/nix \
      -v "$NIX_DIR":/agent-creds-nix \
      -v "$PROJECT_DIR":/src:ro \
      -e "AGENT_CREDS_ENV_KEY=$env_key" \
      "$NIX_IMAGE" \
      sh -c '
        set -eu

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

        private_root="/agent-creds-nix/envs/$AGENT_CREDS_ENV_KEY"
        env_path=$(nix build --store "$private_root" \
          .#sandbox-env --no-link --print-out-paths)

        # Querying the same store proves the output and its references were
        # registered there. Lstat semantics matter: sandbox-env may itself be
        # an absolute symlink that resolves only after the store is mounted at
        # its logical /nix/store location.
        nix path-info --store "$private_root" --recursive "$env_path" >/dev/null
        physical="$private_root$env_path"
        test -e "$physical" || test -L "$physical" || {
            echo "sandbox env was not built into private store: $env_path" >&2
            exit 1
        }

        store_dir=/agent-creds-nix/var/nix/stores
        store_file="$store_dir/$(basename "$env_path").store"
        store_tmp="$store_file.tmp.$$"
        mkdir -p "$store_dir"
        printf "%s\n" "$AGENT_CREDS_ENV_KEY" > "$store_tmp"
        chmod 0644 "$store_tmp"
        mv "$store_tmp" "$store_file"

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
        build_env "${2:-0000000000000000}"
        ;;
    all)
        build_base "${2:-sandbox-base}"
        build_env "${3:-0000000000000000}"
        ;;
    *)
        echo "Usage: $0 base [image-name] | env [cache-key] | all [image-name] [cache-key]" >&2
        exit 1
        ;;
esac
