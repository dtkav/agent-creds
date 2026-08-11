#!/bin/sh
set -eu

source_dir=${1:?source directory is required}
workspace_dir=${2:?workspace directory is required}

mkdir -p "$workspace_dir"

# generated/ contains live runtime state (including Unix sockets, logs, and
# credentials) that is neither a valid Nix flake input nor needed to build the
# sandbox environment. Preserve dirty source files, but exclude Git metadata
# and copy only the generated package expression consumed by flake.nix.
find "$source_dir" -mindepth 1 -maxdepth 1 \
    ! -name .git \
    ! -name generated \
    -exec cp -a {} "$workspace_dir/" \;

mkdir -p "$workspace_dir/generated"
cp "$source_dir/generated/packages.nix" "$workspace_dir/generated/packages.nix"
