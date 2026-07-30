#!/usr/bin/env bash
# Bridge 127.0.0.1:10000 to a running adev instance's envoy CONNECT
# listener, so host-side clients (Claude Code's sandbox egress) reach it
# without publishing container ports.
#
#   envoy-forward.sh <instance>     e.g. envoy-forward.sh myproject
set -euo pipefail

INSTANCE="${1:?usage: envoy-forward.sh <adev-instance-name>}"
PORT="${ENVOY_FORWARD_PORT:-10000}"

IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "adev-${INSTANCE}-envoy" 2>/dev/null | awk '{print $1}')
[ -n "$IP" ] || { echo "no running envoy for instance '$INSTANCE'" >&2; exit 1; }

echo "forwarding 127.0.0.1:${PORT} -> ${IP}:10000 (adev-${INSTANCE}-envoy)"
exec socat "TCP-LISTEN:${PORT},bind=127.0.0.1,fork,reuseaddr" "TCP:${IP}:10000"
