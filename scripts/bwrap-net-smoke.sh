#!/usr/bin/env bash
# bwrap-net-smoke.sh — standalone proof of the bwrap runtime's network invariant.
#
# Assembles the same wiring the bwrap backend generates (no adev involved):
#
#   unshare --map-current-user --net --keep-caps     (userns + netns holder)
#     + slirp4netns --userns-path/--netns-type=path  (usermode tap)
#     + host-only route (10.0.2.2/32, NO default route)
#     + nft output filter (envoy port only)
#     + setpriv cap drop -> bwrap (mount sandbox, inherits the netns)
#
# and proves, from INSIDE the sandbox:
#   1. the envoy CONNECT port on the slirp gateway (10.0.2.2 -> host
#      loopback) IS reachable — proxied HTTPS through a live adev envoy
#      when one is running for the selected slug, TCP connect otherwise;
#   2. arbitrary internet (1.1.1.1:443 direct) is NOT reachable;
#   3. non-envoy host loopback ports are NOT reachable (nft layer);
#   4. the slirp builtin DNS (10.0.2.3) is NOT reachable (no DNS tunnel).
#
# Usage: scripts/bwrap-net-smoke.sh [instance-slug]
set -u

SLUG="${1:-smoke}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CA="$SCRIPT_DIR/generated/certs/ca.crt"
PORT=$((20000 + $(python3 -c "
import sys
h = 2166136261
for b in sys.argv[1].encode():
    h = ((h ^ b) * 16777619) & 0xffffffff
print(h % 9000)" "$SLUG")))
WORK="$(mktemp -d /tmp/bwrap-net-smoke.XXXXXX)"
cleanup() {
    kill $(jobs -p) 2>/dev/null
    if [ -f "$WORK/slirp.pid" ]; then kill "$(cat "$WORK/slirp.pid")" 2>/dev/null; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== bwrap network smoke: slug=$SLUG envoy port=$PORT =="

for tool in bwrap slirp4netns unshare setpriv nft python3; do
    command -v "$tool" >/dev/null || { echo "FAIL: missing tool $tool"; exit 1; }
done

# --- host side: publish an envoy-forward on 127.0.0.1:$PORT ------------------
REAL_ENVOY=0
ENVOY_IP="$(docker inspect -f "{{with (index .NetworkSettings.Networks \"adev-$SLUG\")}}{{.IPAddress}}{{end}}" \
    "adev-$SLUG-envoy" 2>/dev/null)"
if [ -n "${ENVOY_IP:-}" ] && command -v socat >/dev/null && [ -f "$CA" ]; then
    REAL_ENVOY=1
    echo "-- using live envoy adev-$SLUG-envoy at $ENVOY_IP:10000 (via socat on 127.0.0.1:$PORT)"
    socat "TCP-LISTEN:$PORT,bind=127.0.0.1,reuseaddr,fork" "TCP:$ENVOY_IP:10000" &
else
    echo "-- no live envoy for '$SLUG'; using a stand-in listener on 127.0.0.1:$PORT"
    python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
fi
sleep 0.5

# --- inner test script (runs inside bwrap, capability-free) ------------------
cat > "$WORK/inner.sh" <<INNER
#!/bin/bash
set -u
pass=0; fail=0
ok()  { echo "  PASS: \$1"; pass=\$((pass+1)); }
bad() { echo "  FAIL: \$1"; fail=\$((fail+1)); }

echo "[inner] uid=\$(id -u) ambient-caps=\$(grep CapAmb /proc/self/status | awk '{print \$2}')"
ip route del 10.0.2.2/32 >/dev/null 2>&1 && bad "agent could modify netns routes" \
    || ok "agent cannot modify netns routes"

if [ "$REAL_ENVOY" = "1" ]; then
    code=\$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 8 \
        --proxy http://10.0.2.2:$PORT --cacert /run/smoke/ca.crt https://api.github.com/zen)
    if [ "\$code" = "200" ]; then
        ok "envoy CONNECT proxy reachable: proxied https://api.github.com/zen -> HTTP \$code (CA-verified TLS bump)"
    else
        bad "proxied request through envoy returned HTTP '\$code'"
    fi
else
    if timeout 5 bash -c "echo > /dev/tcp/10.0.2.2/$PORT" 2>/dev/null; then
        ok "envoy port 10.0.2.2:$PORT reachable (TCP connect to stand-in)"
    else
        bad "envoy port 10.0.2.2:$PORT NOT reachable"
    fi
fi

if timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" 2>/dev/null; then
    bad "direct internet reachable (1.1.1.1:443)"
else
    ok "direct internet unreachable (1.1.1.1:443)"
fi

if timeout 5 bash -c "echo > /dev/tcp/10.0.2.2/631" 2>/dev/null; then
    bad "non-envoy host loopback port reachable (10.0.2.2:631) — nft layer missing"
else
    ok "non-envoy host loopback port blocked (10.0.2.2:631)"
fi

if python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01', ('10.0.2.3', 53))
s.recvfrom(512)" 2>/dev/null; then
    bad "slirp builtin DNS reachable (10.0.2.3) — DNS tunnel possible"
else
    ok "slirp builtin DNS unreachable (10.0.2.3)"
fi

echo "[inner] \$pass passed, \$fail failed"
[ \$fail -eq 0 ]
INNER
chmod +x "$WORK/inner.sh"

# --- netns setup script (ambient caps, same steps as bwrap-setup.sh) ---------
cat > "$WORK/setup.sh" <<SETUP
#!/bin/bash
set -u
for i in \$(seq 1 300); do ip link show tap0 >/dev/null 2>&1 && break; sleep 0.1; done
ip link show tap0 >/dev/null 2>&1 || { echo "FAIL: slirp4netns did not attach"; exit 1; }
ip link set lo up
ip link set tap0 up
ip addr add 10.0.2.100 peer 10.0.2.2/32 dev tap0
nft -f - <<NFT || echo "WARN: nft filter unavailable (route confinement only)"
table inet adev {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ip daddr 10.0.2.2 tcp dport $PORT accept
  }
}
NFT
exec setpriv --ambient-caps=-all --inh-caps=-all --bounding-set=-all -- \
  bwrap --die-with-parent --unshare-user --unshare-pid \
    --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/sbin /sbin \
    --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --ro-bind /etc /etc --proc /proc --dev /dev \
    --tmpfs /tmp --tmpfs /run --tmpfs /home --tmpfs /var \
    --ro-bind "$WORK/inner.sh" /run/smoke/inner.sh \
    $( [ -f "$CA" ] && echo "--ro-bind $CA /run/smoke/ca.crt" ) \
    --clearenv --setenv PATH /usr/bin:/bin:/usr/sbin --setenv HOME /tmp \
    /bin/bash /run/smoke/inner.sh
SETUP
chmod +x "$WORK/setup.sh"

# --- launcher: slirp attacher + exec unshare (same as bwrap-launch.sh) -------
cat > "$WORK/launch.sh" <<'LAUNCH'
#!/bin/bash
set -u
P=$$
HOST_NET=$(readlink /proc/self/ns/net)
(
    for i in $(seq 1 300); do
        [ "$(readlink /proc/$P/ns/net 2>/dev/null || echo "$HOST_NET")" != "$HOST_NET" ] && break
        sleep 0.1
    done
    exec slirp4netns --mtu=65520 --userns-path=/proc/$P/ns/user --netns-type=path /proc/$P/ns/net tap0
) >"$WORK/slirp.log" 2>&1 &
echo $! > "$WORK/slirp.pid"
exec unshare --map-current-user --net --keep-caps /bin/bash "$WORK/setup.sh"
LAUNCH
chmod +x "$WORK/launch.sh"

WORK="$WORK" CA="$CA" bash "$WORK/launch.sh"
RC=$?
echo
if [ $RC -eq 0 ]; then
    echo "== RESULT: PASS — envoy-only egress invariant holds =="
else
    echo "== RESULT: FAIL (rc=$RC) =="
    echo "-- slirp log:"; cat "$WORK/slirp.log" 2>/dev/null
fi
exit $RC
