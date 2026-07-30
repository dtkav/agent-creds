#!/usr/bin/env bash
# End-to-end test: Claude Code native sandbox with envoy as the egress.
#
# Launches a disposable claude session (haiku) under settings.json in a
# scratch dir, asks it to fetch an allowed and a non-configured domain,
# and reports whether: (a) commands ran without permission prompts,
# (b) allowed traffic succeeded THROUGH envoy, (c) unconfigured egress
# was blocked. Assumes envoy-forward.sh is already running.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=$(mktemp -d /tmp/native-sbx-XXXX)   # no "claude" in path
trap 'rm -rf "$WORK"' EXIT
CA="$HERE/../generated/certs/ca.crt"

# preflight: the forward must be up and envoy must answer
curl -s -m 8 -o /dev/null -w "" --proxy http://127.0.0.1:10000 \
    --cacert "$CA" https://api.github.com/zen \
    || { echo "preflight failed: is envoy-forward.sh running?" >&2; exit 1; }
echo "preflight: envoy reachable through 127.0.0.1:10000"

PROMPT='Run exactly these two bash commands, one at a time, and then reply
with a two-line report and nothing else:
1) curl -sS -m 15 https://api.github.com/zen
2) curl -sS -m 15 https://example.com/ -o /dev/null -w "%{http_code}"
Line 1 of your reply: ALLOWED=<ok|fail> <what command 1 printed>
Line 2 of your reply: BLOCKED=<yes|no> (yes if command 2 failed to connect)'

cd "$WORK"
OUT=$(env -u CLAUDECODE -u CLAUDE_CODE_CHILD_SESSION -u CLAUDE_CODE_SESSION_ID \
        -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_EXECPATH -u CLAUDE_PID \
        NODE_EXTRA_CA_CERTS="$CA" CURL_CA_BUNDLE="$CA" SSL_CERT_FILE="$CA" \
        claude -p --model haiku --settings "$HERE/settings.json" \
        --output-format json "$PROMPT")

echo "---- claude report ----"
echo "$OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result","(no result)")); print("permission_denials:", d.get("permission_denials") or d.get("num_turns"))'
echo "---- verdict ----"
echo "$OUT" | grep -q "ALLOWED=ok" && echo "PASS: allowed domain reached through sandbox" \
    || echo "FAIL: allowed domain did not succeed"
echo "$OUT" | grep -q "BLOCKED=yes" && echo "PASS: unconfigured domain blocked" \
    || echo "FAIL: unconfigured domain was NOT blocked"
