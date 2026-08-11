#!/bin/sh
set -eu

project="agent-creds-tap-lab-$$"
compose="docker compose -p $project -f compose.yaml"
tmp="$(mktemp -d)"
secret="DO_NOT_PERSIST_lab_secret_$$"

cleanup() {
  $compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

$compose up --build -d

i=0
until $compose exec -T probe wget -qO- "http://tap:8080/readyz" >"$tmp/ready.json"; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    $compose logs
    exit 1
  fi
  sleep 1
done

$compose exec -T probe wget -qO- \
  --header "content-type: application/json" \
  --header "authorization: Bearer $secret" \
  --post-data "{\"model\":\"gpt-lab\",\"input\":\"$secret\"}" \
  "http://envoy-openai:10000/v1/responses?secret=$secret" >"$tmp/openai.out"
$compose exec -T probe wget -qO- \
  --header "content-type: application/json" \
  --header "x-api-key: $secret" \
  --post-data "{\"model\":\"claude-lab\",\"messages\":[{\"role\":\"user\",\"content\":\"$secret\"}]}" \
  "http://envoy-anthropic:10000/v1/messages?secret=$secret" >"$tmp/anthropic.out"

i=0
while :; do
  $compose exec -T probe wget -qO- "http://tap:8080/api/operations" >"$tmp/operations.json"
  count="$(grep -o '"id":' "$tmp/operations.json" | wc -l)"
  [ "$count" -ge 2 ] && break
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then
    $compose logs
    exit 1
  fi
  sleep 1
done

grep -q '"provider":"openai"' "$tmp/operations.json"
grep -q '"input_tokens":23' "$tmp/operations.json"
grep -q '"provider":"anthropic"' "$tmp/operations.json"
grep -q '"output_tokens":9' "$tmp/operations.json"
if grep -q "$secret" "$tmp/operations.json"; then
  echo "raw secret leaked through operations API" >&2
  exit 1
fi

$compose exec -T probe wget -qO- "http://tap:8080/metrics" >"$tmp/metrics.txt"
grep -q 'agent_creds_tap_source_connected{source="lab-openai-envoy"} 1' "$tmp/metrics.txt"
grep -q 'agent_creds_tap_source_connected{source="lab-anthropic-envoy"} 1' "$tmp/metrics.txt"
grep -q 'agent_creds_tap_tokens_total' "$tmp/metrics.txt"

$compose cp tap:/data/operations.db "$tmp/operations.db" >/dev/null
if grep -a -q "$secret" "$tmp/operations.db"; then
  echo "raw secret was persisted in SQLite" >&2
  exit 1
fi

expected_network="${project}_tap-lab"
for service in tap envoy-openai envoy-anthropic mock-provider probe; do
  container="$($compose ps -q "$service")"
  networks="$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$container")"
  [ "$networks" = "$expected_network " ] || {
    echo "$service escaped the isolated namespace: $networks" >&2
    exit 1
  }
done

echo "PASS: singleton tap normalized two Envoy sources without persisting raw traffic"
