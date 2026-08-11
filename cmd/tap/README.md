# Normalized GenAI operation tap

This service is the optional singleton observer for all agent Envoys.
`adev tap enable` starts it once at the system level. Every subsequently
started instance registers automatically; there is no project-level opt-in. It
is not in the agent's request path and has no Vault mount, so collector failure
cannot affect agent networking or credential exchange.

The service attaches to each explicitly configured Envoy admin tap endpoint and
reassembles streamed bodies in bounded memory only. It recognizes OpenAI
Responses and Anthropic Messages events, then discards the transport material.
SQLite has an allowlisted `operations` schema containing source, provider,
operation, model, timing, status, byte counts, and provider-reported token
counts. It has no columns for headers, URLs, request/response bodies, or generic
JSON.

The UI is at `/`, the Server-Sent Events endpoint is at
`/api/operations/stream`, normalized operations are at `/api/operations`,
Prometheus exposition is at `/metrics`, and
`/api/export/otel-genai.jsonl` exports normalized records using OpenTelemetry
GenAI semantic-convention attribute names. The latter is a conversion boundary,
not a raw traffic archive or an OTLP transport.

Configuration is JSON:

```json
{
  "sources": [
    {
      "id": "engineer-a",
      "admin_url": "unix:///run/adev-tap/engineer-a/admin.sock",
      "config_id": "agent_creds_global_tap"
    }
  ]
}
```

`adev` generates and reloads this fan-in configuration as instances start and
stop. The hardened global container receives read-only access to the
shared tree of private Envoy admin sockets and writes one persistent database.
Its UI is published on host loopback only over a dedicated, non-masqueraded
Docker network. It receives no Vault configuration, macaroons, provider
credentials, routed internet egress, or instance mount other than the socket
tree.

The `lab/` stack proves the fan-in topology with one tap, two Envoys, and a mock
provider in a disposable Compose project. It does not use production networks,
volumes, Vault, generated certificates, or agent state.
