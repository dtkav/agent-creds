# agent-creds

**Status: Experimental** — This is a vibe-coded proof-of-concept. The API and architecture may change significantly. Not recommended for production use without thorough review.

Credential injection proxy for AI agents. Allows unmodified code to hit `https://api.stripe.com` and have API credentials injected transparently via an Envoy proxy with TLS termination.

## Threat Model

This project addresses two security concerns when running AI agents with API access:

### Primary: Credential Leakage to LLM Providers

When an AI agent makes API calls, the credentials are visible to the LLM provider in the conversation context. Even if the agent runs locally, tool outputs containing `Authorization: Bearer sk_live_...` headers get sent back to the model. This proxy keeps real credentials out of the agent's context entirely — the agent only sees an opaque macaroon token, while real API keys are injected server-side.

### Secondary: Limiting Agent Blast Radius

A misbehaving or compromised agent with full API access can do significant damage. Macaroon tokens with caveats provide fine-grained restrictions:

- **Host restrictions**: Token only works for specific APIs (e.g., `api.stripe.com` but not `api.openai.com`)
- **Method restrictions**: Limit to read-only operations (`GET` only)
- **Path restrictions**: Scope access to specific resources (`/v1/customers/*` but not `/v1/transfers/*`)
- **Time restrictions**: Tokens expire automatically (default: 24 hours)

This turns "full API access" into precisely scoped capabilities that match the agent's intended task.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker network                           │
│                                                             │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐ │
│  │   sandbox   │      │    envoy    │      │    authz    │ │
│  │  (your app) │─────▶│  (TLS term) │─────▶│  (tokens)   │ │
│  └─────────────┘      └─────────────┘      └─────────────┘ │
│   /etc/hosts:             │                                 │
│   api.stripe.com→envoy    │                                 │
│                           ▼                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │ HTTPS
                            ▼
                    api.stripe.com (real)
```

- **sandbox**: Container running your code, with `/etc/hosts` routing API domains to envoy
- **envoy**: Terminates TLS with runtime-generated certs, calls authz for token validation
- **authz**: Validates macaroon tokens, injects real API keys into requests

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for building tools)

### Setup

```bash
# Create project config
cat > agent-creds.toml << 'EOF'
[sandbox]
name = "myproject"

[upstream."api.stripe.com"]
akey = "stripe.akey"
EOF

# Generate a signing key (32+ bytes, base64 encoded)
export MACAROON_SIGNING_KEY=$(openssl rand -base64 32)
export STRIPE_API_KEY=sk_live_xxx

# Start authz service (once)
make up

# Launch sandbox
adev console
```

### adev

`adev` is the main development tool. It launches sandboxed environments where your code runs with transparent API proxying.

```bash
adev              # Show running instances (interactive TUI)
adev console      # Start or attach to sandbox for current directory
adev console foo  # Start or attach to sandbox named "foo"
adev stop         # Stop sandbox for current directory
adev stop foo     # Stop sandbox named "foo"
```

**What adev does:**

- Mounts your current directory at `/workspace` inside the container
- **Blocks all network traffic by default** — the sandbox has no internet access except through the proxy
- Routes only the domains listed in `agent-creds.toml` through envoy
- Starts authz service if not running
- Attaches to existing instances instead of creating duplicates

**Browser forwarding:** When code inside the sandbox needs to open a browser (e.g., OAuth flows), adev forwards the request to your host browser. OAuth callbacks to localhost are automatically proxied back into the sandbox.

**CDP forwarding:** If you have Chrome running with remote debugging (`--remote-debugging-port=9222`), the sandbox can connect to it via Chrome DevTools Protocol for browser automation.

Multiple named sandboxes can run concurrently.

Inside the sandbox, only configured domains are reachable:

```bash
# Works - domain is in agent-creds.toml
curl https://api.stripe.com/v1/customers \
  -H "Authorization: Bearer $STRIPE_TOKEN"

# Blocked - domain not configured
curl https://example.com  # connection refused
```

### Credential Swap

The core feature: your code uses an opaque macaroon token, and the proxy swaps it for the real API key before forwarding to the upstream.

```bash
# 1. Mint a token (on host, before launching sandbox)
export STRIPE_TOKEN=$(bin/mint --hosts api.stripe.com --valid-for 1h)

# 2. Launch sandbox with token as env var
STRIPE_TOKEN=$STRIPE_TOKEN adev console

# 3. Inside sandbox, use the token normally
curl https://api.stripe.com/v1/customers \
  -H "Authorization: Bearer $STRIPE_TOKEN"
```

The sandbox never sees `sk_live_...` — only the macaroon token. The authz service validates the token and injects the real Stripe API key before the request reaches Stripe.

### Minting Tokens

Tokens can include caveats that restrict what the token can do:

```bash
# Full access to configured APIs
bin/mint

# Read-only access to Stripe customers endpoint for 1 hour
bin/mint --hosts api.stripe.com --methods GET --paths "/v1/customers/*" --valid-for 1h
```

#### Token Options

| Flag | Description | Example |
|------|-------------|---------|
| `--hosts` | Allowed API hosts | `api.stripe.com,api.openai.com` |
| `--methods` | Allowed HTTP methods | `GET,POST` |
| `--paths` | Allowed path patterns (`*` = segment, `**` = multiple) | `/v1/customers/*` |
| `--valid-for` | Token expiration | `1h`, `24h`, `7d` |
| `--not-before` | Validity start time (RFC3339) | `2024-01-01T00:00:00Z` |
| `--show-caveats` | Print caveats to stderr | |

Tokens without restrictions (no `--hosts`, `--methods`, `--paths`) have full access to all configured APIs.

## Configuration

Create `agent-creds.toml` in your project directory:

```toml
[sandbox]
name = "myproject"

# Remote authz (optional - defaults to local docker-compose)
# [vault]
# host = "authz.example.com"

# Passthrough (no credential injection)
[upstream."api.example.com"]

# With credential injection
[upstream."api.stripe.com"]
akey = "stripe.akey"

[upstream."api.openai.com"]
akey = "openai.akey"
```

### Adding a new service

1. Add upstream to `agent-creds.toml`
2. If using credential injection, create the `.akey` file
3. Run `adev console` - configs regenerate automatically

### Environment Variables (authz)

- `MACAROON_SIGNING_KEY`: Base64-encoded 32+ byte key for signing/verifying tokens
- `STRIPE_API_KEY`: Stripe API key (env var derived from akey filename)

## Development Commands

```bash
# Primary workflow
adev              # Interactive TUI showing running sandboxes
adev console      # Start or attach to sandbox

# Authz service
make up           # Start authz with docker-compose
make down         # Stop authz

# Building
make build        # Build sandbox Docker image
make binaries     # Build all CLI tools to bin/

# Maintenance
make deploy       # Deploy authz service to Fly.io
make clean-certs  # Remove generated certs (forces regeneration)
```

## Files

```
.
├── agent-creds.toml      # Project config (per-project)
├── docker-compose.yml    # Authz service config
├── Makefile              # Build/deploy commands
├── envoy-entrypoint.sh   # Runtime cert generation for envoy
├── cmd/
│   ├── adev/             # Development orchestrator
│   ├── actl/             # Control utility for managing instances
│   ├── aenv/             # Environment variable helper
│   └── cdp-proxy/        # Chrome DevTools Protocol proxy
├── generated/            # Generated files (gitignored)
│   ├── certs/            # CA certificate (domain certs generated at runtime)
│   ├── envoy.json        # Envoy config
│   ├── hosts             # /etc/hosts entries
│   └── domains.json      # Domain config for runtime cert generation
├── authz/
│   ├── main.go           # gRPC authz service
│   ├── macaroon/         # Macaroon token library
│   ├── cmd/
│   │   ├── mint/         # Token minting CLI
│   │   ├── mintfs/       # FUSE filesystem for short-lived tokens
│   │   └── authz-admin/  # Admin CLI for authz service
│   └── Dockerfile
└── bin/                  # Built binaries (run make binaries)
```

## How It Works

1. **CA Generation**: `adev` creates a CA cert once in `generated/certs/`
2. **Runtime Certs**: `envoy-entrypoint.sh` generates domain certs at startup using the CA
3. **TLS Termination**: Envoy presents these certificates to clients, so `https://api.stripe.com` works with unmodified code
4. **DNS Routing**: Sandbox containers have `/etc/hosts` entries pointing proxied domains to envoy
5. **Token Verification**: Authz verifies the macaroon token signature and checks caveats (host, method, path, validity)
6. **Credential Injection**: On successful verification, authz injects the real API key before forwarding to upstream
