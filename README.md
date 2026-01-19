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
- **envoy**: Terminates TLS with custom certs, calls authz for token validation
- **authz**: Validates macaroon tokens, injects real API keys into requests

## Quick Start

### Prerequisites

- Docker and Docker Compose

### Setup

```bash
# Generate certs and configs from domains.toml
make generate

# Generate a signing key (32+ bytes, base64 encoded)
export MACAROON_SIGNING_KEY=$(openssl rand -base64 32)
export STRIPE_API_KEY=sk_live_xxx

# Start the proxy
make up
```

### Usage

```bash
# Build the sandbox container (once)
make build

# Run a command through the proxy
bin/arun curl https://api.stripe.com/v1/customers \
  -H "Authorization: Bearer <token>"
```

The `bin/arun` wrapper runs your command in a sandbox container that:
- Joins the `envoy_agent-creds` Docker network
- Has `/etc/hosts` routing `api.stripe.com` → `envoy`
- Trusts the proxy CA for TLS

#### Minting Tokens

Tokens are created using `mint` with fine-grained access control:

```bash
# Build mint (once)
cd authz && go build -o ../mint ./cmd/mint && cd ..

# Mint a token with restrictions
export MACAROON_SIGNING_KEY=<your-signing-key>
./mint --hosts api.stripe.com --methods GET,POST --paths "/v1/*" --valid-for 1h
```

#### Token Options

| Flag | Description | Example |
|------|-------------|---------|
| `--hosts` | Allowed API hosts | `api.stripe.com,api.openai.com` |
| `--methods` | Allowed HTTP methods | `GET,POST` |
| `--paths` | Allowed path patterns (supports `*` and `**` globs) | `/v1/customers/*` |
| `--valid-for` | Token validity duration | `1h`, `24h`, `168h` |
| `--not-before` | Validity start time (RFC3339) | `2024-01-01T00:00:00Z` |
| `--show-caveats` | Print caveats to stderr | |

Tokens without restrictions (no `--hosts`, `--methods`, `--paths`) have full access to all configured APIs.

## Configuration

All domain configuration is centralized in `domains.toml`:

```toml
[ca]
common_name = "Agent-Creds Proxy CA"
days_valid = 3650

[domains.stripe]
host = "api.stripe.com"
env_var = "STRIPE_API_KEY"

# Add more domains as needed
[domains.openai]
host = "api.openai.com"
env_var = "OPENAI_API_KEY"
```

### Adding a new service

1. Add domain to `domains.toml`
2. Run `make generate` to regenerate certs and configs
3. Add the API key environment variable to `docker-compose.yml`
4. Restart: `make down && make up`

### Environment Variables (authz)

- `MACAROON_SIGNING_KEY`: Base64-encoded 32+ byte key for signing/verifying tokens
- `STRIPE_API_KEY`: Stripe API key (or other keys matching `env_var` in domains.toml)

## Files

```
.
├── domains.toml          # Source of truth for proxied domains
├── docker-compose.yml    # Docker Compose config
├── Dockerfile            # Envoy container
├── Makefile              # Build/deploy commands
├── scripts/
│   └── generate.py       # Generates certs and configs from domains.toml
├── generated/            # Generated files (gitignored)
│   ├── certs/            # CA and domain certificates
│   ├── envoy.json        # Envoy config with TLS termination
│   ├── hosts             # /etc/hosts entries
│   └── domains.json      # Domain config for other tools
├── authz/
│   ├── main.go           # gRPC authz service
│   ├── domains_gen.go    # Generated domain config
│   ├── macaroon/         # Macaroon token library (caveats, verification)
│   ├── cmd/mint/         # Token minting CLI tool
│   └── Dockerfile
├── mintfs/               # FUSE filesystem for short-lived tokens
│   └── main.go           # Serves attenuated tokens at ./creds/
└── bin/
    ├── arun              # Run a command through the proxy
    └── adev              # Interactive dev session
```

## How It Works

1. **Certificate Generation**: `make generate` creates a CA and signs certificates for each domain in `domains.toml`
2. **TLS Termination**: Envoy presents these certificates to clients, so `https://api.stripe.com` works with unmodified code
3. **DNS Routing**: Client containers need `/etc/hosts` entries pointing proxied domains to the envoy service
4. **Token Verification**: Authz verifies the macaroon token signature and checks caveats (host, method, path, validity)
5. **Credential Injection**: On successful verification, authz injects the real API key before forwarding to upstream
