# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agent-creds is a credential injection proxy for AI agents. It terminates TLS with custom certificates so unmodified code can hit `https://api.stripe.com` and have credentials injected transparently. Can be run locally with Docker Compose or deployed to Fly.io.

## Development Commands

```bash
# Docker Compose (primary)
make generate       # Generate certs and configs from domains.toml
make up             # Start proxy with docker-compose
make down           # Stop proxy

# Fly.io deployment (requires .flycast routing)
make generate-fly   # Generate configs for Fly.io
make deploy         # Deploy both services (authz + proxy)
make deploy-proxy   # Deploy envoy proxy only
make deploy-authz   # Deploy authz service only

# Sandbox development
make dev            # Start interactive sandbox (overlay fs + bash)
make build          # Build sandbox Docker image
make apply-changes  # Copy changes from container overlay to host
make discard-changes # Discard container overlay changes

make clean-certs    # Remove generated certs (forces regeneration)
```

### Dev Environment Workflow

`make dev` mounts the repo read-only with an overlay filesystem. Changes made inside the container are captured to `claude-dev/overlay-changes/`. After exiting:
- `make apply-changes` copies overlay changes back to the host
- `make discard-changes` removes the overlay directory

## Architecture

```
Client container (trusts CA, /etc/hosts points api.stripe.com -> proxy)
    |
    v HTTPS (TLS terminated by envoy with custom cert)
Envoy proxy (port 8443)
    |
    v ext_authz (gRPC)
Authz service (validates macaroon token, returns real API key)
    |
    v HTTPS (with injected Authorization header)
api.stripe.com (real)
```

**Components:**
- **envoy** (root): Envoy proxy that terminates TLS with SNI-based routing, calls ext_authz
- **authz** (`authz/`): Go gRPC service that validates macaroon tokens and injects real API keys
- **mint** (`authz/cmd/mint/`): CLI tool for minting tokens with fine-grained access control

**Authz flow:**
1. Client mints a token using `mint` with optional caveats (hosts, methods, paths, validity)
2. Client hits `https://api.stripe.com` with `Authorization: Bearer <macaroon-token>`
3. DNS (/etc/hosts) routes to envoy proxy
4. Envoy terminates TLS with custom cert, routes based on SNI
5. Envoy calls authz via ext_authz filter
6. Authz verifies token signature and validates caveats against the request
7. Authz looks up real API key by host and returns it in response headers
8. Envoy injects the header and forwards to real upstream over HTTPS

**Token caveats (restrictions):**
- `--hosts`: Limit to specific API hosts (e.g., `api.stripe.com`)
- `--methods`: Limit to HTTP methods (e.g., `GET,POST`)
- `--paths`: Limit to path patterns with glob support (`*` = segment, `**` = multiple segments)
- `--valid-for`: Token expiration duration (default: 24h)

## Configuration

All domain configuration is in `domains.toml`. Run `make generate` after editing to regenerate:
- `generated/certs/` - CA and domain certificates
- `generated/envoy.json` - Envoy config with TLS termination
- `generated/hosts` - /etc/hosts entries for container
- `generated/domains.json` - Domain config for tools
- `authz/domains_gen.go` - Go code with domain mappings

## Adding a New API Service

1. Add domain to `domains.toml`:
   ```toml
   [domains.newservice]
   host = "api.newservice.com"
   env_var = "NEWSERVICE_API_KEY"
   ```
2. Run `make generate`
3. Add `NEWSERVICE_API_KEY` to `docker-compose.yml` environment section
4. Restart: `make down && make up`

For Fly.io: `fly secrets set NEWSERVICE_API_KEY=xxx -a <your-authz-app> && make deploy`

## Common Issues

- **Certificate errors**: Ensure container trusts CA (`/usr/local/share/ca-certificates/agent-creds-ca.crt`)
- **Connection refused**: Ensure `make up` is running and sandbox is on the `envoy_agent-creds` network
- **403 Forbidden**: Check authz logs - token may be invalid or missing required caveats
