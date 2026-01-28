# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agent-creds is a credential injection proxy for AI agents. It terminates TLS with custom certificates so unmodified code can hit `https://api.stripe.com` and have credentials injected transparently.

## Development Commands

```bash
# Primary development
make dev            # Start interactive sandbox with adev
make build          # Build sandbox Docker image

# Authz service
make up             # Start authz with docker-compose
make down           # Stop authz

# Fly.io deployment
make deploy         # Deploy authz service to Fly.io

# Sandbox workflow
make apply-changes  # Copy changes from container overlay to host
make discard-changes # Discard container overlay changes

make clean-certs    # Remove generated certs (forces regeneration)
```

### Dev Environment Workflow

`make dev` runs `adev`, which:
1. Generates configs from `agent-creds.toml`
2. Starts authz service if not running
3. Starts envoy proxy with runtime cert generation
4. Launches sandbox container with network isolation

Changes made inside the container are captured to `claude-dev/overlay-changes/`. After exiting:
- `make apply-changes` copies overlay changes back to the host
- `make discard-changes` removes the overlay directory

## Architecture

```
Client container (trusts CA, /etc/hosts points api.stripe.com -> envoy)
    |
    v HTTPS (TLS terminated by envoy with runtime-generated cert)
Envoy proxy (port 443, uses envoy-entrypoint.sh for cert generation)
    |
    v ext_authz (gRPC)
Authz service (validates macaroon token, returns real API key)
    |
    v HTTPS (with injected Authorization header)
api.stripe.com (real)
```

**Components:**
- **adev** (`cmd/adev/`): Development orchestrator - generates configs, starts services, launches sandbox
- **envoy**: Stock envoy image with `envoy-entrypoint.sh` for runtime domain cert generation
- **authz** (`authz/`): Go gRPC service that validates macaroon tokens and injects real API keys
- **mint** (`authz/cmd/mint/`): CLI tool for minting tokens with fine-grained access control

**Cert generation:**
- CA cert is pre-generated once in `generated/certs/`
- Domain certs are generated at envoy startup by `envoy-entrypoint.sh`
- Certs are stored in `/tmp/certs/` inside the envoy container

**Authz flow:**
1. Client mints a token using `mint` with optional caveats (hosts, methods, paths, validity)
2. Client hits `https://api.stripe.com` with `Authorization: Bearer <macaroon-token>`
3. DNS (/etc/hosts) routes to envoy proxy
4. Envoy terminates TLS with runtime-generated cert, routes based on SNI
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

Project configuration is in `agent-creds.toml`. The `adev` tool reads this and generates:
- `generated/certs/ca.crt` - CA certificate (only generated once)
- `generated/envoy.json` - Envoy config with TLS termination
- `generated/hosts` - /etc/hosts entries for container
- `generated/domains.json` - Domain config for runtime cert generation

### Adding a New API Service

1. Add upstream to `agent-creds.toml`:
   ```toml
   # Passthrough (no credential injection)
   [upstream."api.example.com"]

   # With credential injection (requires .akey file)
   [upstream."api.newservice.com"]
   akey = "newservice.akey"
   ```
2. If using credential injection, create the akey file and configure authz
3. Run `make dev` - configs are regenerated automatically

For Fly.io authz: `fly secrets set NEWSERVICE_API_KEY=xxx -a <your-authz-app> && make deploy`

## Common Issues

- **Certificate errors**: Ensure container trusts CA (`/usr/local/share/ca-certificates/agent-creds-ca.crt`)
- **Connection refused**: Ensure `make dev` started successfully and sandbox is on the correct network
- **403 Forbidden**: Check authz logs - token may be invalid or missing required caveats
