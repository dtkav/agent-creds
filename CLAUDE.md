# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agent-creds is a credential injection proxy for AI agents. It terminates TLS with custom certificates so unmodified code can hit `https://api.stripe.com` and have credentials injected transparently.

## Development Commands

```bash
# Primary development
adev                # Start interactive sandbox
make build          # Build sandbox Docker image
make binaries       # Build all binaries to bin/

# Vault service
make up             # Start vault with docker-compose
make down           # Stop vault

# Fly.io deployment
make deploy         # Deploy vault service to Fly.io

make clean-certs    # Remove generated certs (forces regeneration)
```

### Dev Environment Workflow

`adev` (built via `make binaries` or `cd cmd/adev && go build`):
1. Generates configs from `agent-creds.toml`
2. Starts vault service if not running
3. Starts envoy proxy with runtime cert generation
4. Launches sandbox container with network isolation
5. Watches `agent-creds.toml` for changes and hot-reloads upstream config

## Architecture

```
Client container (trusts CA, iptables DNAT redirects :443 -> envoy)
    |
    v HTTPS (TLS terminated by envoy with runtime-generated cert)
Envoy proxy (port 443, uses envoy-entrypoint.sh for cert generation)
    |
    v ext_authz (gRPC)
Vault service (validates macaroon token, returns real API key)
    |
    v HTTPS (with injected Authorization header)
api.stripe.com (real)
```

**Components:**
- **adev** (`cmd/adev/`): Development orchestrator - generates configs, starts services, launches sandbox
- **envoy**: Stock envoy image with `envoy-entrypoint.sh` for runtime domain cert generation
- **vault** (`vault/`): Go gRPC service that validates macaroon tokens and injects real API keys
- **mint** (`vault/cmd/mint/`): CLI tool for minting tokens with fine-grained access control

**Cert generation:**
- CA cert is pre-generated once in `generated/certs/`
- Domain certs are generated at envoy startup by `envoy-entrypoint.sh`
- Certs are stored in `/tmp/certs/` inside the envoy container

**Vault flow:**
1. Client mints a token using `mint` with optional caveats (hosts, methods, paths, validity)
2. Client hits `https://api.stripe.com` with `Authorization: Bearer <macaroon-token>`
3. iptables DNAT redirects port 443 traffic to envoy proxy
4. Envoy terminates TLS with runtime-generated cert, routes based on SNI
5. Envoy calls vault via ext_authz filter
6. Vault verifies token signature and validates caveats against the request
7. Vault looks up real API key by host and returns it in response headers
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
2. If using credential injection, create the akey file and configure vault
3. Configs are regenerated automatically (on `adev` start or hot-reloaded if already running)

For Fly.io vault: `fly secrets set NEWSERVICE_API_KEY=xxx -a <your-vault-app> && make deploy`

## Common Issues

- **Certificate errors**: Ensure container trusts CA (`/usr/local/share/ca-certificates/agent-creds-ca.crt`)
- **Connection refused**: Ensure `adev` started successfully and sandbox is on the correct network
- **403 Forbidden**: Check vault logs - token may be invalid or missing required caveats
