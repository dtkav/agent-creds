# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

The authz service is a Go gRPC service implementing Envoy's external authorization (ext_authz) filter. It validates macaroon-based tokens with fine-grained access control and injects real API keys into requests before they reach upstream APIs.

## Development Commands

```bash
# Generate a signing key
openssl rand -base64 32

# Build and run locally
go build -o authz .
MACAROON_SIGNING_KEY=<base64-key> STRIPE_API_KEY=sk_test_xxx ./authz

# Build mint tool
go build -o mint ./cmd/mint

# Mint a token
MACAROON_SIGNING_KEY=<base64-key> ./mint --hosts api.stripe.com --valid-for 1h

# Deploy to Fly.io
fly deploy --local-only --flycast

# Set secrets (replace <your-authz-app> with your Fly.io app name)
fly secrets set MACAROON_SIGNING_KEY=<base64-key> STRIPE_API_KEY=xxx -a <your-authz-app>
```

## Code Structure

- `main.go`: gRPC server implementing `authv3.AuthorizationServer`
- `domains_gen.go`: Generated file mapping hosts to env vars (from `../domains.toml`)
- `macaroon/`: Token library
  - `keys.go`: Key loading from environment
  - `verify.go`: Token verification
  - `caveats.go`: Caveat types (host, method, path restrictions)
  - `access.go`: Access context for caveat validation
- `cmd/mint/`: Token minting CLI tool

## Authorization Flow

1. Envoy sends `CheckRequest` with HTTP headers
2. Server extracts `Authorization: Bearer <macaroon-token>` header
3. Server verifies token signature using `MACAROON_SIGNING_KEY`
4. Server validates caveats against the request (host, method, path, validity window)
5. Server looks up API key using `x-target-host` header (falls back to `host`, then `:authority`)
6. On success, returns `OkResponse` with `authorization` header set to real API key
7. On failure, returns `DeniedResponse` with 401 (bad token) or 403 (unknown host)

## Token Caveats

Tokens can be restricted with caveats:
- **HostCaveat**: Limits which API hosts the token can access
- **MethodCaveat**: Limits HTTP methods (GET, POST, etc.)
- **PathCaveat**: Limits request paths with glob patterns (`*` = single segment, `**` = multiple)
- **ValidityWindow**: Built-in expiration time

## Adding a New API Service

1. Add domain to `../domains.toml`
2. Run `make generate` from parent directory (regenerates `domains_gen.go`)
3. Set the API key secret: `fly secrets set NEWSERVICE_API_KEY=xxx -a <your-authz-app>`

## Environment Variables

- `MACAROON_SIGNING_KEY` (required): Base64-encoded 32+ byte key for signing/verifying tokens
- `PORT`: gRPC listen port (default: 9001)
- `<SERVICE>_API_KEY`: Real API keys for each configured domain (see `domains_gen.go`)

## Flycast Notes

- Listens on port 9001, accessed via `<your-authz-app>.flycast:80`
- Requires `h2_backend = true` in fly.toml for gRPC over HTTP/2
- Uses `force_https = false` since flycast handles internal routing
