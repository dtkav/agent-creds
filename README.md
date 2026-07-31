# agent-creds

Agent sandbox with integrated credential injection proxy. Allows unmodified code to hit e.g. `https://api.stripe.com` and have API credentials injected transparently via an Envoy proxy with TLS termination.

![agent-creds sandbox](agent-creds.png)


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
│                    credential plane                         │
│                                                             │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐ │
│  │   sandbox   │      │    envoy    │      │    vault    │ │
│  │  (your app) │─────▶│  (TLS term) │─────▶│  (tokens)   │ │
│  └─────────────┘      └─────────────┘      └─────────────┘ │
│   iptables NAT:           │                                 │
│   all TCP → envoy         │                                 │
│                           ▼                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │ HTTPS
                            ▼
                    api.stripe.com (real)
```

- **sandbox**: Container or `bwrap` process running your code with no direct network path
- **envoy**: Per-sandbox egress proxy that terminates TLS and asks Vault to authorize requests
- **vault**: Singleton credential service shared by sandboxes; validates macaroons, runs trusted upstream policy, and injects credentials

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Go 1.24+ (for building tools)
- `sops` (for the encrypted Vault configuration)
- **bubblewrap** for the lightweight host-process runtime, or Docker plus
  [gVisor runsc](https://gvisor.dev/docs/user_guide/install/) for container runtimes

### Setup

```bash
# Create project config (or copy agent-creds.example.toml)
cat > agent-creds.toml << 'EOF'
[sandbox]
name = "myproject"
# Bundled agents: "claude", "codex", or "pi"
agent = "claude"

[upstream."api.anthropic.com"]
[upstream."claude.ai"]
[upstream."platform.claude.com"]

[[browser_target]]
url = "https://claude.ai/oauth/authorize*"

[[browser_target]]
url = "http://localhost:*"
EOF

# Build the host tools and initialize the encrypted singleton Vault config
make binaries
bin/actl vault init

# Launch sandbox
bin/adev console
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

- Makes your current project writable inside the selected sandbox runtime
- **Blocks all network traffic by default** — the sandbox has no internet access except through the proxy
- Routes only the domains listed in `agent-creds.toml` through envoy
- **Hot-reloads** when you edit `agent-creds.toml` (add/remove upstreams without restart)
- Starts the singleton Vault service and a per-instance Envoy if needed
- Attaches to existing instances instead of creating duplicates

Multiple named sandboxes can run concurrently.

### Agent Profiles

Set `[sandbox].agent` to use a bundled agent profile. Profiles add the agent's
packages, network allowlist entries, and browser login targets to the merged
sandbox config.

```toml
[sandbox]
agent = "claude"  # or "codex" / "pi"
```

The Pi profile includes OpenRouter network access. To inject an OpenRouter API
key through the vault, configure the upstream with a bearer credential whose
environment variable is `OPENROUTER_API_KEY`:

```toml
[upstream."openrouter.ai"]
credential = "/openrouter"
```

### actl

`actl` is a control utility for monitoring and managing sandbox instances.

```bash
actl              # Interactive TUI showing all instances
actl status       # Show status for current project (containers, vault connectivity)
```

The TUI shows all running adev instances with their status (running/partial/stopped).

### Network Isolation

Inside the sandbox, only configured domains are reachable:

```bash
# Works - domain is in agent-creds.toml
curl https://api.stripe.com/v1/customers \
  -H "Authorization: Bearer $STRIPE_TOKEN"

# Blocked - domain not configured
curl https://example.com  # connection refused
```

### Credential Injection

Envoy replaces macaroons for the real API key before forwarding to the upstream.

```bash
# 1. Mint a token (on host, before launching sandbox)
export STRIPE_TOKEN=$(bin/mint --hosts api.stripe.com --valid-for 1h)

# 2. Launch sandbox with token as env var
STRIPE_TOKEN=$STRIPE_TOKEN adev console

# 3. Inside sandbox, use the token normally
curl https://api.stripe.com/v1/customers \
  -H "Authorization: Bearer $STRIPE_TOKEN"
```

The sandbox never sees `sk_live_...` — only the macaroon token. The vault service validates the token and injects the real Stripe API key before the request reaches Stripe.

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
| `--constraint` | Application-owned attenuation, repeatable `namespace=JSON` | `records={"services":["ledger"]}` |
| `--valid-for` | Token expiration | `1h`, `24h`, `7d` |
| `--not-before` | Validity start time (RFC3339) | `2024-01-01T00:00:00Z` |
| `--show-caveats` | Print caveats to stderr | |

Tokens without restrictions (no `--hosts`, `--methods`, `--paths`, or
`--constraint`) have full access to all configured APIs. Application
constraints are restrictive macaroon caveats: holders can append them offline,
so an upstream policy must evaluate every constraint conjunctively.

### Passthrough Mode

Not all requests need credential injection. The vault checks the `Authorization` header:

- **Macaroon tokens** (prefix `acm_`): Validated and swapped for real credentials
- **Other tokens / no auth**: Passed through unchanged to the upstream

Passthrough allows the proxy to handle APIs that don't require credentials, or that use different auth schemes. To require macaroons for all requests, set `STRICT_MODE=true` on the vault service.

### Error Responses

When token validation fails, the vault returns specific HTTP errors:

| Status | Cause | Example |
|--------|-------|---------|
| **401 Unauthorized** | Invalid/expired macaroon, bad signature | `Unauthorized: token expired` |
| **403 Forbidden** | Valid token but caveat violation | `Unauthorized: host not allowed` |
| **403 Forbidden** | No credentials configured for host | `No credentials configured for this host` |

The response body includes a message explaining the failure. Check vault logs for detailed diagnostics.

## Configuration

### agent-creds.toml (per-project)

Controls the sandbox configuration, and which domains are routed through the proxy:

```toml
[sandbox]
name = "myproject"
# runtime = "bwrap"  # or "gvisor" / "runc"
# memory = "8g"     # memory limit (e.g., "8g", "512m")
# cpus = "4"        # CPU limit (e.g., "4", "1.5")

[upstream."api.example.com"]
credential = "/example/prod"
policy = "/example/write"

# Authenticate a request without injecting a credential. Vault overwrites
# x-agent-creds-* identity headers with facts from the verified macaroon.
[upstream."records.internal"]
mode = "identity"
policy = "/records/read"
scheme = "http"
port = 8890
address = "records-service"
network = "records-network"
methods = ["POST"]
paths = ["/graphql"]
```

`credential` selects a Vault credential. `policy` selects a trusted Vault
policy and makes the route require a valid macaroon even when global strict
mode is disabled. Identity routes verify a subject-scoped macaroon, apply the
route policy, and forward only Vault-owned `x-agent-creds-*` identity headers;
they do not inject a credential.

### vault.yaml (vault service)

`actl vault init` creates the encrypted configuration. Credential map keys are
paths selected by project upstreams, rather than necessarily being host names.
Secret references resolve against the encrypted `secrets` map before provider
or policy configuration is loaded.

```yaml
secrets:
  local:
    SIGNING_KEY: base64-encoded-32-byte-key
    API_TOKEN: secret-api-token

signing_key:
  $secret: local#SIGNING_KEY

credentials:
  example/prod:
    type: bearer
    token:
      $secret: local#API_TOKEN
    policy: example/write

policies:
  example/write:
    type: example_acl
    allowed_service: ledger
```

Public credential types are `bearer`, `basic`, `oauth2` refresh tokens, and
AWS `sigv4`. Other types are supplied by trusted JavaScript extensions.

### JavaScript credential providers

Deployment-specific credential types can live outside the public Go binary as
trusted `*.provider.js` files. By default the vault loads `providers.d` relative
to its working directory; set `AGENT_CREDS_PROVIDER_PATH` to an
OS-path-list-separated set of files or directories.

```js
registerCredentialProvider({
  name: "example-session",
  credentialType: "example_session",
  priority: 100,
  cache: "credential",
  match: {
    hosts: ["api.example.com"],
    methods: ["GET", "POST"],
    paths: ["/v1/**"],
  },
  validate(config) {
    if (!config.account) throw new Error("account is required");
  },
  resolve(request, config) {
    const token = $exec.run("example-login", ["--account", config.account]);
    return {
      headers: { authorization: "Bearer " + token },
      expiresAt: $jwt.expiresAt(token),
      stop: true,
    };
  },
});
```

The configured credential type is the first selector. Matching registrations
then run in ascending `priority`, source-filename, and registration order.
Headers are merged in that order, so a later handler overwrites an earlier
value; `stop: true` ends the chain. Empty match lists match every request for
that credential type. Results are request-dependent by default. A registration
may set `cache: "credential"` only when its headers are safe to reuse for every
request that matches it; cached results also require `expiresAt`. The matched
handler set is part of the cache key.

Provider scripts are hot-reloaded. The vault builds and validates a complete
new runtime pool before swapping it into service; a syntax or validation error
leaves the last known-good set active. Scripts are trusted deployment code.
`$exec.run(command, args)` executes a program directly without a local shell.
`$http.request(options)` performs a context-bound HTTP request without following
redirects and caps the response body at 4 MiB. `$jwt.expiresAt(token)` reads an
unverified JWT expiry for cache timing only.
`AGENT_CREDS_PROVIDER_POOL` optionally controls the runtime pool size.

### JavaScript upstream policies

Trusted `*.policy.js` files use the same atomic, hot-reloadable runtime. A
policy receives only request facts produced after macaroon verification. The
policy owns the meaning of application namespaces and must reject unknown
namespaces and evaluate every constraint it receives.

```js
registerUpstreamPolicy({
  name: "example-acl",
  policyType: "example_acl",
  validate(config) {
    if (!config.allowed_service) throw new Error("allowed_service is required");
  },
  authorize(request, config) {
    if (!request.subject) return { allow: false, reason: "subject required" };
    for (const caveat of request.constraints) {
      if (caveat.namespace !== "records") {
        return { allow: false, reason: "unknown constraint namespace" };
      }
      if (!caveat.body.services.includes(config.allowed_service)) {
        return { allow: false, reason: "service excluded" };
      }
    }
    return true;
  },
});
```

Route policies are selected with `policy` in `agent-creds.toml`; credentials
may also bind a policy in `vault.yaml`. When both are present, both must allow.
A credential request carrying application constraints fails closed if no
policy is selected. An identity service may inspect the original macaroon for
convenience, but Vault and the upstream policy remain the authorization
boundary.

### Environment Variables

- `MACAROON_SIGNING_KEY`: Base64-encoded 32+ byte key for signing/verifying tokens
- `TOKEN_PREFIX`: Macaroon token prefix (default: `acm_`)
- `STRICT_MODE`: Set to `true` to reject non-macaroon requests (disables passthrough)
- `AGENT_CREDS_PROVIDER_PATH`: Extension script files/directories (OS path-list syntax)
- `AGENT_CREDS_PROVIDER_POOL`: JavaScript runtime pool size (defaults to available CPUs, capped at 8)
- `VAULT_CONFIG`: Path to the decrypted `vault.yaml`

## Development Commands

```bash
# Primary workflow
adev              # Interactive TUI showing running sandboxes
adev console      # Start or attach to sandbox

# Vault service
make up           # Start vault with docker-compose
make down         # Stop vault

# Building
make build        # Build sandbox Docker image
make binaries     # Build all CLI tools to bin/

# Maintenance
make deploy       # Deploy vault service to Fly.io
make clean-certs  # Remove generated certs (forces regeneration)
```

## Files

```
.
├── agent-creds.toml      # Project config (per-project)
├── docker-compose.yml    # Vault service config
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
│   └── domains.json      # Domain config for runtime cert generation
├── vault/
│   ├── main.go           # gRPC vault service
│   ├── macaroon/         # Macaroon token library
│   ├── cmd/mint/         # Token minting CLI
│   └── Dockerfile
└── bin/                  # Built binaries (run make binaries)
```

## How It Works

1. **CA Generation**: `adev` creates a CA cert once in `generated/certs/`
2. **Runtime Certs**: `envoy-entrypoint.sh` generates domain certs at startup using the CA
3. **Traffic Interception**: iptables NAT rules redirect all outbound TCP to envoy
4. **TLS Termination**: Envoy terminates TLS using SNI to select the right certificate, so `https://api.stripe.com` works with unmodified code
5. **Token Verification**: Vault verifies the macaroon token signature and checks caveats (host, method, path, validity)
6. **Upstream Policy**: Trusted deployment policy evaluates the verified subject and every application constraint
7. **Credential Injection**: On successful authorization, Vault resolves and injects the configured credential

## Advanced Features

### Browser Forwarding

Code inside the sandbox can open URLs in your host's default browser:

```bash
xdg-open https://accounts.google.com/oauth/authorize?...
```

This enables OAuth flows where:
1. Sandbox code calls `xdg-open` with auth URL → browser opens on host
2. User authenticates in host browser
3. OAuth callback to `localhost:PORT` routes back into the sandbox

The callback routing works automatically—adev detects localhost URLs with ports and proxies incoming connections from the host back to the sandbox.

Configure in `agent-creds.toml`:
```toml
[sandbox]
use_host_browser = true  # default

# URL allow-list (required - empty = all blocked)
[[browser_target]]
url = "*accounts.google.com/o/oauth*"

[[browser_target]]
url = "http://localhost:*"
```

Only URLs matching a `[[browser_target]]` pattern will be opened. All others are blocked.

### Chrome DevTools Protocol (CDP)

Control your host's Chrome browser from inside the sandbox. Playwright, Puppeteer, and other automation tools connect to `localhost:9222` which forwards to Chrome on your host.

```python
# Inside sandbox - controls host Chrome
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp("http://localhost:9222")
    page = browser.new_page()
    page.goto("https://example.com")
```

Start Chrome on your host with remote debugging enabled:
```bash
google-chrome --remote-debugging-port=9222
```

Configure in `agent-creds.toml`:
```toml
[sandbox]
use_host_browser_cdp = true  # default

# Target allow-list (required - empty = all blocked)
[[cdp_target]]
type = "page"
title = "*My App*"

[[cdp_target]]
url = "*github.com*"
```

Only browser tabs matching a `[[cdp_target]]` pattern will be accessible. This prevents agents from accessing sensitive tabs (email, banking, etc.).

**CDP target fields** (all optional, empty = match any):
- `type`: Target type (`page`, `background_page`, `service_worker`, etc.)
- `title`: Glob pattern matching page title
- `url`: Glob pattern matching page URL

When multiple fields are specified, all must match.
