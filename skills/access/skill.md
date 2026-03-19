---
name: access
description: Configure agent API access. Use when the user wants to add, review, or fix credential access in agent-creds.toml. Handles Stripe, AWS, GitHub, and other API credentials.
---

# /access — Configure Agent API Access

You are helping a developer configure which API endpoints their AI agent can access through agent-creds, a credential injection proxy.

## Context

agent-creds lets agents use real API credentials (Stripe, AWS, GitHub, etc.) without seeing the actual secrets. The developer configures access in `agent-creds.toml`, and the system mints scoped tokens, injects credentials transparently, and logs all access.

## Steps

### 1. Gather current state

Read and run all of these to understand what's configured and what's available:

- **Current config**: Read `agent-creds.toml` to see existing upstream entries and their scopes (methods, paths, credential references).
- **Available credentials**: Run `actl vault show --credentials` to list credentials stored in the vault, their types (bearer, sigv4, basic), and associated hosts.
- **Recent denials**: Run `actl vault log --recent --denials` to see recent authorization failures with method, host, path, and reason.

### 2. Present vault state

Before acting on the request, show the operator a summary of the current access state:

**Credential inventory** — For each credential from `actl vault show --credentials`, display:
- Credential path (e.g., `/stripe/prod`)
- Type (bearer, sigv4, basic)
- Associated host(s)
- Whether it's referenced in `agent-creds.toml` (active) or available but unused

**Recent failures** — If there are any recent denials, surface them prominently:
- Group denials by host and reason
- Highlight repeated patterns (e.g., same path denied multiple times)
- Suggest the most likely fix for each denial pattern

This gives the operator full context before making changes.

### 3. Understand the request

The user may ask to:
- **Add access** to a new API ("I need Stripe access", "add S3 read access")
- **Review access** ("what do I have?", "show current config")
- **Fix denials** ("fix the recent denials", "why is my API call failing?")
- **Modify scope** ("restrict to read-only", "add POST to /v1/charges")

### 4. Propose changes to agent-creds.toml

When adding or modifying upstream entries, use this format:

```toml
[upstream."api.stripe.com"]
credential = "/stripe/prod"
methods = ["GET", "POST"]
paths = ["/v1/customers", "/v1/customers/**"]
```

Key fields:
- `credential` — path to the vault credential (from `actl vault show --credentials`)
- `methods` — HTTP methods to allow (omit to allow all)
- `paths` — URL path patterns with glob support (`*` = one segment, `**` = multiple segments). Omit to allow all paths.

### 5. Apply changes

After the user approves the proposed changes:
1. Edit `agent-creds.toml` with the new/modified upstream entries
2. Hot-reload picks up the change automatically — `adev` watches the file, re-mints tokens, and updates the sandbox environment
3. No restart needed

## Important rules

- Only suggest credentials that exist in the vault (from `actl vault show --credentials`)
- Prefer least-privilege: suggest specific methods and paths rather than wide-open access
- When fixing denials, match the denied method+path exactly rather than opening broad access
- The `credential` field value must match a vault credential path (e.g., `/stripe/prod`)
- Passthrough upstreams (no credential injection) omit the `credential` field
