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

Show the user the exact TOML changes before applying. Clearly distinguish between:

**Adding a new upstream** — a new `[upstream."host"]` section:
```toml
[upstream."api.stripe.com"]
credential = "/stripe/prod"
methods = ["GET", "POST"]
paths = ["/v1/customers", "/v1/customers/**"]
```

**Modifying an existing upstream** — changing fields on an existing entry:
- Adding a `credential` reference to a passthrough upstream
- Narrowing or widening `methods` (e.g., adding "POST" to a read-only upstream)
- Adjusting `paths` patterns (e.g., adding a new path glob)

**Key fields:**
- `credential` — path to the vault credential (from `actl vault show --credentials`). Must match exactly.
- `methods` — HTTP methods to allow (omit to allow all)
- `paths` — URL path patterns with glob support (`*` = one segment, `**` = multiple segments). Omit to allow all paths.

When proposing changes, present a before/after diff so the user can see exactly what will change:
```
 [upstream."api.stripe.com"]
+credential = "/stripe/prod"
+methods = ["GET", "POST"]
+paths = ["/v1/charges", "/v1/charges/**"]
```

### 5. Apply changes

After the user confirms the proposed changes:

1. **Read** the current `agent-creds.toml` to get the latest content
2. **Edit** the file using precise string replacements:
   - For new upstreams: append the new `[upstream."host"]` section at the end of the file
   - For modifications: replace the specific fields within the existing upstream section
   - Preserve all other sections and formatting in the file
3. **Verify** the edit was applied correctly by reading the file back
4. **Hot-reload** happens automatically — `adev` watches `agent-creds.toml` for changes and will:
   - Re-generate envoy config with updated routes
   - Re-mint tokens with new caveats (methods/paths) for changed upstreams
   - Regenerate `sandbox.env` with updated tokens
   - No restart needed — changes take effect within seconds

## Important rules

- Only suggest credentials that exist in the vault (from `actl vault show --credentials`)
- Prefer least-privilege: suggest specific methods and paths rather than wide-open access
- When fixing denials, match the denied method+path exactly rather than opening broad access
- The `credential` field value must match a vault credential path (e.g., `/stripe/prod`)
- Passthrough upstreams (no credential injection) omit the `credential` field
