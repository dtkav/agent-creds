# Vault JavaScript API

Vault JavaScript extensions define credential configuration contracts,
credential injection, capability extraction, and upstream authorization
policies. Extensions are trusted credential-plane code: provider and policy
callbacks can receive resolved secrets, make network requests, and execute
installed programs.

## Loading extensions

Vault loads files ending in `.provider.js` or `.policy.js`. The default search
paths are `providers` and `providers.d`, relative to the Vault working
directory. Set `AGENT_CREDS_PROVIDER_PATH` to an OS path-list of files and
directories to replace those defaults. Directory scans are not recursive.

Scripts are evaluated in path order. Callbacks are synchronous; they must
return their documented value directly rather than a promise.

Vault polls extension sources every 500 milliseconds. A reload activates only
after every script loads and every configured credential and policy validates.
An invalid reload leaves the active runtime generation unchanged.

## Execution zones

Each script is evaluated in separate JavaScript runtime pools for two execution
zones. Registration calls that belong to the other zone are accepted and
ignored, so one file can define both sides of a credential adapter.

| Zone | Registration hooks | Configuration and secrets | Globals | Request deadline |
| --- | --- | --- | --- | --- |
| Trusted provider/policy | `registerCredentialType`, `registerCredentialProvider`, `registerUpstreamPolicy` | Resolved configuration is passed to callbacks | `$http`, `$exec`, `$jwt`, `$base64.encode`, `$log` | 30 seconds |
| Pre-verification extractor | `registerCredentialExtractor` | Never available | `$base64.decode`, `$log` | 100 milliseconds |

Extractor input is unverified. Returning a token does not authorize the
request; Go verifies the returned agent-creds capability and enforces its
caveats before any provider callback runs.

## Common matching fields

Credential providers and extractors accept this optional matcher:

```js
match: {
  hosts: ["api.example.com", "*.service.example"],
  methods: ["GET", "POST"],
  paths: ["/v1/*", "/v2/**"],
}
```

An omitted matcher or omitted matcher field matches every value. Entries
within one field are alternatives, while populated fields are combined
conjunctively.

- Host patterns are lowercased and use Go path-style glob matching.
- Method patterns are uppercased and use Go path-style glob matching.
- Path patterns use `*` for one path segment and `**` for zero or more path
  segments. Query strings are ignored while matching paths.

Provider and extractor registrations run in ascending `priority` order. The
default priority is `0`. Ties are ordered by source path and then declaration
order.

## `registerCredentialType`

`registerCredentialType` declares one configuration contract for an exact
credential type.

```js
registerCredentialType({
  credentialType: "session",
  configSchema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    required: ["active", "identities", "scopes"],
    properties: {
      active: { type: "string", minLength: 1 },
      identities: {
        type: "object",
        additionalProperties: { $ref: "#/$defs/identity" },
      },
      scopes: { type: "array", items: { type: "string" } },
    },
    $defs: {
      identity: {
        type: "object",
        required: ["token"],
        properties: { token: { type: "string", minLength: 1 } },
      },
    },
  },
  validate(config) {
    if (!config.identities[config.active]) {
      throw new Error("active identity is not configured");
    }
  },
  macaroon: {
    namespace: "session",
    constraintSchema: {
      type: "object",
      additionalProperties: false,
      required: ["scopes"],
      properties: {
        scopes: { type: "array", minItems: 1, items: { type: "string" } },
      },
    },
    constraint(config) {
      return { scopes: config.scopes };
    },
    authorize(request, config) {
      return request.constraints.every((constraint) =>
        constraint.body.scopes.includes("records:read")
      );
    },
  },
});
```

| Field | Required | Meaning |
| --- | --- | --- |
| `credentialType` | yes | Exact, non-empty configured credential type. A type can be registered only once. |
| `configSchema` | yes | JSON Schema for provider-specific configuration. |
| `validate(config)` | no | Additional semantic or cross-field validation. Throw to reject activation. |
| `macaroon` | no | Credential-bound macaroon namespace, derivation, and authorization callbacks. |

Vault compiles the schema while loading the extension. A schema without
`$schema` uses JSON Schema Draft 2020-12. Document-local references are
supported; file and network references are rejected without I/O.

Credential configuration is validated after `$secret` references are resolved
and before a runtime generation is activated. Schema errors identify instance
paths and failed keywords without including rejected values. Schema defaults
are annotations only: validation does not add or modify configuration fields.

Type validation runs before provider-level validation. Registering a type does
not register a resolver; at least one `registerCredentialProvider` must also
match each configured JavaScript credential.

### Credential-bound macaroons

The optional `macaroon` object lets a credential type own application caveats
without requiring a separately configured upstream policy:

| Field | Required | Meaning |
| --- | --- | --- |
| `namespace` | yes | Non-empty application-constraint namespace owned by this credential type. |
| `constraintSchema` | no | JSON Schema for provider fields accepted from named `[authorization.*]` policies. Required before the credential can use that configuration form. |
| `validateConstraint(constraint)` | no | Additional semantic validation for a schema-valid authorization body. Throw to reject discharge issuance. |
| `constraint(config)` | yes | Returns a JSON object to add to newly minted capabilities, or `null` for no default caveat. |
| `authorize(request, config)` | yes | Authorizes every verified request using the credential. |

`constraint` runs during configuration validation and when credential metadata
is requested for minting. Its return value is intentionally exposed as public
capability metadata, so it must select only authorization limits and must never
copy secrets from `config`. `adev` identifies the selected credential when it
mints, causing Vault to add this constraint to the macaroon automatically.

`authorize` receives the same request shape documented for upstream policies,
but `request.constraints` contains only verified caveats in the credential
type's namespace. The callback runs even when that list is empty, so it must
enforce the current credential configuration as the upper bound. Multiple
same-namespace caveats are conjunctive; this allows a holder to append a
narrower caveat offline. A default caveat also preserves the original scope if
the credential configuration is later widened. Narrowing current credential
config takes effect immediately; widening it requires minting a new capability
because an existing macaroon cannot be broadened.

Constraints in other namespaces remain unconsumed and require an explicitly
selected upstream policy. Changing a configured credential type's macaroon
namespace requires a Vault configuration reload; provider-only hot reloads
that change it are rejected.

`constraintSchema` is public provider metadata. Vault validates an
authorization body against it immediately before issuing the third-party
discharge, then embeds the validated body under `namespace`. It is independent
of `configSchema`: the former describes authority supplied by an external
authorizer, while the latter describes the stored credential itself. A primary
macaroon minted for a named authorization also carries a requirement for the
namespace, so a valid but constraint-free discharge fails verification.

## `registerCredentialProvider`

`registerCredentialProvider` resolves the upstream headers for one configured
credential after its agent-creds capability has been verified.

```js
registerCredentialProvider({
  name: "session-primary",
  credentialType: "session",
  priority: 100,
  cache: "credential",
  match: {
    hosts: ["api.example.com"],
    methods: ["GET", "POST"],
    paths: ["/v1/**"],
  },
  validate(config) {
    // Throw to reject startup or reload.
  },
  resolve(request, config) {
    return {
      headers: { authorization: "Bearer " + config.token },
      expiresAt: 1893456000,
      stop: true,
    };
  },
});
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique provider registration name. |
| `credentialType` | yes | Exact type or `"*"`. |
| `priority` | no | Numeric ordering value; lower values run first. |
| `cache` | no | The only supported value is `"credential"`. |
| `match` | no | Host, method, and path restrictions. |
| `validate(config)` | no | Provider-specific configuration validation. Throw to reject activation. |
| `resolve(request, config)` | yes | Returns headers and optional caching/layering controls. |

`validate` runs for every configured credential whose type matches the
registration, regardless of the request matcher. Configuration contains the
provider-specific fields from `vault.yaml`, with `$secret` references already
resolved. Selection metadata such as `type`, `env`, `policy`, and
`capabilities` is not included.

### Provider request

```js
{
  credential: "service/prod",       // configured credential name
  credentialType: "session",
  host: "api.example.com",
  method: "GET",
  path: "/v1/records?limit=10",
  headers: { /* original request headers */ },
  body: new ArrayBuffer(0),          // buffered raw request prefix
  bodyPartial: false,
}
```

Header values and other request facts remain caller-controlled. Do not treat
them as secrets or authorization decisions. A pass-through credential type
may deliberately return the incoming authorization header, but only after its
extractor has required a capability and its macaroon authorizer or selected
policy has consumed every application constraint.

`body` is an `ArrayBuffer` containing at most the first 8 KiB of the request
body. `bodyPartial` is true when Envoy stopped buffering at that limit. Parse
binary protocols through a `Uint8Array`, and fail closed if the complete
authorization-relevant prefix is not present. Request bodies are available
only to verified provider and policy callbacks, not pre-verification
extractors.

### Provider result

`resolve` returns an object with these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `headers` | yes | Object whose names and values are strings. The combined provider result must contain at least one header. |
| `expiresAt` | no | Positive Unix timestamp in seconds. Required for caching. |
| `stop` | no | When truthy, prevents later matching providers from running. |

Vault rejects invalid header names and multiline values. When registrations
are layered, later providers overwrite earlier values with the same
case-insensitive header name. The earliest positive expiry becomes the
combined expiry. If any matching provider omits an expiry, the combined result
is not cacheable.

### Credential caching

`cache: "credential"` caches the combined result on the configured credential
instance. Caching is enabled only when every registration matching that
request declares the same cache scope and the combined result has an
`expiresAt`. Vault refreshes a cached result when fewer than 30 seconds remain
and clears caches when the runtime generation changes.

The cache key does not include host, method, path, headers, or body. Use
credential caching only when every request matched by the registrations can
reuse the same result.

## `registerCredentialExtractor`

`registerCredentialExtractor` translates service-specific client framing into
an agent-creds capability before verification.

```js
registerCredentialExtractor({
  name: "session-client-auth",
  credentialType: "session",
  priority: 100,
  match: { hosts: ["api.example.com"] },
  extract(request) {
    const match = /^Session\s+(.+)$/.exec(
      request.headers["x-service-authorization"] || "",
    );
    return match ? match[1] : null;
  },
});
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique extractor registration name. |
| `credentialType` | yes | Exact type or `"*"`. |
| `priority` | no | Numeric ordering value; lower values run first. |
| `match` | no | Host, method, and path restrictions. |
| `extract(request)` | yes | Returns a token string or `null`/`undefined`. |

The request contains the provider request's credential, credential type, host,
method, path, and headers, but no body or configuration argument. Extractors
run in priority order. The first non-empty returned string is trimmed and sent
to the Go verifier. Empty and nullish results continue to the next extractor.
Returned tokens are limited to 64 KiB.

The extractor VM has no `$http`, `$exec`, `$jwt`, resolved configuration, or
provider-zone `$base64.encode` function.

## `registerUpstreamPolicy`

`registerUpstreamPolicy` authorizes verified request facts and application
constraints.

```js
registerUpstreamPolicy({
  name: "records-scope",
  policyType: "records_scope",
  validate(config) {
    if (!config.required_scope) throw new Error("required_scope is required");
  },
  authorize(request, config) {
    return request.constraints.every(
      (constraint) =>
        constraint.namespace === "records" &&
        constraint.body.scopes.includes(config.required_scope),
    );
  },
});
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique policy registration name. |
| `policyType` | yes | Exact type or `"*"`. |
| `validate(config)` | no | Policy configuration validation. Throw to reject activation. |
| `authorize(request, config)` | yes | Returns a boolean or `{ allow, reason? }`. |

Policy configuration contains the inline fields under a configured policy,
excluding `type`. The request object is:

```js
{
  policy: "records/read",            // configured policy name
  policyType: "records_scope",
  host: "records.internal",
  method: "GET",
  path: "/v1/records",
  body: new ArrayBuffer(0),          // same 8 KiB prefix as providers receive
  bodyPartial: false,
  credential: "service/prod",        // may be empty without a configured credential
  credentialType: "session",         // may be empty without a configured credential
  constraints: [
    {
      namespace: "records",
      body: { scopes: ["records:read"] },
      authorized: true,
    },
  ],
}
```

`constraints` come from the verified macaroon. Credential-bound macaroon hooks
consume their own namespace first, so an explicit policy receives the
remaining constraints. A policy must evaluate every constraint it receives
conjunctively and reject namespaces it does not understand. Policy
registrations have no priority or request matcher; matching registrations run
by source path and name until one denies. All registrations matching the
selected policy type must allow the request. `false` uses a generic denial
reason; an object can supply a specific reason.

`authorized` is true only for a constraint carried by a verified third-party
discharge. A policy that relies on an external authorizer, rather than ordinary
holder-added attenuation, must require it.

Credential type schemas do not apply to policy configuration. Use the policy
registration's `validate(config)` callback for policy configuration checks.

## Provider and policy globals

### `$http.request(options)`

Performs a synchronous HTTP request within the active callback's context.

```js
const response = $http.request({
  method: "POST",                    // defaults to GET
  url: "https://auth.example/session",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ assertion }),
});

// response = {
//   status: 200,
//   headers: { "content-type": ["application/json"] },
//   body: "...",
// }
```

`url` must be an absolute `http` or `https` URL. Header values must be strings.
Redirects are returned rather than followed. Response header names are
lowercase and each value is an array. Response bodies are limited to 4 MiB.

### `$exec.run(command, args?, options?)`

Executes a program directly without a shell and returns trimmed standard
output.

```js
const assertion = $exec.run(
  "/usr/local/bin/session-helper",
  ["assertion", "--audience", config.audience],
  {
    env: {
      HOME: "/tmp",
    },
    stdin: JSON.stringify({
      accessToken: config.access_token,
      challenge: config.challenge,
    }),
  },
);
```

Arguments and environment values must be strings. The child starts with an
empty environment; `env` defines its complete environment. `stdin` supplies a
string directly to the child's standard input, which keeps secret material out
of argv and the child environment. Unknown option names are rejected.

Standard output is limited to 4 MiB and standard error to 64 KiB. A non-zero
exit raises an exception and includes captured standard error. Use an absolute
executable path, supply only the environment values the helper needs, and never
interpolate request values into a shell command.

### `$jwt.expiresAt(token)`

Reads the numeric `exp` claim from a three-part JWT and returns it as a Unix
timestamp in seconds. It returns `0` for malformed tokens or missing/invalid
claims. This helper does not verify the token or any claim; use it only to set
cache timing for a credential obtained from a trusted issuer.

### `$base64.encode(value)`

Returns standard padded base64 for a string. It is available to providers and
policies.

### `$log.debug`, `$log.info`, `$log.warn`

Each function writes one string to Vault logs. Do not log credential
configuration, capabilities, authorization headers, or helper output that can
contain secrets.

## Extractor globals

### `$base64.decode(value)`

Decodes a standard padded base64 string. Invalid input raises an exception.

### `$log.debug`, `$log.info`, `$log.warn`

The extractor-zone logging functions write one string to Vault logs. Extractor
request headers are unverified and can contain capabilities or other sensitive
client material; do not log them.

## Errors and time limits

Script initialization and configuration validation callbacks have a two-second
execution limit. Provider and policy request callbacks have a 30-second limit,
bounded further by cancellation of the incoming request. Extractors have a
100-millisecond limit.

An exception during initialization or configuration validation rejects startup
or reload. An exception during extraction, authorization, or resolution fails
that request. `$http` and `$exec` use the active callback context and are
canceled with it.

See the complete provider and extractor example in
[`examples/providers/command-session.provider.js`](../../examples/providers/command-session.provider.js)
and the policy example in
[`examples/policies/constraint-scope.policy.js`](../../examples/policies/constraint-scope.policy.js).
