# JavaScript extension examples

Vault's JavaScript runtime is a trusted deployment extension point. Providers
resolve upstream credentials; policies authorize verified request facts. The
agent can select configured credentials and policies, but it must not be able
to add or edit the scripts loaded by Vault.

This directory contains two deployment-neutral examples:

- [`providers/command-session.provider.js`](providers/command-session.provider.js)
  demonstrates the complete credential extension surface: schema and semantic
  validation, custom capability extraction, request matching, a minimal child
  process environment, an HTTP session exchange, and credential-scoped caching.
- [`policies/subject-scope.policy.js`](policies/subject-scope.policy.js)
  requires a verified subject and evaluates every application constraint.

## Load the examples locally

Copy only the scripts you intend to trust into the ignored provider directory:

```console
$ cp examples/providers/command-session.provider.js vault/providers.d/
$ cp examples/policies/subject-scope.policy.js vault/providers.d/
```

Docker Compose mounts `vault/providers.d` read-only inside Vault. This is a
development convenience: do not give an untrusted agent write access to this
checkout while Vault is loading scripts from it. Production deployments
should bake reviewed scripts into a private image or mount an
administrator-controlled directory outside every agent worktree.

Configure the command-backed provider in `vault.yaml`:

```yaml
secrets:
  service:
    CLIENT_SECRET: replace-with-the-client-secret

credentials:
  service/prod:
    type: command_session
    command: /usr/local/bin/session-helper
    token_url: https://auth.service.example/session
    client_id: deployment-client
    audience: api.service.example
    allowed_audiences: [api.service.example]
    client_secret:
      $secret: service#CLIENT_SECRET
    env: SERVICE_API_TOKEN
```

The helper receives `SERVICE_CLIENT_SECRET` in an otherwise minimal child
environment and prints an assertion to standard output. Vault exchanges that
assertion at `token_url`. The endpoint response is one JSON object:

```json
{"access_token":"eyJ...","expires_at":1893456000}
```

`expires_at` is a Unix timestamp. It may be omitted when `access_token` is a
JWT with an `exp` claim.

The extractor also accepts custom client framing in which the agent-creds
capability is standard-base64 encoded:

```text
X-Service-Authorization: Session <base64 capability>
```

Returning the decoded value from the extractor does not bypass verification;
Vault verifies it before running the provider.

Configure the policy independently:

```yaml
policies:
  records/read:
    type: subject_scope
    namespace: records
    required_scope: records:read
```

Then select `/service/prod` or `/records/read` from the appropriate upstream
in `sandbox.toml`.

## Build a deployment image

The public Vault image intentionally contains an empty `/app/providers.d`.
A private deployment can install its helper and reviewed scripts in a derived,
digest-pinned image:

```dockerfile
FROM your-registry/agent-creds-vault@sha256:replace-with-a-pinned-digest

COPY session-helper /usr/local/bin/session-helper
COPY providers.d/ /app/providers.d/
```

Remove or override the development bind mount in `docker-compose.yml`; a mount
at `/app/providers.d` would otherwise hide the scripts baked into the image.
Keep the derived Dockerfile, helper, application names, audiences, and secret
configuration in the private deployment repository.

## Runtime boundaries

JavaScript extensions are deliberately trusted. They can make context-bound
HTTP requests, run installed programs, receive resolved credential config,
and return upstream headers. Review them like other credential-plane code.

`$exec.run(command, args, options)` does not invoke a local shell. For helpers
that receive credentials, use an absolute executable path and
`inheritEnv: false`. Never interpolate request-controlled values into a remote
shell command.

The complete registration and helper contract is documented in the
[Vault JavaScript API reference](../docs/reference/vault-js-api.md).
