# JavaScript extension examples

Vault's JavaScript runtime is a trusted deployment extension point. Providers
resolve upstream credentials; policies authorize verified request facts. The
agent can select configured credentials and policies, but it must not be able
to add or edit the scripts loaded by Vault.

This directory contains two deployment-neutral examples:

- [`providers/command-session.provider.js`](providers/command-session.provider.js)
  invokes a separately installed credential helper with a minimal child
  environment and caches the returned session until expiry.
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
    ACCESS_TOKEN: replace-with-the-helper-token

credentials:
  service/prod:
    type: command_session
    command: /usr/local/bin/session-helper
    audience: api.service.example
    access_token:
      $secret: service#ACCESS_TOKEN
    env: SERVICE_API_TOKEN
```

The helper is expected to print one JSON object to standard output:

```json
{"access_token":"eyJ...","expires_at":1893456000}
```

`expires_at` is a Unix timestamp. It may be omitted when `access_token` is a
JWT with an `exp` claim.

Configure the policy independently:

```yaml
policies:
  records/read:
    type: subject_scope
    namespace: records
    required_scope: records:read
```

Then select `/service/prod` or `/records/read` from the appropriate upstream
in `agent-creds.toml`.

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
