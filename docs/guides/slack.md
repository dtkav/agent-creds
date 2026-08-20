# Protect a Slack bot token

This guide gives one sandbox access to one Slack Web API method without putting
the Slack token inside the sandbox. The agent sends an `acm_` capability;
Vault replaces it with the bot token only after the request passes its host,
method, and path restrictions.

Slack's [`auth.test`](https://docs.slack.dev/reference/methods/auth.test) method
is a useful first check: it accepts a bearer token, requires no additional
scope, and returns the identity associated with that token.

## Before you begin

You need:

- a working agent-creds installation;
- a Slack app installed in a workspace; and
- a bot or user token for that installation.

Use the narrowest Slack scopes your real workflow permits. Treat the token as
a secret even when working in a development workspace.

## 1. Store the token in Vault

Open the encrypted Vault configuration:

```console
$ actl vault edit
```

Add a Slack secret below the existing `secrets` mapping. Leave the generated
Vault signing and encryption keys unchanged:

```yaml
secrets:
  slack:
    BOT_TOKEN: xoxb-replace-with-your-token
```

Add a bearer credential:

```yaml
credentials:
  slack/dev:
    type: bearer
    token:
      $secret: slack#BOT_TOKEN
    env: SLACK_BOT_TOKEN
    capabilities:
      hosts: [slack.com]
      endpoints:
        - methods: [POST]
          paths: [/api/auth.test]
          description: Verify the Slack token identity
```

Raw tokens belong only below `secrets`; SOPS encrypts that subtree.

## 2. Allow one Slack method

Add the upstream to the project agent's `sandbox.toml`:

```toml
[sandbox]
runtime = "bwrap"
agent = "codex"

[upstream."slack.com"]
credential = "/slack/dev"
methods = ["POST"]
paths = ["/api/auth.test"]
```

This route does not allow other Slack API methods. Add each additional method
deliberately as the workflow grows.

## 3. Start the sandbox

```console
$ adev console
```

Inside the sandbox, verify that the environment contains a capability rather
than a Slack token:

```console
$ printf '%.4s\n' "$SLACK_BOT_TOKEN"
acm_
```

Then call Slack normally:

```console
$ curl -sS -X POST https://slack.com/api/auth.test \
    -H "Authorization: Bearer $SLACK_BOT_TOKEN"
{"ok":true,"url":"https://example.slack.com/",...}
```

Slack often reports API errors in a successful HTTP response, so check the
JSON `ok` field as well as curl's exit status.

## 4. Confirm the boundary

An unlisted Slack method is outside the route:

```console
$ curl -sS -X POST https://slack.com/api/api.test \
    -H "Authorization: Bearer $SLACK_BOT_TOKEN"
```

The request is rejected before Slack receives the credential. Inspect the
authorization decision with `actl vault log`.

To add a write operation such as `chat.postMessage`, first grant the Slack app
the corresponding scope, then add exactly `/api/chat.postMessage` and `POST`
to both the credential capabilities and project route.

See Slack's [Web API documentation](https://docs.slack.dev/apis/web-api/) for
its bearer-header and request-body conventions.
