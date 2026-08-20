# Protect a Stripe API key

This guide gives one sandbox read-only access to a small part of the Stripe
API without putting a Stripe key in the sandbox. Use a sandbox-mode or
restricted key while testing—never begin with a live secret key.

Stripe authenticates API requests with HTTP Basic authentication: the API key
is the username and the password is explicitly empty. See Stripe's
[authentication reference](https://docs.stripe.com/api/authentication) and
[API key guidance](https://docs.stripe.com/keys).

## 1. Store a test key in Vault

Open the encrypted configuration:

```console
$ actl vault edit
```

Add the key below the existing `secrets` mapping:

```yaml
secrets:
  stripe:
    API_KEY: sk_test_replace_with_your_key
```

Add a Basic-auth credential. The empty password is intentional and matches
Stripe's documented authentication scheme:

```yaml
credentials:
  stripe/test:
    type: basic
    username:
      $secret: stripe#API_KEY
    password: ""
    env_user: STRIPE_PROXY_USER
    env_pass: STRIPE_PROXY_PASSWORD
    capabilities:
      hosts: [api.stripe.com]
      endpoints:
        - methods: [GET]
          paths: [/v1/customers, /v1/customers/**]
          description: List and retrieve test customers
```

The agent receives capability values in the proxy variables. It does not
receive `sk_test_...`.

## 2. Restrict the project route

Add the same host, method, and path boundary to `sandbox.toml`:

```toml
[sandbox]
runtime = "bwrap"
agent = "codex"

[upstream."api.stripe.com"]
credential = "/stripe/test"
methods = ["GET"]
paths = ["/v1/customers", "/v1/customers/**"]
```

Both layers matter: the project route controls sandbox egress, while the
macaroon and Vault credential policy enforce the request at authorization
time.

## 3. Start the sandbox and call Stripe

```console
$ adev console
```

Inside the sandbox, the Basic-auth password position contains the macaroon:

```console
$ printf 'password-prefix=%.4s\n' "$STRIPE_PROXY_PASSWORD"
password-prefix=acm_
```

Use those proxy values as ordinary Basic credentials:

```console
$ curl -sS 'https://api.stripe.com/v1/customers?limit=3' \
    -u "$STRIPE_PROXY_USER:$STRIPE_PROXY_PASSWORD"
{"object":"list","data":[...]}
```

Vault extracts the macaroon from the sandbox's Basic password, verifies the
request, and replaces the header with `API_KEY:` before forwarding it to
Stripe.

## 4. Confirm the boundary

The route rejects writes and unrelated resources even though the underlying
Stripe key may be broader:

```console
$ curl -sS -X POST https://api.stripe.com/v1/customers \
    -u "$STRIPE_PROXY_USER:$STRIPE_PROXY_PASSWORD"

$ curl -sS https://api.stripe.com/v1/balance \
    -u "$STRIPE_PROXY_USER:$STRIPE_PROXY_PASSWORD"
```

Review denied requests with `actl vault log`. For production workflows, pair
the path restrictions with a Stripe restricted key so the upstream credential
is independently least-privileged.
