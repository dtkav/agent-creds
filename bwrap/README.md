# native-sandbox

Claude Code's native bwrap sandbox as the CONFINEMENT layer, with the
existing envoy + vault stack unchanged as the CREDENTIAL / EGRESS plane.
The goal is agent-creds' security model without gVisor or per-agent
containers: the agent process runs on the host, every Bash command it
issues runs inside a per-command bubblewrap sandbox whose only network
exit is envoy.

```
claude (host process, trusted)
    └─ each Bash command → bwrap sandbox
           egress → 127.0.0.1:10000 (envoy-forward)
                       └→ envoy CONNECT listener :10000 (TLS bump, CA)
                              └→ vault (macaroon check, credential inject)
                                     └→ real upstream
```

Because each command is confined, Claude Code skips its permission
prompt for it (`autoAllowBashIfSandboxed`) — the interactive permission
frontier is replaced by this infrastructure, which is the point.

## Files

- `settings.json` — the Claude Code settings profile: sandbox on,
  auto-allow on, and egress via `httpProxyPort: 10000`.
- `envoy-forward.sh` — bridges `127.0.0.1:10000` to a running instance's
  envoy container (socat; resolves the container IP by instance name).
- `test.sh` — end-to-end: starts the forward, launches a disposable
  Claude session under `--settings settings.json`, has it fetch an
  allowed domain (expect: success, no prompt, envoy access log entry)
  and a non-configured domain (expect: blocked), and reports. It exports
  the repository-generated CA bundle to the Claude process.

## Run

```bash
./envoy-forward.sh myproject &
./test.sh
```
