# Antigravity ACP bridge

A local adapter between an OpenAI Responses-compatible client and an existing
Google Antigravity ACP installation. It is an independent project, not an
official Google or OpenAI product. You provide the upstream executable, your
own authorized login, and a locally generated bridge token; this repository
contains no executable, account credentials, subscription, or private setup.

```text
Codex / Responses client -> loopback HTTP bridge -> isolated agy ACP -> upstream
                                  |
                                  +-> client-side tool requests (when enabled)
```

The bridge supports streaming and non-streaming Responses requests, a model
list, client-side tool calls, image deduplication, and context compaction. When
ACP's text budget is exceeded, it prioritizes the first task, the newest user
message and recent history, and marks omitted content. It rejects an oversized
newest user message instead of silently discarding it. It also recognizes a
specific ACP interruption and can retry once within the existing deadline.

## Security boundaries

- The HTTP listener accepts loopback addresses only and requires a bearer
  token for model endpoints. Other processes with that token can use it.
- An expected SHA-512 pins the configured `agy` executable. A hash only proves
  identity against the supplied digest; verify the executable and digest using
  a trusted source **before** setup.
- The ACP runtime is isolated; native ACP tools are disabled, permission
  requests are cancelled, and native tool-call updates abort the request.
  Client-side tools may still run under the client's own permissions.
- Accounts, rate limits, availability, regional access, and acceptable use are
  determined by the upstream provider. This project cannot guarantee them.

See [security notes](docs/security.md) and the optional
[SSH and network design](docs/ssh-and-network.md) before enabling remote access.

## Quick start

Requirements: Python 3.9 or later, a working Antigravity ACP executable and
an authorized native login. Model IDs are only available if offered by your
upstream account. No Python packages are required for the bridge.

1. Verify the upstream binary and obtain its expected SHA-512 from a trusted
   source. Then create a **new** private directory (existing paths are never
   overwritten):

   ```sh
   python3 bootstrap.py --agy /path/to/verified/agy \
     --sha512 YOUR_VERIFIED_SHA512 --client-version YOUR_CLIENT_VERSION
   ```

   On Windows, run the equivalent command in PowerShell using `py -3` and the
   path to `agy.exe`. To choose a new location, add `--root /path/to/new-dir`.
   The script prints the config path, but never prints the generated token.

2. Validate and start the bridge with that path:

   ```sh
   python3 antigravity_acp_bridge.py --config /path/to/new-dir/bridge_config.json --check-only
   python3 antigravity_acp_bridge.py --config /path/to/new-dir/bridge_config.json
   ```

   Quote paths containing spaces. The default URL is `http://127.0.0.1:18045`;
   `GET /health` is unauthenticated, while `/v1/models` and `/v1/responses`
   require the token from `auth_token.txt`. Keep the config directory private.

3. Connect a Responses client using `http://127.0.0.1:18045/v1` and the bearer
   token. An isolated Codex example is in [docs/codex.md](docs/codex.md).
   The optional CC Switch helper can modify local provider data; review and
   back up your configuration before using its activation commands.

## Tests

```sh
python3 -B -m unittest -v test_bootstrap.py test_antigravity_acp_bridge.py
```

The tests use a mock ACP executable and loopback HTTP server; they do not need
an upstream login. Windows uses `py -3 -B -m unittest ...`. The optional router
guard has a separate, isolated test suite described in its directory.

## Limitations

The adapter is a subset implementation, not a complete Responses API. Model
availability and ACP behavior can change. Image history is deduplicated within
a 20 MiB budget, with omitted images marked in context. The request body is
limited to 64 MiB. Long text history is reduced before sending, so a model may
need a fresh summary or file reference for older details. The in-memory
`previous_response_id` cache is process-local and does not survive a restart.

The upstream ACP executable and this bridge do not come with a promise of
production support. Review changes, protect local files and use a separate
workspace before integrating with an existing installation.
