# Codex integration

Use a separate `CODEX_HOME` for a first test so an existing configuration is
not overwritten. The provider uses the environment variable named by
`env_key`; the token should be read from your private file, never pasted into
a public project. See the [Codex configuration reference](https://developers.openai.com/codex/config-file/config-reference.md).

Example configuration in the isolated Codex home:

```toml
model_provider = "antigravity_local"
model = "gemini-4-carbon"
model_reasoning_effort = "high"

[model_providers.antigravity_local]
name = "Local ACP bridge"
base_url = "http://127.0.0.1:18045/v1"
wire_api = "responses"
env_key = "ANTIGRAVITY_BRIDGE_TOKEN"
supports_websockets = false
```

Set `ANTIGRAVITY_BRIDGE_TOKEN` in the environment of the Codex process to the
contents of your private `auth_token.txt`. An environment variable in one
terminal is not automatically available to an already running desktop app.
Available model names and supported reasoning levels must be checked against
your own upstream session.

`agy_ssh_lan.py` provides an optional CC Switch integration. It reads and
writes local CC Switch data and, when activated, updates Codex configuration.
Back up those files first and inspect `--help`. `register-ccswitch` without
`--activate` registers a provider without switching it. `local-disable`
restores the saved pre-activation configuration; inspect subsequent changes
before running it because restoring an old snapshot can overwrite them.
