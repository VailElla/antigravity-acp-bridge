# Security and privacy

The bridge is intended for one trusted local user. Bind only to loopback; the
server rejects non-loopback listener addresses. A bearer token is a credential:
any process that can read it can send requests through your account. On POSIX,
the bootstrapper creates a private directory and token file. On Windows, it
removes inherited directory ACLs and grants the current user and LocalSystem
access; check the actual ACLs if your environment applies additional policy.

The upstream `agy` executable is not included. The bridge compares it with the
configured SHA-512 before use. Verify its publisher, distribution channel and
digest independently; computing a hash from an unknown binary is not origin
verification. The bridge does not export native OAuth credentials.

Each active request uses an isolated ACP profile. Native ACP tool declarations
and permission requests are disabled or rejected. The Responses client may
still execute tools requested by the model, so use the client's normal sandbox,
approval and filesystem protections. Isolation does not turn an untrusted
model response into a trusted instruction.

Conversation data and images are sent to the upstream service. A process-local
response cache can contain recent messages. Protect the host, backups, logs and
token-bearing Codex or CC Switch configurations accordingly. Do not put live
tokens, chat transcripts, local paths, router configs, connection reports or
provider credentials in a public issue or repository.

If you discover a vulnerability, use the repository's private vulnerability
reporting channel when available and avoid publishing working credentials.
