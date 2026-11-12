# SSH and optional network design

A remote workspace can use a bridge on the initiating machine through an SSH
reverse forward. For example, if the local bridge listens on `18045`, an
authenticated SSH connection can expose it on the remote host's loopback
port `28046`:

```sh
ssh -N -R 127.0.0.1:28046:127.0.0.1:18045 example-host
```

Configure the remote client's base URL as `http://127.0.0.1:28046/v1` and
provision the bearer token to that trusted remote account through your own
secure channel. The remote account can then use the local bridge while the
SSH tunnel is connected. Do not expose the forwarded port publicly, copy
SSH private keys, disable host-key verification, or commit the token.

For routers that switch upstream paths, an optional connection guard is in
[`router-guard/`](../router-guard/README.md). It illustrates a fail-closed
design: identify only the intended local application's source sockets, wait
until tasks and connections are quiet, recheck the selected upstream, and
close at most one matching stale connection. Treat router integration as
site-specific: source paths, access controls, proxy group names, identity
verification and rollback must be configured and tested independently.

A separate subscription selection policy can validate candidate configuration,
test a staged configuration before activation, preserve an existing healthy
route, and roll back only when concurrent changes are absent. This repository
does not include a real subscription, controller secret, node list or a
one-click router deployment. Region probes cannot prove account eligibility.
