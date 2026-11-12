# Optional router connection guard

This is a site-independent adaptation of an OpenClash connection guard. It is
separate from the bridge and is **not required** to use the bridge. It has only
been tested here with synthetic data and a loopback fake controller; it has
not been validated on your router. Review it and test it in an isolated setup
before using it on a real network.

The macOS reporter finds established TCP source tuples owned by a configured
Antigravity language server, checks an aggregate conversation-state database,
and sends a short-lived report over an existing authenticated SSH connection.
It does not send the remote endpoints, raw logs, conversations, or credentials.
The router guard matches a fresh report against a configured client MAC and
the router's neighbor table. It rechecks task idleness, traffic, selected
upstream and destination before deleting a **single** stale matching
connection. Missing identities, unknown state or stale reports stop cleanup.

## Adaptation

- Set `ACP_GUARD_CLIENT_MAC` privately on the router to the intended client's
  MAC address. An empty or invalid value fails closed.
- Set `ACP_GUARD_CONFIG` to the router's local OpenClash runtime config,
  `ACP_GUARD_TARGET` to the intended proxy group and optionally
  `ACP_GUARD_FALLBACK` to a permitted older group. The defaults are examples.
- The neighbor lookup currently assumes the `br-lan` interface. Adapt it to
  your own router and verify how client identities are observed.
- On the Mac, set `ACP_GUARD_ROUTER` to a trusted SSH alias. If the language
  server is installed elsewhere, set `ACP_GUARD_SERVER` to its exact resolved
  executable path. Install the feed script at the path referenced by the
  reporter or change that path deliberately. Restrict the SSH key and remote
  command to the least permissions your environment permits.
- The reporter's idle check depends on a private Antigravity database schema,
  not an upstream locking API. A schema change or missing data fails closed;
  sampling cannot eliminate the race between checking and closing a connection.

No actual MAC, private IP, router address, SSH key, proxy credentials, node
names or live configuration belongs in this directory or in a public issue.
The examples in tests use documentation-only addresses.

## Isolated tests

```sh
ruby test_guard.rb
python3 -B -m unittest -v test_reporter.py
python3 -B test_controller_integration.py
```

The final command uses a fake HTTP controller on loopback and checks one
authenticated targeted DELETE. It does not contact or modify a real router.
