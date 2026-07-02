# Changelog

All notable changes to **@askalf/keeper** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Broker response sanitizer.** The broker injects the secret upstream — now it
  also makes sure the secret can't come *back*: if the upstream reflects the
  injected key (echo/debug endpoints, verbose errors, misconfigured proxies),
  the broker redacts it from the relayed response headers and body
  (`[keeper:redacted]`) and records a `sanitize` audit event. The body scan is
  streaming-safe (SSE flows through event-by-event; a secret split across chunk
  boundaries is still caught) and the upstream request is pinned to
  `accept-encoding: identity` so the scan always sees the real bytes.
- **Per-lease concurrency cap** — `keeper grant … --concurrency <n>` bounds
  *simultaneous* in-flight broker requests per lease (the existing `--rate`
  bounds requests-per-minute). Enforced before redeem: an over-cap request gets
  `429`, consumes no use, and is audited (`deny` / `concurrency`).

### Fixed
- **Broker no longer relays a stale `content-encoding` header.** `fetch()`
  hands the broker a *decoded* body; passing the upstream's `content-encoding`
  through mislabeled the re-streamed response for any client that asked for
  compression. The header is now stripped (and upstream compression is not
  requested at all — see the sanitizer note above).
- **Redeem-daemon socket is now owner-only (`0600`).** The Unix domain socket
  that serves decrypted secrets was created at the ambient umask and never
  `chmod`ed, so it landed group/other-accessible (`0755` under the default
  `umask 0022`, `0777` under `umask 000`). Because `connect()` on a Unix socket
  requires write permission on the socket node, another local user could reach
  the secret-serving endpoint — the one keeper artifact NOT locked down, while
  the vault, leases, audit, master key, and the token-bearing `daemon.json` are
  all already `0600`. The daemon now `chmod 0600`s the socket the instant it is
  bound, before the capability token is published (no-op on Windows named pipes).
  This is the local-socket-exposure class (CWE-732 / CWE-276) — the `docker.sock`
  family of bugs. Pinned by a regression test that forces `umask 000` and asserts
  the socket carries no group/other bits.

## [0.1.0] - 2026-06-16

First public release — own your agent secrets: hand agents leases, not keys.

### Added
- **Vault** — secrets encrypted at rest (AES-256-GCM, with the secret name
  bound in as AAD). Master key from a passphrase (scrypt), the OS keychain
  (macOS Keychain / Linux Secret Service / Windows DPAPI), or a `0600` key file.
- **Leases** — `grant` mints an opaque, hashed handle bound to a TTL, a use
  count, and (optionally) a destination host. The agent holds the lease, never
  the key. Single-use redeem is atomic (no double-spend); a denial never burns a
  use; every access fails **closed**.
- **Egress broker** — point an agent's HTTP client at `keeper broker` and the
  real key is injected at the network boundary, scoped to one upstream, with a
  per-lease path allowlist and rate cap. The secret never enters the agent.
- **Redeem-daemon** (`keeper serve`, `@askalf/keeper/daemon` + `/client`) — a
  long-lived local process that HOLDS the master key and answers lease→secret
  over a local socket (unix domain / Windows named pipe; token-gated, never TCP).
  A doer (or a remote agent) sets `KEEPER_DAEMON=1` + `KEEPER_SOCKET` +
  `KEEPER_DAEMON_TOKEN` and redeems its leases **without ever holding the master
  key** — the no-key-on-device counterpart to the broker, for credentials a tool
  consumes directly (e.g. a `GIT_ASKPASS` that runs `keeper redeem`).
- **exec** — `keeper exec <lease> --as ENV -- <cmd>` runs a child with the
  secret in *its* environment only.
- **Tamper-evident audit** — every grant / redeem / deny / revoke is hash-chained
  (shared with `@askalf/warden`); editing a past entry breaks `keeper audit
  --verify`. Leases are logged by fingerprint, never raw.

[0.1.0]: https://github.com/askalf/keeper/releases/tag/v0.1.0
