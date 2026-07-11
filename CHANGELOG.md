# Changelog

## 0.1.1

- **Renamed: `@askalf/keeper` → `@askalf/strongroom`** (npm-publishable name; `keeper` is squatted unscoped and the registry create-policy blocks colliding scoped names). GitHub repo becomes `askalf/strongroom` (old URLs redirect). Legacy `keeper` bin alias retained alongside the new `strongroom` bin; `KEEPER_*` env vars and `~/.keeper` unchanged.

All notable changes to **@askalf/keeper** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Operator-set grant ceiling** — `KEEPER_MAX_TTL` (seconds) and
  `KEEPER_MAX_USES` cap every lease minted from the vault, enforced in the
  shared mint path so the CLI and the library `grant()` obey the same policy.
  An over-cap grant is **rejected** with an error naming the cap (never
  silently clamped) and audited as a `deny`/`policy` event. Unset = no
  ceiling (unchanged behavior). Zero, negative, and non-numeric `--ttl` /
  `--uses` are now always rejected — a `NaN` previously minted a lease that
  never expired and never exhausted. (#29)
- **Master-key rotation** — `keeper rekey [--to passphrase|keychain|file]`
  re-encrypts every secret under a fresh master key, optionally migrating
  between key stores (a passphrase target reads `KEEPER_NEW_PASSPHRASE`).
  Runs under the same cross-process lock as redeem (a rotation can't
  interleave with a decrypt), decrypts everything up front so a wrong
  passphrase aborts with **nothing changed**, stages the re-encrypted vault
  and commits it with an atomic rename, retires old key material (salt / key
  file / keychain entry — the old keychain key is parked under a second
  keychain account during the swap, never plaintext on disk), completes or
  discards an interrupted swap on the next run, and re-MACs the audit's
  authenticated tip under the new key (the tip is keyed off the master key —
  a rotation that skipped this would break `keeper audit --verify`). Audited
  as a `rekey` event. Running daemons/brokers hold the old key and fail
  closed — restart them after rotating.
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
