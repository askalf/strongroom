# Changelog

## 0.1.1

- **Renamed: `@askalf/keeper` → `@askalf/strongroom`** (npm-publishable name; `keeper` is squatted unscoped and the registry create-policy blocks colliding scoped names). GitHub repo becomes `askalf/strongroom` (old URLs redirect). Legacy `keeper` bin alias retained alongside the new `strongroom` bin; `KEEPER_*` env vars and `~/.keeper` unchanged.

All notable changes to **@askalf/keeper** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-07-16

### Added

- **Lease delegation (attenuation).** A parent agent turns its OWN lease into a
  narrower sub-lease for a sub-agent with `strongroom grant --from-lease <lease>
  [tighter opts]` (library: `grantFromLease(parentId, opts)`). Every scope can
  only be **narrowed, never widened**: a shorter `--ttl` (a sub-lease may not
  outlive its parent), fewer `--uses` (≤ the parent's remaining), a tighter
  `--host`/`--upstream` (inherit-or-tighten, never redirect), a smaller
  `--rate`/`--concurrency` cap (or add one where the parent had none), and a
  `--paths` allowlist that must be a **subset** of the parent's (glob-subset
  checked with the same segment semantics the broker enforces). Any widening
  attempt is **rejected** naming the offending axis, and audited as a
  `deny`/`policy` event. Unset scopes **inherit** the parent's.
- **Delegation audit trail.** The child lease records the **parent lease
  fingerprint**, and the child's `grant` audit event carries it as `from` — so
  the delegation composes with the existing hash-chained, authenticated-tip
  audit into a full parent→child trail that still verifies. `strongroom leases`
  and `strongroom audit` surface the `⤷ from <fp>` provenance.
- Least privilege between agents in a multi-agent tree: a sub-agent can never
  redeem toward anything its parent couldn't. Delegating does **not** consume a
  parent use — the guarantee is per-capability (child scope ⊆ parent scope).

## [0.2.1] - 2026-07-11

### Added

- **Signed releases.** Every GitHub release now ships the npm tarball plus its keyless Sigstore provenance bundle (`<tarball>.sigstore.json`), attested via GitHub OIDC. Verify with `gh attestation verify <tarball> --owner askalf`.

### Changed

- The ClusterFuzzLite build now installs via `npm ci` (integrity-verified against the committed lockfile) and pins the OSS-Fuzz base image by digest.

## [0.2.0] - 2026-07-11

### Added
- **Operator-set grant ceiling** — `KEEPER_MAX_TTL` (seconds) and
  `KEEPER_MAX_USES` cap every lease minted from the vault, enforced in the
  shared mint path so the CLI and the library `grant()` obey the same policy.
  An over-cap grant is **rejected** with an error naming the cap (never
  silently clamped) and audited as a `deny`/`policy` event. Unset = no
  ceiling (unchanged behavior). Zero, negative, and non-numeric `--ttl` /
  `--uses` are now always rejected — a `NaN` previously minted a lease that
  never expired and never exhausted. (#29)
- **Broker upstream timeout** — the broker's upstream request is now bounded
  (default **30 s** to first response headers; `keeper broker --timeout <ms>`,
  `KEEPER_BROKER_TIMEOUT_MS`, or `startBroker({ timeoutMs })`). A black-hole
  upstream gets a structured `504` (audited as `deny`/`timeout`, leaking
  neither secret nor raw lease id) instead of hanging indefinitely — before
  this, a hung upstream pinned its per-lease `--concurrency` slot forever and
  could permanently wedge a concurrency-capped lease until a broker restart.
  A client that disconnects mid-stream now also aborts the upstream request,
  freeing the upstream socket. (#27)
- **`--json` machine contract** for `grant`, `leases`, `ls`, and `audit`
  (incl. `audit --verify`): stdout carries exactly one JSON value — no ANSI,
  no prose, and no stderr summary — so a control plane dispatching leases to
  a fleet scripts keeper instead of scraping decorated output. `grant --json`
  returns the same one-time lease id + metadata the human path already
  returns; `leases --json` stays secret-safe (fingerprints, never raw ids);
  `audit --verify --json` surfaces `{ ok, entries }` / `{ ok:false, reason }`
  with the 0/1 exit code preserved. Default output is unchanged. (#28)
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
- **Continuous fuzzing (ClusterFuzzLite).** The security-critical broker parsers
  (request-target canonicalizer, path allowlist) and the egress lease
  fail-closed contract are now fuzzed with Jazzer.js — weekly in CI
  (`.github/workflows/cflite.yml`) and locally via `npm run fuzz` (targets in
  `./fuzz`). The two Fixed items below were found this way.

### Fixed
- **Broker path canonicalizer no longer leaves a climbing `..`.** A relative
  request target (e.g. `..`) canonicalized to `/..` because the path was
  normalized *before* being anchored to root; it is now anchored first
  (`normalize('/' + path)`) so every `..` is clamped at `/`. Not reachable
  through the broker today (its URL parse already yields a leading `/`), but the
  canonicalizer is now correct for any input — defense in depth for the
  allowlist. (found by fuzzing)
- **Broker path allowlist no longer throws on a `?` in a `--paths` glob.** The
  regex-escape set missed `?`, so a pattern containing it compiled to an invalid
  regex (`SyntaxError: Nothing to repeat`) and 502-ed every request on that
  lease. `?` is now escaped as a literal (only `*` is a keeper wildcard), and any
  un-compilable pattern now matches nothing (fail closed) instead of throwing.
  (found by fuzzing)
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

[0.2.0]: https://github.com/askalf/strongroom/releases/tag/v0.2.0
[0.1.0]: https://github.com/askalf/keeper/releases/tag/v0.1.0
