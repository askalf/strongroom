# Changelog

All notable changes to **@askalf/keeper** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

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
- **exec** — `keeper exec <lease> --as ENV -- <cmd>` runs a child with the
  secret in *its* environment only.
- **Tamper-evident audit** — every grant / redeem / deny / revoke is hash-chained
  (shared with `@askalf/warden`); editing a past entry breaks `keeper audit
  --verify`. Leases are logged by fingerprint, never raw.

[0.1.0]: https://github.com/askalf/keeper/releases/tag/v0.1.0
