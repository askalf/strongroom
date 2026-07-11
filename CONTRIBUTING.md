# Contributing to strongroom

Thanks for your interest in improving **strongroom** — own your agent secrets.
Your AI agent holds a scoped, single-use lease, never the raw API key;
strongroom injects the real secret only at egress, so a leaked prompt or a
poisoned tool can't leak a credential. Encrypted vault, tamper-evident audit,
zero runtime dependencies. Part of the agent-security stack (redstamp ·
truecopy · strongroom) — part of
[Own Your Agent Security](https://sprayberrylabs.com).

## Ground rules

- Be respectful. This project follows our [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a security issue? **Do not open a public issue** — follow
  [SECURITY.md](SECURITY.md) to report it privately.

## Development setup

strongroom is a Node.js package. You need Node.js **20 or 22** (the versions CI
tests against).

```bash
git clone https://github.com/askalf/strongroom.git
cd strongroom
npm ci        # install from the frozen lockfile
npm test      # run the full test suite (node --test)
```

## Making a change

1. Branch off `master`.
2. Keep the change focused — one concern per PR.
3. Add or update tests for any behavior change. strongroom protects credentials,
   so changes to the encrypted vault, the lease lifecycle, the egress-time
   secret injection, or the audit trail must be covered by tests.
4. Run `npm test` locally before pushing.
5. Open a pull request against `master`.

## What CI requires

Every PR must pass these checks to merge:

- `test` on **ubuntu-latest** and **windows-latest** × Node **20** and **22**
  (the `test (<os>, <node>)` matrix)
- **CodeQL** static analysis (`analyze (javascript-typescript)`)

OpenSSF Scorecard and ClusterFuzzLite fuzzing also run on the repo; a discovered
crash or a new high-severity finding will block the change.

## Conventions

- GitHub Actions are **pinned to a commit SHA**, never a mutable tag. New or
  updated workflow steps must keep this.
- Commit messages: short imperative subject, with a wrapped body explaining the
  *why* when it isn't obvious.
- PRs are squash-merged, so your PR title becomes the commit subject on `master`.

## Releases

Releases are automated: bump `version` in `package.json` on `master` and
`auto-release.yml` tags it, cuts a GitHub release from `CHANGELOG.md`, and
publishes to npm via OIDC trusted publishing (no tokens). A normal PR needs no
release steps.
