# strongroom

[![ci](https://github.com/askalf/strongroom/actions/workflows/ci.yml/badge.svg)](https://github.com/askalf/strongroom/actions/workflows/ci.yml)
[![CodeQL](https://github.com/askalf/strongroom/actions/workflows/codeql.yml/badge.svg)](https://github.com/askalf/strongroom/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/askalf/strongroom/badge)](https://scorecard.dev/viewer/?uri=github.com/askalf/strongroom)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> _strongroom — **own your agent secrets**. An encrypted vault that hands agents scoped, short-lived, single-use leases instead of raw keys. Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it by the token._

> _**Formerly `keeper`.** Renamed to `strongroom` for the npm release; the GitHub repo redirects and the legacy `keeper` CLI alias keeps working. `KEEPER_*` env vars and the `~/.keeper` home directory are unchanged for compatibility._

Agents need credentials — API keys, tokens, passwords — to do anything useful. Today they get them the worst possible way: a long-lived key stuffed into an environment variable or, worse, into the prompt. OpenClaw leaked the keys of ~135k exposed instances exactly this way. A key in the model's context is a key in every log, every trace, and every place a poisoned tool can read.

**strongroom holds the keys so the agent doesn't.** The raw secret stays encrypted in the vault; the agent only ever holds a **lease** — a scoped, short-lived, use-limited handle — and the real key is revealed **only at the egress point**, only while the lease is valid:

- **vault** — secrets encrypted at rest (AES-256-GCM, key in `~/.keeper`, `0600`). Never a plaintext env var, never in a prompt.
- **lease** — `grant` mints an opaque handle bound to a **TTL**, a **use count**, and (optionally) a **destination host**. The agent's context holds the lease, not the secret.
- **redeem** — exchange a lease for the secret at the point of use, *iff* it's still valid (not expired, uses remaining, host in scope). A denial is audited and never burns a use.
- **audit** — every grant / redeem / deny / revoke is **hash-chained** (shared with [redstamp](https://github.com/askalf/redstamp)) — editing or deleting a past access breaks `strongroom audit --verify`.

Completes the agent-security stack: **redstamp** contains the call · **truecopy** vets the tool · **strongroom** holds the keys.

## Quick start

> Install: `npm i -g @askalf/strongroom` (or run any command below with `npx -y @askalf/strongroom`). Also installable straight from GitHub: `npm i -g github:askalf/strongroom`.

```bash
echo "sk-live-…" | strongroom add OPENAI_API_KEY          # stored encrypted

LEASE=$(strongroom grant OPENAI_API_KEY --ttl 300 --uses 1 --host api.openai.com)
# → the agent gets $LEASE — not the key

# at the egress point, run the call with the key in the child's env only:
strongroom exec "$LEASE" --as OPENAI_API_KEY -- \
  curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"

strongroom audit --verify                                 # tamper-evident access log
```

The agent dispatched `strongroom exec <lease> …`; the key was decrypted inside strongroom and handed to the subprocess's environment — it never entered the agent's context, stdout, or logs. Run the whole story: `npm run demo`.

## Egress broker — the agent just swaps a base URL

Run the broker and the agent needs no key, no `exec`, no redeem — only a base-URL swap:

```bash
# bind a lease to ONE upstream, how to inject, which endpoints, and a rate cap
LEASE=$(strongroom grant OPENAI_API_KEY \
  --upstream https://api.openai.com --inject bearer \
  --paths "/v1/chat/*,/v1/models" --rate 60 --concurrency 4 --ttl 600 --uses 100)
strongroom broker --port 8771 &
```

Point the agent's client at the broker:

```js
const openai = new OpenAI({ baseURL: `http://127.0.0.1:8771/${LEASE}`, apiKey: 'unused' });
await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [/* … */] });
```

For each call the broker redeems the lease (atomic + audited), makes the **real** upstream request itself with the secret injected (`Authorization: Bearer …`), and streams the response back. The key is injected at the network boundary — it never enters the agent's context, env, or logs. And because the lease is **bound to one upstream**, the secret can only ever go to that host; the agent can't redirect it. `--inject`: `bearer` (default) · `x-api-key` (Anthropic) · `Header-Name` (custom).

**Scope it down further:**
- `--paths "/v1/chat/*,/v1/models"` — restrict the lease to specific endpoints (glob; a chat lease can't reach billing or admin).
- `--rate 60` — cap it at 60 requests/min.
- `--concurrency 4` — cap simultaneous in-flight requests (a runaway or hijacked agent can't hold N parallel streams open through one lease).

All three are enforced **before** the secret is redeemed — an out-of-scope, over-rate, or over-concurrency request gets `403` / `429`, consumes no use, and is audited.

**And the upstream call itself is bounded.** The broker's upstream request times out after **30 s** to first response headers (`strongroom broker --timeout <ms>`, or `KEEPER_BROKER_TIMEOUT_MS`). A black-hole upstream gets a `504` (audited as `deny`/`timeout`) instead of hanging the request forever — which also means a hung upstream can't pin a `--concurrency` slot and wedge the lease. The bound is to *headers*: a healthy streaming response is never cut off mid-stream.

**And the response is sanitized on the way back.** If the upstream ever *reflects* the injected secret — an echo/debug endpoint, a verbose error, a misconfigured proxy — the broker redacts it from the relayed headers and body (`[strongroom:redacted]`) and records a `sanitize` audit event. The scan is streaming-safe: SSE passes through event-by-event, and a secret split across chunk boundaries is still caught. Without this, a reflecting upstream would hand the raw key straight back into the agent's context, defeating the injection boundary.

> **Windows / Git Bash:** MSYS auto-rewrites an argument that looks like a Unix absolute path, so a bare `--paths "/v1/models"` reaches strongroom as `C:/Program Files/Git/v1/models` and silently never matches (every call then `403`s on `path`). A comma-list like `"/v1/chat/*,/v1/models"` is left alone, which is why it works. Prefix the run with `MSYS_NO_PATHCONV=1` (use drive-letter paths for any file args), or call strongroom from PowerShell/cmd. Not a strongroom bug — it mangles the arg before strongroom sees it.

## Redeem-daemon — no master key on the redeeming side

The broker covers HTTP APIs. For credentials a tool consumes *directly* — git over `GIT_ASKPASS`, a CLI that reads a token — the redeem happens in the agent's own process tree, and a local `strongroom redeem` would need the master key there. The **redeem-daemon** removes that requirement:

```bash
strongroom serve &                          # long-lived local process — HOLDS the master key
KEEPER_DAEMON=1 strongroom redeem "$LEASE"  # this side holds NO key, NO passphrase
```

With `KEEPER_DAEMON=1`, `strongroom redeem` / `strongroom exec` route lease→secret over a **local socket** (unix domain socket / Windows named pipe — token-gated, owner-only `0600`, never TCP) instead of opening the vault. Same-user callers need zero config — both sides share the default socket path, and the client reads the capability token from the daemon's `0600` info file; a **sandboxed worker** is instead handed only `KEEPER_SOCKET` + `KEEPER_DAEMON_TOKEN` (pin one via env before `serve`) and never reads strongroom's home at all. Either way the redeeming process never holds the master key: compromise it and you get its leases — scoped, expiring, revocable — not the vault. This is how a control plane hands git credentials to sandboxed workers: a `GIT_ASKPASS` helper that runs `strongroom redeem`, with zero token bytes on disk and zero key material in the worker.

## Examples — real SDKs, zero keys in the agent

Three end-to-end examples, each running a genuine client with a credential that never enters the agent's context:

| Example | Shows |
|---|---|
| [`examples/anthropic-sdk-strongroom`](examples/anthropic-sdk-strongroom) | the **Anthropic SDK** (`@anthropic-ai/sdk`) making a real `messages.create` call through the broker — `x-api-key` injected at egress |
| [`examples/openai-agents-strongroom`](examples/openai-agents-strongroom) | a real **OpenAI Agents SDK** agent run loop with its model calls brokered through a lease |
| [`examples/mcp-strongroom`](examples/mcp-strongroom) | an **MCP server** whose tools return *leases, not keys* — the "where does the key live?" answer for every credentialed MCP server |

## Why a lease, not the key

| | a raw key in env / prompt | a strongroom lease |
|---|---|---|
| in the model's context | **yes** — leaks to logs, traces, poisoned tools | no — only an opaque handle |
| lifetime | until you rotate it | seconds (TTL) |
| blast radius | every call, every host | one use, one host |
| revocable | rotate everywhere | `strongroom revoke <lease>` |
| audited | no | every access, tamper-evident |

## Dispatching to a fleet

A platform that runs agents on remote devices shouldn't ship a long-lived key to each one — that's how OpenClaw leaked ~135k of them. Ship a **lease** instead:

- the **control plane** stores the secret in strongroom and grants a scoped, short-lived lease per task (`--upstream`, `--paths`, `--rate`, `--concurrency`, `--ttl`, `--uses`);
- the **device** receives only the lease id and runs through `strongroom broker` — the key is injected at egress, never written to the device;
- a compromised device yields a *lease* (scoped, expiring, revocable), not a key. `strongroom revoke <lease>` kills it instantly — no production-key rotation.

**The control plane never scrapes human output.** `grant`, `leases`, `ls`, and `audit` take `--json` and put exactly **one JSON value on stdout** — no ANSI, no prose, no stderr summary:

```bash
strongroom grant TASK_API_KEY --ttl 300 --uses 50 --upstream https://api.example.com --json
# → {"id":"lease_…","secret":"TASK_API_KEY","usesLeft":50,"expiresAt":1720000000000,"ttlS":300,
#    "host":null,"upstream":"https://api.example.com","inject":null,"rate":null,"paths":null,"concurrency":null}
strongroom leases --json          # → array of secret-safe lease records (fingerprints, never raw ids)
strongroom ls --json              # → ["TASK_API_KEY", …]
strongroom audit --json           # → the parsed event array
strongroom audit --verify --json  # → {"ok":true,"entries":n} | {"ok":false,"reason":"audit-tip-forged"} — exit code 0/1 preserved
```

`grant --json` returns the same one-time id + metadata the human path already returns — just machine-readable. Without `--json`, output is unchanged.

See it end to end: `npm run demo:platform`.

## Delegating a lease — least privilege between agents

In a multi-agent tree, a parent agent can hand a **sub-agent** a *narrower* slice of its own access without ever touching the vault. `grant --from-lease` **attenuates** a lease the parent holds into a sub-lease whose every scope is `≤` the parent's — shorter TTL, fewer uses, tighter host/upstream/paths/rate/concurrency. **Never wider.**

```bash
# Parent holds a broad lease: 1h, 100 uses, all of /v1/*
PARENT=$(strongroom grant OPENAI_API_KEY --upstream https://api.openai.com \
  --paths "/v1/*" --ttl 3600 --uses 100)

# Delegate a tight sub-lease to a summarizer sub-agent: 5 min, 3 uses, chat only
CHILD=$(strongroom grant --from-lease "$PARENT" \
  --paths "/v1/chat/completions" --ttl 300 --uses 3)
```

- **Attenuate-only.** A sub-lease may **narrow** any axis or **inherit** it (unset = inherit the parent's), but never widen: a longer TTL, more uses, a broader `--paths` glob, a different `--host`/`--upstream`, or a higher `--rate`/`--concurrency` is **rejected** with an error naming the axis. `--paths` must be a **subset** of the parent's (checked with the same segment-glob semantics the broker enforces). A parent axis left *unlimited* may be *capped* by the child.
- **Recorded provenance.** The child lease carries the **parent lease fingerprint**, and the child's `grant` audit event carries it as `from` — so a delegation shows up in the hash-chained, authenticated-tip audit as a parent→child link that still verifies. `strongroom leases` and `strongroom audit` render it as `⤷ from <fp>`.
- **Per-capability guarantee.** The child is an independent lease bounded by `child scope ⊆ parent scope`, so a sub-agent can never redeem toward anything its parent couldn't — and delegating does **not** spend a parent use.

## Security model

strongroom is a vault, so its own security is the point:

- **Encrypted at rest** — AES-256-GCM, with the secret *name* bound in as AAD, so a ciphertext can't be swapped between names.
- **Master key** — three options, in priority order:
  - `KEEPER_PASSPHRASE` — derived with **scrypt**; never on disk (only a salt is).
  - `KEEPER_KEYCHAIN=1` — held by the **OS keychain**: macOS Keychain · Linux Secret Service · Windows DPAPI (user scope). Never plaintext on disk, and it **fails closed** if no keychain is available (no silent downgrade). `strongroom keychain` shows the active backend.
  - else — a random key file in `~/.keeper` (`0600` + a restrictive ACL on Windows).

  Use the passphrase or the keychain for anything that matters.
- **Rotation is built in** — `strongroom rekey` re-encrypts every secret under a fresh master key, optionally switching key stores (`--to passphrase|keychain|file`; a passphrase target reads `KEEPER_NEW_PASSPHRASE`). It's atomic and fail-closed: a wrong current passphrase aborts with nothing changed, an interrupted swap is completed or discarded safely on the next run, retired key material (old salt / key file / keychain entry) is removed, and the audit's authenticated tip is re-MACed under the new key. Restart a running daemon/broker afterwards — they hold the old key and fail closed.
- **Operator ceiling on grants** — set `KEEPER_MAX_TTL` (seconds) and/or `KEEPER_MAX_USES` and no lease minted from this vault — CLI **or** library — may exceed them. An over-cap grant is **rejected** with an error naming the cap (never silently clamped) and audited as a `deny`/`policy` event, so "leases stay small" is vault policy, not caller discipline. Unset = no ceiling (unchanged behavior). Zero, negative, or non-numeric `--ttl`/`--uses` are always rejected — a NaN would otherwise mint a lease that never expires.
- **Leases are bearer tokens** — only `sha256(id)` is stored; the raw id is returned once, to you. Reading `leases.json` therefore can't redeem anything.
- **Single-use is atomic** — redeem is a check-and-consume under a cross-process lock, so concurrent redeems can't double-spend a one-use lease.
- **Fail-closed** — a tampered, swapped, or wrong-key entry returns null and denies; it never throws or leaks garbage.
- **Tamper-evident audit** — every access is hash-chained (shared with redstamp) and logged by lease *fingerprint*, never the raw id. An **authenticated tip** (HMAC under a subkey of the master key) commits to the chain's length and last hash, so *truncating* or *splicing* the log is caught — not just editing an entry.
- **Reflected secrets can't ride back in** — the broker redacts any occurrence of the injected secret from relayed response headers and bodies and audits it (`sanitize`), so an echoing or misconfigured upstream can't hand the raw key back into the agent's context.

What it is **not**: a defense against an attacker who already has your passphrase / master key or full process memory — at that point they have the vault. strongroom shrinks the *agent's* exposure (a lease, not the key; short-lived; scoped; audited); it doesn't replace OS-level isolation.

## Commands

```
strongroom add <name>                  store a secret (stdin, or --value=)
strongroom ls [--json]                 list secret names (never values)
strongroom grant <name> [--ttl --uses --host]                        mint a lease
              [--upstream --inject --paths --rate --concurrency]  (broker scoping)
              (KEEPER_MAX_TTL / KEEPER_MAX_USES, if set, cap every grant — over-cap is rejected + audited)
              [--json]                 one machine-readable JSON object on stdout
strongroom grant --from-lease <lease> [tighter opts]  DELEGATE: attenuate a lease you hold into a
              narrower sub-lease for a sub-agent (shorter --ttl, fewer --uses, tighter
              --host/--upstream/--paths/--rate/--concurrency; NEVER wider; unset scopes inherit)
strongroom redeem <lease> [--host]     exchange a valid lease for the secret (egress side)
strongroom exec <lease> --as <ENV> -- <cmd...>  redeem + run <cmd> with the secret in its env only
strongroom broker [--port 8771]        egress-injection proxy (base-URL swap, zero key in the agent)
strongroom serve [--socket <path>]     redeem-daemon: holds the master key, answers lease→secret
                                   over a local socket (KEEPER_DAEMON=1 on the keyless side)
strongroom leases [--json] · strongroom revoke <lease> · strongroom rm <name>
strongroom audit [--verify] [--json]   the access log, optionally chain-verified
strongroom rekey [--to passphrase|keychain|file]   rotate the master key (re-encrypts the vault)
strongroom keychain                    master-key backend status (KEEPER_KEYCHAIN=1 to use the OS keychain)
```

## Library

```js
import { addSecret, grant, redeem } from '@askalf/strongroom';

addSecret('STRIPE_KEY', process.env.STRIPE_KEY);
const lease = grant('STRIPE_KEY', { ttlS: 60, uses: 1, host: 'api.stripe.com' });
// hand `lease.id` to the agent; at egress:
const { ok, value } = redeem(lease.id, { host: 'api.stripe.com' });

// Delegate a narrower sub-lease to a sub-agent (attenuate-only; child ⊆ parent):
import { grantFromLease } from '@askalf/strongroom';
const sub = grantFromLease(lease.id, { ttlS: 30, uses: 1 }); // sub.parent = parent fingerprint
```

## The agent-security stack

Three composable layers, one defense: **[redstamp](https://github.com/askalf/redstamp)** contains the call · **[truecopy](https://github.com/askalf/truecopy)** vets the tool · **[strongroom](https://github.com/askalf/strongroom)** holds the keys *(you are here)*. Run all three together → **[agent-security-stack](https://github.com/askalf/agent-security-stack)**.

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
