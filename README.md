# keeper

> _keeper — **own your agent secrets**. An encrypted vault that hands agents scoped, short-lived, single-use leases instead of raw keys. Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it by the token._

Agents need credentials — API keys, tokens, passwords — to do anything useful. Today they get them the worst possible way: a long-lived key stuffed into an environment variable or, worse, into the prompt. OpenClaw leaked the keys of ~135k exposed instances exactly this way. A key in the model's context is a key in every log, every trace, and every place a poisoned tool can read.

**keeper holds the keys so the agent doesn't.** The raw secret stays encrypted in the vault; the agent only ever holds a **lease** — a scoped, short-lived, use-limited handle — and the real key is revealed **only at the egress point**, only while the lease is valid:

- **vault** — secrets encrypted at rest (AES-256-GCM, key in `~/.keeper`, `0600`). Never a plaintext env var, never in a prompt.
- **lease** — `grant` mints an opaque handle bound to a **TTL**, a **use count**, and (optionally) a **destination host**. The agent's context holds the lease, not the secret.
- **redeem** — exchange a lease for the secret at the point of use, *iff* it's still valid (not expired, uses remaining, host in scope). A denial is audited and never burns a use.
- **audit** — every grant / redeem / deny / revoke is **hash-chained** (shared with [warden](https://github.com/askalf/warden)) — editing or deleting a past access breaks `keeper audit --verify`.

Completes the agent-security stack: **warden** contains the call · **canon** vets the tool · **keeper** holds the keys.

## Quick start

> Not yet on npm — installs straight from GitHub: `npm i -g github:askalf/keeper` (or prefix any command below with `npx -y github:askalf/keeper`).

```bash
echo "sk-live-…" | keeper add OPENAI_API_KEY          # stored encrypted

LEASE=$(keeper grant OPENAI_API_KEY --ttl 300 --uses 1 --host api.openai.com)
# → the agent gets $LEASE — not the key

# at the egress point, run the call with the key in the child's env only:
keeper exec "$LEASE" --as OPENAI_API_KEY -- \
  curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"

keeper audit --verify                                 # tamper-evident access log
```

The agent dispatched `keeper exec <lease> …`; the key was decrypted inside keeper and handed to the subprocess's environment — it never entered the agent's context, stdout, or logs. Run the whole story: `npm run demo`.

## Egress broker — the agent just swaps a base URL

Run the broker and the agent needs no key, no `exec`, no redeem — only a base-URL swap:

```bash
# bind a lease to ONE upstream, how to inject, which endpoints, and a rate cap
LEASE=$(keeper grant OPENAI_API_KEY \
  --upstream https://api.openai.com --inject bearer \
  --paths "/v1/chat/*,/v1/models" --rate 60 --concurrency 4 --ttl 600 --uses 100)
keeper broker --port 8771 &
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

**And the response is sanitized on the way back.** If the upstream ever *reflects* the injected secret — an echo/debug endpoint, a verbose error, a misconfigured proxy — the broker redacts it from the relayed headers and body (`[keeper:redacted]`) and records a `sanitize` audit event. The scan is streaming-safe: SSE passes through event-by-event, and a secret split across chunk boundaries is still caught. Without this, a reflecting upstream would hand the raw key straight back into the agent's context, defeating the injection boundary.

> **Windows / Git Bash:** MSYS auto-rewrites an argument that looks like a Unix absolute path, so a bare `--paths "/v1/models"` reaches keeper as `C:/Program Files/Git/v1/models` and silently never matches (every call then `403`s on `path`). A comma-list like `"/v1/chat/*,/v1/models"` is left alone, which is why it works. Prefix the run with `MSYS_NO_PATHCONV=1` (use drive-letter paths for any file args), or call keeper from PowerShell/cmd. Not a keeper bug — it mangles the arg before keeper sees it.

## Why a lease, not the key

| | a raw key in env / prompt | a keeper lease |
|---|---|---|
| in the model's context | **yes** — leaks to logs, traces, poisoned tools | no — only an opaque handle |
| lifetime | until you rotate it | seconds (TTL) |
| blast radius | every call, every host | one use, one host |
| revocable | rotate everywhere | `keeper revoke <lease>` |
| audited | no | every access, tamper-evident |

## Dispatching to a fleet

A platform that runs agents on remote devices shouldn't ship a long-lived key to each one — that's how OpenClaw leaked ~135k of them. Ship a **lease** instead:

- the **control plane** stores the secret in keeper and grants a scoped, short-lived lease per task (`--upstream`, `--paths`, `--rate`, `--ttl`, `--uses`);
- the **device** receives only the lease id and runs through `keeper broker` — the key is injected at egress, never written to the device;
- a compromised device yields a *lease* (scoped, expiring, revocable), not a key. `keeper revoke <lease>` kills it instantly — no production-key rotation.

See it end to end: `npm run demo:platform`.

## Security model

keeper is a vault, so its own security is the point:

- **Encrypted at rest** — AES-256-GCM, with the secret *name* bound in as AAD, so a ciphertext can't be swapped between names.
- **Master key** — three options, in priority order:
  - `KEEPER_PASSPHRASE` — derived with **scrypt**; never on disk (only a salt is).
  - `KEEPER_KEYCHAIN=1` — held by the **OS keychain**: macOS Keychain · Linux Secret Service · Windows DPAPI (user scope). Never plaintext on disk, and it **fails closed** if no keychain is available (no silent downgrade). `keeper keychain` shows the active backend.
  - else — a random key file in `~/.keeper` (`0600` + a restrictive ACL on Windows).

  Use the passphrase or the keychain for anything that matters.
- **Leases are bearer tokens** — only `sha256(id)` is stored; the raw id is returned once, to you. Reading `leases.json` therefore can't redeem anything.
- **Single-use is atomic** — redeem is a check-and-consume under a cross-process lock, so concurrent redeems can't double-spend a one-use lease.
- **Fail-closed** — a tampered, swapped, or wrong-key entry returns null and denies; it never throws or leaks garbage.
- **Tamper-evident audit** — every access is hash-chained (shared with warden) and logged by lease *fingerprint*, never the raw id.

What it is **not**: a defense against an attacker who already has your passphrase / master key or full process memory — at that point they have the vault. keeper shrinks the *agent's* exposure (a lease, not the key; short-lived; scoped; audited); it doesn't replace OS-level isolation.

## Commands

```
keeper add <name>                  store a secret (stdin, or --value=)
keeper ls                          list secret names (never values)
keeper grant <name> [--ttl --uses --host --upstream --inject]   mint a lease
keeper redeem <lease> [--host]     exchange a valid lease for the secret (egress side)
keeper exec <lease> --as <ENV> -- <cmd...>  redeem + run <cmd> with the secret in its env only
keeper broker [--port 8771]        egress-injection proxy (base-URL swap, zero key in the agent)
keeper leases · keeper revoke <lease> · keeper rm <name>
keeper audit [--verify]            the access log, optionally chain-verified
keeper keychain                    master-key backend status (KEEPER_KEYCHAIN=1 to use the OS keychain)
```

## Library

```js
import { addSecret, grant, redeem } from '@askalf/keeper';

addSecret('STRIPE_KEY', process.env.STRIPE_KEY);
const lease = grant('STRIPE_KEY', { ttlS: 60, uses: 1, host: 'api.stripe.com' });
// hand `lease.id` to the agent; at egress:
const { ok, value } = redeem(lease.id, { host: 'api.stripe.com' });
```

## The agent-security stack

Three composable layers, one defense: **[warden](https://github.com/askalf/warden)** contains the call · **[canon](https://github.com/askalf/canon)** vets the tool · **[keeper](https://github.com/askalf/keeper)** holds the keys *(you are here)*. Run all three together → **[agent-security-stack](https://github.com/askalf/agent-security-stack)**.

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
