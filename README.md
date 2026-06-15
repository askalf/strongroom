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

## Why a lease, not the key

| | a raw key in env / prompt | a keeper lease |
|---|---|---|
| in the model's context | **yes** — leaks to logs, traces, poisoned tools | no — only an opaque handle |
| lifetime | until you rotate it | seconds (TTL) |
| blast radius | every call, every host | one use, one host |
| revocable | rotate everywhere | `keeper revoke <lease>` |
| audited | no | every access, tamper-evident |

## Commands

```
keeper add <name>                  store a secret (stdin, or --value=)
keeper ls                          list secret names (never values)
keeper grant <name> [--ttl --uses --host]   mint a lease
keeper redeem <lease> [--host]     exchange a valid lease for the secret (egress side)
keeper exec <lease> --as <ENV> -- <cmd...>  redeem + run <cmd> with the secret in its env only
keeper leases · keeper revoke <lease> · keeper rm <name>
keeper audit [--verify]            the access log, optionally chain-verified
```

## Library

```js
import { addSecret, grant, redeem } from '@askalf/keeper';

addSecret('STRIPE_KEY', process.env.STRIPE_KEY);
const lease = grant('STRIPE_KEY', { ttlS: 60, uses: 1, host: 'api.stripe.com' });
// hand `lease.id` to the agent; at egress:
const { ok, value } = redeem(lease.id, { host: 'api.stripe.com' });
```

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
