# Example: MCP tools should return leases, not keys

Every MCP server that talks to a credentialed API faces the same question:
**where does the key live?** The common answers all leak. A key in the
server's env is one server compromise away from gone. And an MCP tool that
*returns* a credential writes that credential straight into the calling
agent's context window — persisted in its history, its logs, its traces, and
readable by every poisoned tool that shares the conversation.

This example is the keeper answer, stated as two rules:

1. **The MCP server holds a lease, not a key.** Its outbound calls go through
   keeper's egress broker, which checks the lease and injects the real key at
   the network boundary. Compromise the server and you get a scoped, expiring,
   revocable capability — not the credential.
2. **A credential-granting tool returns a capability, not a secret.** When the
   agent asks for upstream access, the answer is a lease-backed base URL. It
   is *safe to land in agent context* precisely because it is not a secret.

The run wires up three real processes — a genuine `@modelcontextprotocol/sdk`
client (the agent), a genuine MCP server as a **separate child process spawned
keyless** (its env carries only the lease id and broker URL), and the keeper
broker in front of a stub upstream that rejects anything without the real key
— and then puts **the MCP wire itself under observation**: every JSON-RPC
frame in both directions is captured and checked.

```
MCP client (agent) ── stdio/JSON-RPC ──▶ MCP server (child, KEYLESS)
        │   every frame captured              │ holds only a lease
        │                                     ▼
        │                               keeper broker ──▶ upstream API
        └── direct, via the granted      REAL key inject    verifies the key
            lease-backed base URL
```

The whole example runs **offline** — the upstream is a local stub playing the
provider — while the path (MCP client → stdio → MCP server → broker →
upstream) is exactly what production runs.

## Files

| File | What it is |
|------|------------|
| `server.mjs` | the real MCP server — keyless, lease-held, with the two tools |
| `agent_leased_flow.mjs` | the real MCP client + control plane + wire capture + proofs |
| `verify_audit.mjs` | re-verifies the run's audit chain and proves it is tamper-evident |
| `evidence/` | captured stdout, the **captured JSON-RPC wire** (`wire.jsonl`), `audit.jsonl`, verify output, version provenance |
| `package.json` | pinned MCP SDK + zod versions |

## Run

From a keeper checkout:

```bash
cd examples/mcp-keeper
npm install
npm run demo      # -> MCP_KEEPER_PASS
npm run verify    # -> AUDIT_VERIFY_PASS  (re-checks the audit the demo left behind)
```

## What the run proves

1. **A genuine MCP round-trip works** — real SDK client and server, separate
   processes, stdio transport; tools listed and called normally.
2. **The server process was born keyless** — the env it was spawned with
   contains the lease id and broker URL, and no key.
3. **The upstream only ever saw the real key** — injected by the broker at
   egress, never by the server.
4. **The secret never crossed the MCP wire** — every JSON-RPC frame between
   agent and server was captured; the real key appears in **zero** of them.
   The checked-in `evidence/wire.jsonl` is the receipt.
5. **The lease crossed the wire instead — by design.** The
   `get_upstream_credential` tool returns a lease-backed base URL; the agent
   uses it directly and it works. A capability in context is fine; a
   credential in context is an incident.
6. **Revocation kills everything at once** — `keeper revoke` instantly breaks
   both the server's tool and the agent's direct access, with the real key
   never rotated, and nothing further reaching the upstream.
7. **Everything is audited** — add → grant → redeem → revoke → deny in a
   hash-chained, tip-authenticated log that fails verification on a one-byte
   mid-chain edit **and** on tail truncation.

## Adapting this to your stack

Any MCP server that calls a credentialed HTTP API inherits the pattern: take a
lease id + broker URL from the environment instead of a key, and prefix
requests with `<broker>/<lease>`. The control plane (whatever starts your
servers) owns the vault, runs `startBroker()` / `keeper broker`, and grants
each server a lease scoped to exactly the upstream and paths it needs —
`--inject x-api-key` for Anthropic-style APIs, `bearer` for OpenAI-style, any
`Header-Name` for the rest. The sibling examples show the same broker pattern
from the client side: [`openai-agents-keeper`](../openai-agents-keeper/)
(Bearer) and [`anthropic-sdk-keeper`](../anthropic-sdk-keeper/) (x-api-key).

One honest caveat about this demo's shape: the control plane (vault + broker)
runs in the orchestrating process so the example is self-contained, and the
"agent" is the demo script driving a real MCP client rather than a model
choosing tools. The isolation that matters is real, though: the MCP server is
a separate OS process that never receives key material, and everything the
agent side sees travels over the observed wire. In a real deployment the
vault and broker live in your control plane, and MCP servers get exactly what
the child here gets — a lease and a broker URL.
