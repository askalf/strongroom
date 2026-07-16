# @askalf/strongroom-mcp

**An MCP server that is the [strongroom](https://github.com/askalf/strongroom) control plane.** Its tools mint scoped, expiring, revocable **leases** and hand agents a lease-backed base URL — so **API keys never enter agent context**. Part of [Own Your Stack](https://sprayberrylabs.com).

> Every MCP server that talks to a credentialed API faces the same question: **where does the key live?** A key in the server's env is one compromise away from gone, and an MCP tool that *returns* a credential writes it straight into the calling agent's context window — persisted in history, logs, and traces, readable by every poisoned tool that shares the conversation.
>
> strongroom-mcp is the answer, as one rule: **a credential-granting tool returns a capability, not a secret.** The answer to "give me upstream access" is a lease-backed base URL. It is *safe to land in agent context* precisely because it is not a secret.

## Install

```bash
npm install -g @askalf/strongroom-mcp
```

## How it works

This server **is** the control plane. It owns the encrypted strongroom vault and runs strongroom's egress **broker** in-process:

```
MCP client (agent) ── stdio/JSON-RPC ──▶ strongroom-mcp (owns vault + broker)
        │  grant_lease → base_url                 │
        │  (a capability, NOT a key)              ▼
        └── direct API calls, NO key ──────▶ egress broker ──▶ upstream API
                    via the lease-backed base URL   REAL key injected here
```

1. The operator loads secrets into the vault **out-of-band** with the strongroom CLI (`strongroom add NAME`). The MCP server never sees a secret value — deliberately there is **no `add_secret` tool**, so no secret value ever crosses the MCP wire in either direction.
2. An agent calls `grant_lease`; the server mints a scoped, expiring, revocable lease and returns a **lease-backed base URL** (`http://127.0.0.1:<port>/<lease>`).
3. The agent points its HTTP client's base URL at that URL and calls the upstream with **no key**. The broker checks the lease (host + path allowlist + rate + concurrency), redeems it (atomic + audited), and **injects the real secret at the network boundary**.

Compromise the agent — or read its whole context window — and you get a scoped, expiring, revocable capability. Never the key.

## Tools

| Tool | Returns | Notes |
|------|---------|-------|
| `grant_lease` | a lease-backed `base_url` + fingerprint | mints a scoped, expiring, revocable lease. The raw key is never returned. |
| `list_secrets` | secret **names** | never values — just what you can grant against. |
| `list_leases` | outstanding leases by **fingerprint** | raw lease ids are never stored or returned. |
| `revoke_lease` | `{ revoked }` | kills a lease at once (by id or its base URL); the real secret is untouched. |
| `broker_status` | broker base URL + listening state | lease URLs are `broker_base + "/" + <lease>`. |

`grant_lease` inputs: `secret` (name), `upstream` (URL the secret may be injected toward), and optional `ttl_s`, `uses`, `inject` (`bearer` | `x-api-key`), `paths` (glob allowlist), `rate` (req/min), `concurrency`.

## Configure (MCP client)

```json
{
  "mcpServers": {
    "strongroom": {
      "command": "strongroom-mcp",
      "env": {
        "KEEPER_HOME": "/home/you/.keeper",
        "STRONGROOM_BROKER_HOST": "127.0.0.1",
        "STRONGROOM_BROKER_PORT": "8771"
      }
    }
  }
}
```

The vault must already hold your secrets (`strongroom add openai:key`, etc). The broker binds to loopback only; `STRONGROOM_BROKER_PORT=0` picks an ephemeral port (read it back with `broker_status`). `STRONGROOM_MAX_TTL` / `STRONGROOM_MAX_USES`, if set, cap every lease this server mints.

## Why keys never enter context

- The **server** holds a vault + broker, not raw keys in tool return values. The secret only touches the request at the broker's network boundary.
- Every **tool result** is a capability or a fingerprint — safe to persist in agent history, logs, and traces.
- A lease is **bound to one upstream** (and optionally to specific paths), so even the capability can only be injected toward that host — not an attacker URL. Revoke it and both the tool and any direct access die instantly, without rotating the real key.

## License

MIT © Thomas Sprayberry
