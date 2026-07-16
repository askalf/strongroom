#!/usr/bin/env node
// @askalf/strongroom-mcp — the strongroom control plane, as an MCP server.
//
// This server IS the control plane: it owns the encrypted vault (populated
// out-of-band by the operator via the `strongroom` CLI) and runs strongroom's
// egress broker in-process. Its tools mint scoped, expiring, revocable LEASES
// and hand agents a lease-backed base URL — a capability, never a credential.
// A downstream agent points its HTTP client's base URL at that URL and makes
// normal API calls with NO key; the broker checks the lease and injects the
// real secret at the network boundary. So the API key never crosses the MCP
// wire and never enters agent context.
//
// Deliberately NO add_secret / redeem tool: no secret VALUE ever crosses the
// MCP wire in either direction. Secrets are loaded into the vault out-of-band
// (`strongroom add NAME`); this server only mints capabilities against them.
//
// House recipe: tools declare a zod RAW shape (not z.object()); @modelcontext
// protocol/sdk + zod + @askalf/strongroom are REGULAR deps; ALL logging goes
// to stderr — stdout is the MCP stdio transport and must carry only JSON-RPC.
import crypto from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { grant, revoke, vault, lease } from '@askalf/strongroom';
import { startBroker } from '@askalf/strongroom/broker';

// stderr-only logger — stdout is the JSON-RPC transport.
const log = (...a) => console.error('[strongroom-mcp]', ...a);
const fp = (id) => crypto.createHash('sha256').update(typeof id === 'string' ? id : String(id ?? '')).digest('hex').slice(0, 12);

// ── the egress broker (in-process control plane) ─────────────────────────────
// Bind to loopback only. STRONGROOM_BROKER_HOST/PORT let the operator pin a
// stable base URL; PORT=0 (default) picks an ephemeral port and we report the
// real one via broker_status. The broker holds the vault key material inside
// THIS process — the agent on the other end of the MCP wire never does.
const BROKER_HOST = process.env.STRONGROOM_BROKER_HOST || '127.0.0.1';
const BROKER_PORT = Number.isFinite(Number(process.env.STRONGROOM_BROKER_PORT)) ? Number(process.env.STRONGROOM_BROKER_PORT) : 8771;

let brokerPort = null; // real bound port (resolved on 'listening')
const broker = startBroker({ host: BROKER_HOST, port: BROKER_PORT, onLog: (m) => log('broker:', m) });
broker.on('listening', () => { brokerPort = broker.address().port; });
broker.on('error', (e) => log('broker error:', e.message));

const brokerBase = () => `http://${BROKER_HOST}:${brokerPort ?? BROKER_PORT}`;
const leaseBaseUrl = (id) => `${brokerBase()}/${id}`;

const server = new McpServer({ name: 'strongroom-mcp', version: '0.1.0' });

// grant_lease — mint a scoped, expiring, revocable lease and return a
// lease-backed base URL. The RESPONSE is safe to land in agent context: it
// carries the capability (base URL) and a fingerprint, never the secret value.
server.registerTool(
  'grant_lease',
  {
    title: 'Grant a lease (a capability, never a key)',
    description:
      'Mint a scoped, expiring, revocable lease for a stored secret and return a ' +
      'lease-backed base URL. Point your HTTP client at base_url and call the upstream ' +
      'with NO key — the broker injects the real secret at the network boundary. The raw ' +
      'API key is never returned and never crosses the MCP wire.',
    inputSchema: {
      secret: z.string().min(1).describe('Name of a secret already in the vault (see list_secrets). The value is never exposed.'),
      upstream: z.string().url().describe('Upstream base URL the secret may be injected toward, e.g. https://api.example.com. The lease is bound to this host.'),
      ttl_s: z.number().int().positive().max(86400).optional().describe('Lease lifetime in seconds (default 300). Capped by STRONGROOM_MAX_TTL if set.'),
      uses: z.number().int().positive().max(10000).optional().describe('Number of times the lease may be redeemed (default 1). Capped by STRONGROOM_MAX_USES if set.'),
      inject: z.enum(['bearer', 'x-api-key']).optional().describe("How to inject the secret upstream: 'bearer' (Authorization: Bearer) or 'x-api-key' (default bearer)."),
      paths: z.array(z.string()).optional().describe("Glob path allowlist scoping which endpoints the lease may hit, e.g. ['/v1/chat/*']. Empty = any path on the upstream host."),
      rate: z.number().int().positive().max(100000).optional().describe('Requests-per-minute cap for this lease (default unlimited).'),
      concurrency: z.number().int().positive().max(10000).optional().describe('Max simultaneous in-flight requests for this lease (default unlimited).'),
    },
  },
  async ({ secret, upstream, ttl_s, uses, inject, paths, rate, concurrency }) => {
    try {
      const l = grant(secret, {
        upstream,
        ttlS: ttl_s ?? 300,
        uses: uses ?? 1,
        inject: inject ?? 'bearer',
        paths: Array.isArray(paths) ? paths.filter(Boolean) : [],
        rate: rate ?? null,
        concurrency: concurrency ?? null,
      });
      log(`granted ${fp(l.id)} → ${secret} · ${l.usesLeft} use(s) · → ${l.upstream}`);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            kind: 'strongroom-lease',
            base_url: leaseBaseUrl(l.id),
            fingerprint: fp(l.id),
            secret,
            upstream: l.upstream,
            inject: l.inject,
            paths: l.paths,
            uses: l.usesLeft,
            expires_at: new Date(l.expiresAt).toISOString(),
            note: 'Point your HTTP client base URL here and call with NO key. Scoped, expiring, revocable — a capability, not a credential.',
          }, null, 2),
        }],
      };
    } catch (e) {
      // e.message names the cap/reason (never a secret value) — safe to surface.
      return { content: [{ type: 'text', text: `grant denied: ${e.message}` }], isError: true };
    }
  },
);

// list_secrets — vault secret NAMES only, never values.
server.registerTool(
  'list_secrets',
  {
    title: 'List secret names (never values)',
    description: 'List the names of secrets in the vault. Values are never returned — only names you can grant a lease against.',
    inputSchema: {},
  },
  async () => ({
    content: [{ type: 'text', text: JSON.stringify({ secrets: vault.listSecrets() }, null, 2) }],
  }),
);

// list_leases — outstanding leases by FINGERPRINT (we never hold raw ids).
server.registerTool(
  'list_leases',
  {
    title: 'List outstanding leases (by fingerprint)',
    description: 'List outstanding leases by fingerprint, with their secret name, uses remaining, and expiry. Raw lease ids are never stored or returned.',
    inputSchema: {},
  },
  async () => ({
    content: [{ type: 'text', text: JSON.stringify({ leases: lease.listLeases() }, null, 2) }],
  }),
);

// revoke_lease — kill a lease immediately by its raw id (or a lease-backed
// base URL, from which we extract the id). Revoking cuts off the capability
// instantly, without rotating the real secret.
server.registerTool(
  'revoke_lease',
  {
    title: 'Revoke a lease',
    description: 'Revoke a lease immediately by its raw lease id or its lease-backed base URL. The capability dies at once; the real secret is untouched.',
    inputSchema: {
      lease: z.string().min(1).describe('The raw lease id, or the lease-backed base_url returned by grant_lease.'),
    },
  },
  async ({ lease: leaseArg }) => {
    // Accept either the raw id or the full base URL (…/<lease>) — take the last
    // path segment when a URL was passed.
    const id = String(leaseArg).includes('/') ? String(leaseArg).split('/').filter(Boolean).pop() : String(leaseArg);
    const had = revoke(id);
    log(`revoke ${fp(id)} → ${had ? 'revoked' : 'no such lease'}`);
    return { content: [{ type: 'text', text: JSON.stringify({ revoked: had, fingerprint: fp(id) }) }] };
  },
);

// broker_status — where the egress broker is listening (so a client knows the
// base URL host/port). Never exposes secrets or lease ids.
server.registerTool(
  'broker_status',
  {
    title: 'Egress broker status',
    description: 'Report the strongroom egress broker base URL and whether it is listening. Lease-backed URLs are broker_base + "/" + <lease>.',
    inputSchema: {},
  },
  async () => ({
    content: [{
      type: 'text',
      text: JSON.stringify({
        listening: brokerPort != null,
        broker_base: brokerBase(),
        host: BROKER_HOST,
        port: brokerPort ?? BROKER_PORT,
      }, null, 2),
    }],
  }),
);

await server.connect(new StdioServerTransport());
log(`up — control plane on ${brokerBase()} · vault ${process.env.KEEPER_HOME || '~/.keeper'} · tools: grant_lease, list_secrets, list_leases, revoke_lease, broker_status`);
