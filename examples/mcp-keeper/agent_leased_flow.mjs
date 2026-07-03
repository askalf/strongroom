// An MCP server that holds a keeper LEASE instead of an API key — and the
// proof that the secret never crosses the MCP wire.
//
// Three processes, exactly like production:
//
//   MCP client (agent) ── stdio/JSON-RPC ──▶ MCP server (child process)
//                                              holds ONLY a lease
//                                                │
//                                                ▼
//                                          keeper broker ──▶ upstream API
//                                          REAL key inject    verifies the key
//
// The MCP server child is spawned with an environment containing NO key — just
// the opaque lease id and the broker URL. Every JSON-RPC frame between agent
// and server is captured, and the run proves the real key appears in NONE of
// them: not in tool results, not in the credential-granting tool's answer
// (which returns the LEASE — a scoped, expiring, revocable capability), not
// anywhere the agent can see. Revoking the lease kills both the server's tool
// and the agent's direct access instantly, without rotating the real key.
//
// The upstream here is a local stub that plays the status API: it rejects any
// request without the real key — so the whole example runs OFFLINE, while the
// path (MCP client → stdio → MCP server → broker → upstream) is exactly what
// production runs. Both MCP ends are the genuine @modelcontextprotocol/sdk.
//
// Run (from a keeper checkout):  npm install && npm run demo
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Hermetic keeper state: a fresh vault in ./keeper-home (gitignored), keyed by
// a file master key inside it. Kept after the run so verify_audit.mjs can
// re-check the chain. Set env BEFORE importing keeper.
const KEEPER_HOME = path.join(here, 'keeper-home');
fs.rmSync(KEEPER_HOME, { recursive: true, force: true });
process.env.KEEPER_HOME = KEEPER_HOME;
delete process.env.KEEPER_PASSPHRASE;
delete process.env.KEEPER_KEYCHAIN;
delete process.env.KEEPER_DAEMON;

const { addSecret, grant, revoke, audit } = await import('../../src/index.mjs');
const { startBroker } = await import('../../src/broker.mjs');

const ok = (cond, msg) => {
  if (!cond) { console.error('FAIL: ' + msg); process.exit(1); }
  console.log('   ✓ ' + msg);
};

// ── the provider side ─────────────────────────────────────────────────────────
// A stub upstream playing the status API. Like the real thing, it 401s any
// request that doesn't carry the REAL key. The key is generated fresh per run
// and exists only here and in keeper's vault.
const REAL_KEY = 'sk-real-' + crypto.randomBytes(12).toString('hex');
const seenByUpstream = [];
const upstream = http.createServer((req, res) => {
  seenByUpstream.push({ path: req.url, xApiKey: req.headers['x-api-key'] ?? null });
  if (req.headers['x-api-key'] !== REAL_KEY) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ error: 'invalid api key' }));
  }
  res.setHeader('content-type', 'application/json');
  const service = new URL(req.url, 'http://x').searchParams.get('service') ?? 'unknown';
  res.end(JSON.stringify({ status: `${service}: all deployments green (served only for the real key)` }));
});
upstream.listen(0, '127.0.0.1');
await once(upstream, 'listening');
const UPSTREAM = 'http://127.0.0.1:' + upstream.address().port;

// ── the operator / control-plane side ─────────────────────────────────────────
// Stash the key once (encrypted at rest), mint a scoped lease, run the broker.
// The MCP server gets the LEASE — the control plane keeps the vault.
console.log('1. control plane: keeper add status:prod  (encrypted at rest in the vault)');
addSecret('status:prod', REAL_KEY);
console.log('2. control plane: grant a scoped lease — this upstream only, /v1/status only, 120s, 10 uses');
const lease = grant('status:prod', {
  ttlS: 120, uses: 10, upstream: UPSTREAM, inject: 'x-api-key',
  paths: ['/v1/status'], rate: 30,
});
const broker = startBroker({ port: 0, onLog: (m) => console.log('   [broker] ' + m) });
await once(broker, 'listening');
const BROKER = 'http://127.0.0.1:' + broker.address().port;

// ── the MCP server side (a real child process, spawned KEYLESS) ───────────────
// Its entire credential surface: the lease id + the broker URL. We assert the
// env we hand it carries no key before it ever starts.
const serverEnv = {
  UPSTREAM_LEASE: lease.id,
  BROKER_URL: BROKER,
  // minimal process plumbing only (Windows needs SystemRoot for networking)
  PATH: process.env.PATH ?? '',
  ...(process.env.SYSTEMROOT ? { SYSTEMROOT: process.env.SYSTEMROOT } : {}),
  ...(process.env.TEMP ? { TEMP: process.env.TEMP } : {}),
};

// ── the agent side (a real MCP client) — with the WIRE under observation ──────
// TeeTransport wraps the real stdio transport and records every JSON-RPC frame
// in both directions, so we can prove what did — and did not — cross the wire.
const frames = [];
class TeeTransport {
  constructor(inner) { this._inner = inner; }
  async start() {
    this._inner.onmessage = (m, extra) => { frames.push({ dir: 'server→agent', m }); this.onmessage?.(m, extra); };
    this._inner.onclose = () => this.onclose?.();
    this._inner.onerror = (e) => this.onerror?.(e);
    await this._inner.start();
  }
  async send(m, opts) { frames.push({ dir: 'agent→server', m }); return this._inner.send(m, opts); }
  async close() { return this._inner.close(); }
}

const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

console.log('3. agent: real MCP client connects to the real (keyless) MCP server over stdio');
const client = new Client({ name: 'demo-agent', version: '1.0.0' });
const tee = new TeeTransport(new StdioClientTransport({
  command: process.execPath,
  args: [path.join(here, 'server.mjs')],
  env: serverEnv,
  stderr: 'inherit',
}));
await client.connect(tee);

const tools = await client.listTools();
console.log('4. agent: calls deployment_status through the MCP server (server → broker → upstream)');
const status = await client.callTool({ name: 'deployment_status', arguments: { service: 'forge' } });
const statusText = status.content?.[0]?.text ?? '';

console.log('5. agent: asks for the upstream credential — gets a LEASE, never a key');
const cred = await client.callTool({ name: 'get_upstream_credential', arguments: {} });
const credObj = JSON.parse(cred.content?.[0]?.text ?? '{}');
const direct = await fetch(credObj.base_url + '/v1/status?service=amnesia');
const directBody = await direct.json().catch(() => ({}));

console.log('\n── proofs ─────────────────────────────────────────────────────────');
ok(tools.tools.map((t) => t.name).sort().join(',') === 'deployment_status,get_upstream_credential',
  'genuine MCP round-trip: client listed the server\'s tools over stdio');
ok(statusText.includes('all deployments green'),
  'the tool call completed — server reached the upstream through its lease');
ok(seenByUpstream.length >= 1 && seenByUpstream.every((s) => s.xApiKey === REAL_KEY),
  'upstream only ever saw the REAL key — injected by the broker at egress');
ok(!Object.values(serverEnv).includes(REAL_KEY),
  'the MCP server process was spawned KEYLESS — no key in its env, only the lease');
ok(direct.ok && String(directBody.status ?? '').includes('all deployments green'),
  'the granted credential works: the agent used the lease-backed base URL directly');

// The headline: every JSON-RPC frame between agent and server, both
// directions, and the secret is in NONE of them. The lease id IS on the wire —
// by design: a lease is a capability that is safe to hold in agent context.
const wire = JSON.stringify(frames);
ok(frames.length >= 6, `the wire was under observation (${frames.length} JSON-RPC frames captured)`);
ok(!wire.includes(REAL_KEY), 'the REAL key appears in ZERO frames — the secret never crossed the MCP wire');
ok(wire.includes(lease.id), 'the LEASE crossed the wire instead — a scoped, expiring, revocable capability');

// Kill switch: revoke the lease — BOTH paths (the server's tool and the
// agent's direct access) die instantly, without rotating the real key.
console.log('6. control plane: keeper revoke — server tool AND direct access die, key unrotated');
revoke(lease.id);
const upstreamCallsBefore = seenByUpstream.length;
const afterRevokeTool = await client.callTool({ name: 'deployment_status', arguments: { service: 'forge' } });
ok(afterRevokeTool.isError === true, 'post-revoke tool call → upstream denied, surfaced as a tool error');
const afterRevokeDirect = await fetch(credObj.base_url + '/v1/status?service=forge');
ok(afterRevokeDirect.status === 403, 'post-revoke direct call → 403 denied');
ok(seenByUpstream.length === upstreamCallsBefore, 'nothing further ever reached the upstream');

// Every step above is in keeper's hash-chained, tip-authenticated audit.
const v = audit.verify();
ok(v.ok === true, `audit chain verifies intact (${v.entries} entries)`);
const events = audit.read().map((e) => e.event);
for (const must of ['add', 'grant', 'redeem', 'deny', 'revoke']) {
  ok(events.includes(must), `audit records '${must}'`);
}

// Leave the captured wire as a checked-in receipt (fingerprints + lease only).
fs.mkdirSync(path.join(here, 'evidence'), { recursive: true });
fs.writeFileSync(
  path.join(here, 'evidence', 'wire.jsonl'),
  frames.map((f) => JSON.stringify(f)).join('\n') + '\n',
);

console.log('\naudit trail: ' + events.join(' → '));
console.log('\nMCP_KEEPER_PASS');
await client.close();
upstream.close();
broker.close();
process.exit(0);
