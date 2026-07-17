// Egress e2e for @askalf/strongroom-mcp: everything smoke.mjs deliberately
// stops short of. Spawn the server as a real MCP child over stdio, then make
// ACTUAL HTTP calls through the lease-backed base URL against a live local
// stub upstream — proving the broker injects the secret at the network
// boundary (and only there), enforces path scope and use-count, and that
// revocation cuts a live capability off instantly. The stub records every
// request it receives, so "the upstream saw the key / was never hit" are
// asserted on real traffic, not inferred.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Hermetic vault, seeded out-of-band before the server starts — same setup as
// smoke.mjs (the server only ever mints leases against the name).
const KEEPER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'strongroom-mcp-e2e-'));
process.env.KEEPER_HOME = KEEPER_HOME;
delete process.env.KEEPER_PASSPHRASE;
delete process.env.KEEPER_KEYCHAIN;
delete process.env.KEEPER_DAEMON;

const REAL_KEY = 'sk-real-' + crypto.randomBytes(16).toString('hex');
const { addSecret } = await import('@askalf/strongroom');
addSecret('demo:key', REAL_KEY);

// Live stub upstream: records every hit and the auth header it arrived with.
const hits = [];
const stub = http.createServer((req, res) => {
  hits.push({ path: req.url, auth: req.headers['authorization'] ?? null });
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ upstream: 'stub', path: req.url }));
});
await new Promise((r) => stub.listen(0, '127.0.0.1', r));
const upstream = `http://127.0.0.1:${stub.address().port}`;

const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

// One server/client for the whole flow; the tests below run sequentially and
// walk a single lease through its life. Frames are captured so the no-key-on-
// the-wire invariant covers this file's entire session too.
const frames = [];
const inner = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(here, 'server.mjs')],
  env: { ...process.env, KEEPER_HOME, STRONGROOM_BROKER_PORT: '0' },
  stderr: 'ignore',
});
const transport = {
  async start() {
    inner.onmessage = (m, extra) => { frames.push(m); this.onmessage?.(m, extra); };
    inner.onclose = () => this.onclose?.();
    inner.onerror = (e) => this.onerror?.(e);
    await inner.start();
  },
  async send(m, opts) { frames.push(m); return inner.send(m, opts); },
  async close() { return inner.close(); },
  get sessionId() { return inner.sessionId; },
  setProtocolVersion(v) { inner.setProtocolVersion?.(v); },
};
const client = new Client({ name: 'strongroom-mcp-e2e', version: '0.0.0' });
await client.connect(transport);

const callTool = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  return r.content.map((c) => c.text).join('');
};

let base; // lease-backed base URL, minted once, consumed across the tests

test('keyless call through the lease reaches the upstream WITH the secret', async () => {
  base = JSON.parse(await callTool('grant_lease', {
    secret: 'demo:key', upstream, ttl_s: 120, uses: 2, inject: 'bearer', paths: ['/v1/ok*'],
  })).base_url;

  const res = await fetch(`${base}/v1/ok`);
  const body = await res.json();
  assert.equal(res.status, 200, 'broker relays the upstream response');
  assert.deepEqual(body, { upstream: 'stub', path: '/v1/ok' });
  assert.equal(hits.length, 1, 'upstream hit exactly once');
  assert.equal(hits[0].auth, `Bearer ${REAL_KEY}`, 'secret injected at the network boundary');
});

test('out-of-scope path is refused before the upstream and burns no use', async () => {
  const res = await fetch(`${base}/admin/keys`);
  assert.ok(res.status >= 400, `denied (got ${res.status})`);
  assert.equal(hits.length, 1, 'upstream never saw the out-of-scope request');
});

test('use-count is enforced: second use OK, third exhausted', async () => {
  const okRes = await fetch(`${base}/v1/ok`);
  assert.equal(okRes.status, 200, 'use 2/2 succeeds');
  const spent = await fetch(`${base}/v1/ok`);
  assert.ok(spent.status >= 400, `exhausted lease denied (got ${spent.status})`);
  assert.equal(hits.length, 2, 'upstream hit exactly twice across the lease lifetime');
});

test('revoking a live lease cuts it off instantly', async () => {
  const fresh = JSON.parse(await callTool('grant_lease', { secret: 'demo:key', upstream, ttl_s: 120, uses: 5 })).base_url;
  const rv = JSON.parse(await callTool('revoke_lease', { lease: fresh }));
  assert.equal(rv.revoked, true);
  const res = await fetch(`${fresh}/v1/ok`);
  assert.ok(res.status >= 400, `revoked lease denied (got ${res.status})`);
  assert.equal(hits.length, 2, 'upstream untouched after revocation');
});

test('the secret value crossed the MCP wire in NO frame of this session', () => {
  assert.ok(!JSON.stringify(frames).includes(REAL_KEY));
});

test.after(async () => {
  await client.close();
  stub.close();
  try { fs.rmSync(KEEPER_HOME, { recursive: true, force: true }); } catch {}
});
