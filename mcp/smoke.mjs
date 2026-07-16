// Smoke test for @askalf/strongroom-mcp: spawn the server as a REAL MCP child
// over stdio, exercise every tool, and prove the secret VALUE never crosses
// the MCP wire — the whole point of the control-plane-as-MCP-server design.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Hermetic vault in a throwaway KEEPER_HOME, keyed by a file master key inside
// it. Stash a fake secret out-of-band (exactly as the operator would via the
// CLI) BEFORE the server starts — the server never sees the value, only mints
// leases against the name.
const KEEPER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'strongroom-mcp-test-'));
process.env.KEEPER_HOME = KEEPER_HOME;
delete process.env.KEEPER_PASSPHRASE;
delete process.env.KEEPER_KEYCHAIN;
delete process.env.KEEPER_DAEMON;

const REAL_KEY = 'sk-real-' + crypto.randomBytes(16).toString('hex');
const { addSecret } = await import('@askalf/strongroom');
addSecret('demo:key', REAL_KEY);

const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

// TeeTransport — wraps the real stdio transport and records every JSON-RPC
// frame in BOTH directions, so we can prove what did (and did not) cross the
// wire. Same pattern the examples/mcp-strongroom demo uses.
function makeCapturingClient() {
  const frames = [];
  const inner = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(here, 'server.mjs')],
    env: { ...process.env, KEEPER_HOME, STRONGROOM_BROKER_PORT: '0' },
    stderr: 'ignore',
  });
  const transport = {
    async start() {
      inner.onmessage = (m, extra) => { frames.push({ dir: 'server→agent', m }); this.onmessage?.(m, extra); };
      inner.onclose = () => this.onclose?.();
      inner.onerror = (e) => this.onerror?.(e);
      await inner.start();
    },
    async send(m, opts) { frames.push({ dir: 'agent→server', m }); return inner.send(m, opts); },
    async close() { return inner.close(); },
    get sessionId() { return inner.sessionId; },
    setProtocolVersion(v) { inner.setProtocolVersion?.(v); },
  };
  const client = new Client({ name: 'strongroom-mcp-test', version: '0.0.0' });
  return { client, transport, frames };
}

test('tools are registered', async () => {
  const { client, transport } = makeCapturingClient();
  await client.connect(transport);
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['broker_status', 'grant_lease', 'list_leases', 'list_secrets', 'revoke_lease']);
  await client.close();
});

test('list_secrets returns the name, never the value', async () => {
  const { client, transport } = makeCapturingClient();
  await client.connect(transport);
  const r = await client.callTool({ name: 'list_secrets', arguments: {} });
  const text = r.content.map((c) => c.text).join('');
  assert.ok(text.includes('demo:key'), 'secret name is listed');
  assert.ok(!text.includes(REAL_KEY), 'secret value is NOT in the response');
  await client.close();
});

test('grant_lease returns a lease-backed base URL, never the key', async () => {
  const { client, transport, frames } = makeCapturingClient();
  await client.connect(transport);
  const r = await client.callTool({
    name: 'grant_lease',
    arguments: { secret: 'demo:key', upstream: 'https://api.example.com', ttl_s: 120, uses: 3, inject: 'bearer', paths: ['/v1/status'] },
  });
  const text = r.content.map((c) => c.text).join('');
  const parsed = JSON.parse(text);
  assert.equal(parsed.kind, 'strongroom-lease');
  assert.match(parsed.base_url, /^http:\/\/127\.0\.0\.1:\d+\/lease_[0-9a-f]+$/, 'base_url is a lease-backed broker URL');
  assert.equal(parsed.secret, 'demo:key');
  assert.equal(parsed.upstream, 'https://api.example.com');
  assert.ok(!text.includes(REAL_KEY), 'secret value is NOT in the grant response');
  // The whole point: the real key appears in NO frame the agent ever saw.
  const allFrames = JSON.stringify(frames);
  assert.ok(!allFrames.includes(REAL_KEY), 'secret value crossed the MCP wire in NO frame');
  await client.close();
});

test('list_leases shows fingerprints, revoke_lease kills a lease', async () => {
  const { client, transport } = makeCapturingClient();
  await client.connect(transport);
  const g = await client.callTool({ name: 'grant_lease', arguments: { secret: 'demo:key', upstream: 'https://api.example.com' } });
  const base = JSON.parse(g.content.map((c) => c.text).join('')).base_url;

  const l = await client.callTool({ name: 'list_leases', arguments: {} });
  const leases = JSON.parse(l.content.map((c) => c.text).join('')).leases;
  assert.ok(Array.isArray(leases) && leases.length >= 1, 'a lease is outstanding');
  assert.ok(leases.every((x) => typeof x.fingerprint === 'string' && !x.id), 'leases shown by fingerprint, never raw id');

  // revoke by the base URL (the server extracts the id from the last segment)
  const rv = await client.callTool({ name: 'revoke_lease', arguments: { lease: base } });
  assert.equal(JSON.parse(rv.content.map((c) => c.text).join('')).revoked, true);
  await client.close();
});

test('broker_status reports a listening loopback broker', async () => {
  const { client, transport } = makeCapturingClient();
  await client.connect(transport);
  const r = await client.callTool({ name: 'broker_status', arguments: {} });
  const s = JSON.parse(r.content.map((c) => c.text).join(''));
  assert.equal(s.listening, true);
  assert.equal(s.host, '127.0.0.1');
  assert.match(s.broker_base, /^http:\/\/127\.0\.0\.1:\d+$/);
  await client.close();
});

test.after(() => { try { fs.rmSync(KEEPER_HOME, { recursive: true, force: true }); } catch {} });
