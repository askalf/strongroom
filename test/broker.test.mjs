import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-broker-' + process.pid);
const { addSecret, grant } = await import('../src/index.mjs');
const { checkLease } = await import('../src/lease.mjs');
const { startBroker } = await import('../src/broker.mjs');

const up = (server) => new Promise((res) => server.on('listening', () => res(server.address().port)));

test('broker injects the leased secret upstream; the agent holds only the lease', async () => {
  // stub "upstream API" that RECORDS what it received (asserted server-side —
  // echoing the secret back through the body would now just get it redacted)
  let saw;
  const stub = http.createServer((req, res) => {
    saw = { authorization: req.headers['authorization'] || null, path: req.url, hadXKey: !!req.headers['x-api-key'] };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  });
  stub.listen(0, '127.0.0.1');
  const stubPort = await up(stub);

  addSecret('OPENAI', 'sk-the-real-key');
  const lease = grant('OPENAI', { uses: 3, upstream: `http://127.0.0.1:${stubPort}`, inject: 'bearer' });

  const broker = startBroker({ port: 0 });
  const brokerPort = await up(broker);

  // the agent makes a normal API call with NO key — just the lease in the base URL
  const r = await fetch(`http://127.0.0.1:${brokerPort}/${lease.id}/v1/models`, { headers: { authorization: 'Bearer DUMMY-agent-has-no-real-key' } });
  assert.deepEqual(await r.json(), { ok: true }, 'upstream response relayed to the agent');

  assert.equal(saw.authorization, 'Bearer sk-the-real-key', 'upstream received the injected real secret');
  assert.equal(saw.path, '/v1/models', 'path forwarded to the bound upstream');
  assert.ok(!lease.id.includes('sk-the-real-key'), "the agent's lease is not the secret");

  stub.close(); broker.close();
});

test('broker denies an unknown/exhausted lease and forwards nothing', async () => {
  const broker = startBroker({ port: 0 });
  const port = await up(broker);
  const r = await fetch(`http://127.0.0.1:${port}/lease_does_not_exist/x`);
  assert.equal(r.status, 403);
  broker.close();
});

test('broker refuses a lease with no bound upstream (no blind forwarding)', async () => {
  addSecret('NOUP', 'v');
  const lease = grant('NOUP', { uses: 1 }); // no --upstream
  const broker = startBroker({ port: 0 });
  const port = await up(broker);
  const r = await fetch(`http://127.0.0.1:${port}/${lease.id}/x`);
  assert.equal(r.status, 400);
  broker.close();
});

test('broker enforces the path allowlist (lease scoped to specific endpoints)', async () => {
  const stub = http.createServer((req, res) => res.end('ok'));
  stub.listen(0, '127.0.0.1');
  const sp = await up(stub);
  addSecret('PATHS', 'k');
  const lease = grant('PATHS', { uses: 9, upstream: `http://127.0.0.1:${sp}`, inject: 'bearer', paths: ['/v1/chat/*', '/v1/models'] });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);
  assert.equal((await fetch(`http://127.0.0.1:${bp}/${lease.id}/v1/chat/completions`)).status, 200, 'allowed glob path');
  assert.equal((await fetch(`http://127.0.0.1:${bp}/${lease.id}/v1/models`)).status, 200, 'allowed exact path');
  assert.equal((await fetch(`http://127.0.0.1:${bp}/${lease.id}/v1/admin/keys`)).status, 403, 'disallowed path blocked before injection');
  stub.close(); broker.close();
});

test('broker enforces the per-lease rate limit (429, no use consumed)', async () => {
  const stub = http.createServer((req, res) => res.end('ok'));
  stub.listen(0, '127.0.0.1');
  const sp = await up(stub);
  addSecret('RATE', 'k');
  const lease = grant('RATE', { uses: 100, upstream: `http://127.0.0.1:${sp}`, inject: 'bearer', rate: 2 }); // 2 / minute
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);
  const hit = () => fetch(`http://127.0.0.1:${bp}/${lease.id}/x`).then((r) => r.status);
  assert.equal(await hit(), 200);
  assert.equal(await hit(), 200);
  assert.equal(await hit(), 429, 'third request over the 2/min cap is rate-limited');
  // only the 2 forwarded requests consumed a use; the rate-limited one did not
  assert.equal(checkLease(lease.id).lease.usesLeft, 98, 'rate-limited request consumed no use');
  stub.close(); broker.close();
});
