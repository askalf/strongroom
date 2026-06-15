import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-broker-' + process.pid);
const { addSecret, grant } = await import('../src/index.mjs');
const { startBroker } = await import('../src/broker.mjs');

const up = (server) => new Promise((res) => server.on('listening', () => res(server.address().port)));

test('broker injects the leased secret upstream; the agent holds only the lease', async () => {
  // stub "upstream API" that echoes what it received
  const stub = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ authorization: req.headers['authorization'] || null, path: req.url, hadXKey: !!req.headers['x-api-key'] }));
  });
  stub.listen(0, '127.0.0.1');
  const stubPort = await up(stub);

  addSecret('OPENAI', 'sk-the-real-key');
  const lease = grant('OPENAI', { uses: 3, upstream: `http://127.0.0.1:${stubPort}`, inject: 'bearer' });

  const broker = startBroker({ port: 0 });
  const brokerPort = await up(broker);

  // the agent makes a normal API call with NO key — just the lease in the base URL
  const r = await fetch(`http://127.0.0.1:${brokerPort}/${lease.id}/v1/models`, { headers: { authorization: 'Bearer DUMMY-agent-has-no-real-key' } });
  const echoed = await r.json();

  assert.equal(echoed.authorization, 'Bearer sk-the-real-key', 'upstream received the injected real secret');
  assert.equal(echoed.path, '/v1/models', 'path forwarded to the bound upstream');
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
