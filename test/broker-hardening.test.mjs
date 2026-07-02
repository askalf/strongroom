// Broker response-sanitizer + concurrency-cap battery. The broker injects the
// secret upstream — these tests prove it can't come BACK: a reflecting upstream
// (echo/debug endpoint, verbose error, misconfigured proxy) gets redacted from
// the relayed headers and body, streaming survives, and a lease's in-flight
// request count is capped at grant time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-broker-hard-' + process.pid);
const { addSecret, grant, audit } = await import('../src/index.mjs');
const { checkLease } = await import('../src/lease.mjs');
const { startBroker } = await import('../src/broker.mjs');

const up = (server) => new Promise((res) => server.on('listening', () => res(server.address().port)));
const SECRET = 'sk-reflected-secret-0123456789abcdef';
const REDACTED = '[keeper:redacted]';

test('a reflected secret in the response BODY is redacted (and audited)', async () => {
  // stub upstream that echoes the auth header it received — the reflection leak
  const stub = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ echo: req.headers['authorization'] }));
  });
  stub.listen(0, '127.0.0.1');
  addSecret('REFLECT', SECRET);
  const lease = grant('REFLECT', { uses: 3, upstream: `http://127.0.0.1:${await up(stub)}`, inject: 'bearer' });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);

  const text = await (await fetch(`http://127.0.0.1:${bp}/${lease.id}/v1/echo`)).text();
  assert.ok(!text.includes(SECRET), 'secret does not reach the agent');
  assert.ok(text.includes(REDACTED), 'reflection replaced with the redaction marker');
  const ev = audit.read().filter((e) => e.event === 'sanitize' && e.where === 'body');
  assert.equal(ev.length, 1, 'body reflection audited once for the request');

  stub.close(); broker.close();
});

test('a secret SPLIT across stream chunks is still redacted', async () => {
  const mid = Math.floor(SECRET.length / 2);
  const stub = http.createServer((req, res) => {
    res.write('leak: ' + SECRET.slice(0, mid)); // first half in one chunk…
    setTimeout(() => { res.end(SECRET.slice(mid) + ' :end'); }, 50); // …rest later
  });
  stub.listen(0, '127.0.0.1');
  addSecret('SPLIT', SECRET);
  const lease = grant('SPLIT', { uses: 3, upstream: `http://127.0.0.1:${await up(stub)}`, inject: 'bearer' });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);

  const text = await (await fetch(`http://127.0.0.1:${bp}/${lease.id}/x`)).text();
  assert.equal(text, 'leak: ' + REDACTED + ' :end', 'boundary-spanning secret redacted');

  stub.close(); broker.close();
});

test('a reflected secret in a response HEADER is redacted (and audited)', async () => {
  const stub = http.createServer((req, res) => {
    res.setHeader('x-upstream-saw', req.headers['authorization'] || 'none');
    res.end('ok');
  });
  stub.listen(0, '127.0.0.1');
  addSecret('HDR', SECRET);
  const lease = grant('HDR', { uses: 3, upstream: `http://127.0.0.1:${await up(stub)}`, inject: 'bearer' });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);

  const r = await fetch(`http://127.0.0.1:${bp}/${lease.id}/x`);
  assert.equal(r.headers.get('x-upstream-saw'), 'Bearer ' + REDACTED, 'header reflection redacted');
  assert.ok(audit.read().some((e) => e.event === 'sanitize' && e.where === 'header'), 'header reflection audited');

  stub.close(); broker.close();
});

test('a clean streaming (SSE) response passes through unchanged', async () => {
  const events = 'data: {"delta":"hel"}\n\ndata: {"delta":"lo"}\n\ndata: [DONE]\n\n';
  const stub = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/event-stream');
    let i = 0;
    const parts = events.split(/(?<=\n\n)/); // one write per SSE event
    const tick = () => { if (i < parts.length) { res.write(parts[i++]); setTimeout(tick, 10); } else res.end(); };
    tick();
  });
  stub.listen(0, '127.0.0.1');
  addSecret('SSE', SECRET);
  const lease = grant('SSE', { uses: 3, upstream: `http://127.0.0.1:${await up(stub)}`, inject: 'x-api-key' });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);

  const r = await fetch(`http://127.0.0.1:${bp}/${lease.id}/v1/messages`);
  assert.equal(await r.text(), events, 'sanitizer is byte-transparent when nothing reflects');

  stub.close(); broker.close();
});

test('broker forces an uncompressed upstream response (accept-encoding: identity)', async () => {
  let saw;
  const stub = http.createServer((req, res) => { saw = req.headers['accept-encoding']; res.end('ok'); });
  stub.listen(0, '127.0.0.1');
  addSecret('ENC', SECRET);
  const lease = grant('ENC', { uses: 3, upstream: `http://127.0.0.1:${await up(stub)}`, inject: 'bearer' });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);

  await fetch(`http://127.0.0.1:${bp}/${lease.id}/x`, { headers: { 'accept-encoding': 'gzip, br' } });
  assert.equal(saw, 'identity', 'agent-requested compression overridden so the scan sees real bytes');

  stub.close(); broker.close();
});

test('broker enforces the per-lease concurrency cap (429, no use consumed)', async () => {
  // slow upstream: every request holds its response open long enough to overlap
  const stub = http.createServer((req, res) => setTimeout(() => res.end('ok'), 400));
  stub.listen(0, '127.0.0.1');
  addSecret('CONC', SECRET);
  const lease = grant('CONC', { uses: 10, upstream: `http://127.0.0.1:${await up(stub)}`, inject: 'bearer', concurrency: 1 });
  const broker = startBroker({ port: 0 });
  const bp = await up(broker);

  const hit = () => fetch(`http://127.0.0.1:${bp}/${lease.id}/x`).then((r) => r.status);
  const statuses = (await Promise.all([hit(), hit()])).sort();
  assert.deepEqual(statuses, [200, 429], 'second simultaneous request over the cap is refused');
  assert.equal(checkLease(lease.id).lease.usesLeft, 9, 'refused request consumed no use');
  assert.ok(audit.read().some((e) => e.event === 'deny' && e.reason === 'concurrency'), 'concurrency deny audited');

  // the slot frees once the first response completes — the lease still works
  assert.equal(await hit(), 200, 'cap releases after the in-flight request finishes');

  stub.close(); broker.close();
});
