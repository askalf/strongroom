// --json machine contract: grant / leases / ls / audit each put exactly ONE
// parseable JSON value on stdout — no ANSI, no prose, no stderr summary — so a
// control plane dispatching leases to a fleet never scrapes human output.
// Default (no --json) output must stay byte-for-byte what it was.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-clijson-')); // 0700 + unpredictable (CodeQL js/insecure-temporary-file)
process.env.KEEPER_HOME = HOME;
const { addSecret } = await import('../src/index.mjs');

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { env: { ...process.env }, encoding: 'utf8' });

test('grant --json: one parseable object, full lease metadata, no ANSI, no stderr summary', () => {
  addSecret('J1', 'sk-json-secret-value-0123456789');
  const r = run('grant', 'J1', '--json', '--ttl', '120', '--uses', '3',
    '--upstream', 'https://api.openai.com', '--inject', 'bearer',
    '--rate', '60', '--paths', '/v1/chat/*,/v1/models', '--concurrency', '4');
  assert.equal(r.status, 0);
  const o = JSON.parse(r.stdout); // round-trips — the whole contract
  assert.match(o.id, /^lease_/, 'the one-time raw id, machine-readable');
  assert.equal(o.secret, 'J1');
  assert.equal(o.usesLeft, 3);
  assert.equal(o.ttlS, 120);
  assert.ok(typeof o.expiresAt === 'number' && o.expiresAt > Date.now(), 'expiresAt is an epoch-ms number');
  assert.equal(o.upstream, 'https://api.openai.com');
  assert.equal(o.inject, 'bearer');
  assert.equal(o.rate, 60);
  assert.deepEqual(o.paths, ['/v1/chat/*', '/v1/models']);
  assert.equal(o.concurrency, 4);
  assert.ok(!r.stdout.includes('\x1b'), 'no ANSI on the machine channel');
  assert.equal(r.stderr, '', 'no human summary mixed into the invocation');
  assert.ok(!r.stdout.includes('sk-json-secret-value'), 'returns the lease, never the secret value');
});

test('leases --json: array of secret-safe records (fingerprints, no raw ids)', () => {
  const r = run('leases', '--json');
  assert.equal(r.status, 0);
  const ls = JSON.parse(r.stdout);
  assert.ok(Array.isArray(ls) && ls.length >= 1);
  for (const l of ls) {
    assert.equal(typeof l.fingerprint, 'string');
    assert.equal(l.fingerprint.length, 12);
    assert.ok(typeof l.usesLeft === 'number' && typeof l.expiresAt === 'number');
  }
  assert.ok(!r.stdout.includes('lease_'), 'no raw lease id ever appears');
});

test('ls --json: plain array of names', () => {
  const r = run('ls', '--json');
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout), ['J1']);
});

test('audit --json: the parsed event array (mirrors audit.read())', () => {
  const r = run('audit', '--json');
  assert.equal(r.status, 0);
  const events = JSON.parse(r.stdout);
  assert.ok(Array.isArray(events));
  assert.ok(events.some((e) => e.event === 'add' && e.secret === 'J1'));
  assert.ok(events.some((e) => e.event === 'grant'));
});

test('audit --verify --json: { ok, entries } with the 0/1 exit code preserved', () => {
  const r = run('audit', '--verify', '--json');
  const v = JSON.parse(r.stdout);
  assert.equal(v.ok, true);
  assert.ok(v.entries >= 2);
  assert.equal(r.status, 0);

  // tamper mid-chain → ok:false surfaced in the JSON AND exit 1
  const p = path.join(HOME, 'audit.jsonl');
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  const o0 = JSON.parse(lines[0]);
  o0.ts = '1999-01-01T00:00:00.000Z';
  lines[0] = JSON.stringify(o0);
  fs.writeFileSync(p, lines.join('\n') + '\n');
  const r2 = run('audit', '--verify', '--json');
  const v2 = JSON.parse(r2.stdout);
  assert.equal(v2.ok, false, 'tampering surfaces as ok:false');
  assert.equal(r2.status, 1, 'failure exit code preserved under --json');
});

test('without --json, output is unchanged (bare id on stdout, dim summary on stderr)', () => {
  const r = run('grant', 'J1', '--ttl', '60');
  assert.equal(r.status, 0);
  assert.match(r.stdout.trim(), /^lease_[0-9a-f]+$/, 'human path still prints the bare id');
  assert.ok(r.stderr.includes('J1'), 'human summary still goes to stderr');
});
