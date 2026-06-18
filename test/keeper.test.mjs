import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-' + process.pid); // isolate the vault
import { addSecret, grant, redeem, revoke, vault, audit } from '../src/index.mjs';

test('vault: secrets are encrypted at rest; round-trip decrypts', () => {
  addSecret('API_KEY', 'sk-super-secret-value');
  assert.equal(vault.getSecret('API_KEY'), 'sk-super-secret-value');
  assert.ok(vault.listSecrets().includes('API_KEY'));
  const onDisk = fs.readFileSync(path.join(process.env.KEEPER_HOME, 'vault.json'), 'utf8');
  assert.ok(!onDisk.includes('sk-super-secret-value')); // ciphertext only — never plaintext at rest
});

test('lease: the agent holds a lease, redeem reveals the secret once, then exhausted', () => {
  addSecret('S1', 'val1');
  const l = grant('S1', { uses: 1 });
  assert.ok(l.id.startsWith('lease_') && l.id !== 'val1'); // the agent's handle is not the secret
  const r1 = redeem(l.id);
  assert.equal(r1.ok, true);
  assert.equal(r1.value, 'val1');
  assert.equal(redeem(l.id).reason, 'exhausted'); // single-use spent
});

test('lease: host scope is enforced, and a denial does not burn a use', () => {
  addSecret('S2', 'val2');
  const l = grant('S2', { uses: 1, host: 'api.openai.com' });
  assert.equal(redeem(l.id, { host: 'evil.test' }).reason, 'host-scope');
  assert.equal(redeem(l.id, { host: 'api.openai.com' }).ok, true); // the wrong-host denial didn't consume it
});

test('lease: expired lease is denied', () => {
  addSecret('S3', 'val3');
  assert.equal(redeem(grant('S3', { ttlS: -1 }).id).reason, 'expired');
});

test('lease: revoke kills it immediately', () => {
  addSecret('S4', 'val4');
  const l = grant('S4', { uses: 5 });
  assert.equal(revoke(l.id), true);
  assert.equal(redeem(l.id).reason, 'unknown');
});

test('audit: every access is hash-chained and tamper-evident', () => {
  process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-audit-' + process.pid); // own chain
  addSecret('AK', 'v');
  redeem(grant('AK', { uses: 1 }).id);
  assert.equal(audit.verify().ok, true);
  const f = path.join(process.env.KEEPER_HOME, 'audit.jsonl');
  const lines = fs.readFileSync(f, 'utf8').trim().split('\n');
  const i = lines.findIndex((x) => JSON.parse(x).event === 'redeem');
  const e = JSON.parse(lines[i]); e.secret = 'hidden'; lines[i] = JSON.stringify(e); // rewrite a past access
  fs.writeFileSync(f, lines.join('\n') + '\n');
  assert.equal(audit.verify().ok, false);
});
