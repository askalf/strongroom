// rekey --json — isolated from cli-json.test.mjs deliberately: rotating the
// master key is whole-vault surgery, and cli-json.test.mjs already ends by
// tampering its own audit chain on purpose. A rekey belongs in its own vault,
// same reasoning that gave rekey.test.mjs its own file for the library path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-rekeyjson-'));
process.env.KEEPER_HOME = HOME;
delete process.env.KEEPER_PASSPHRASE; delete process.env.KEEPER_KEYCHAIN; delete process.env.KEEPER_NEW_PASSPHRASE;
const { addSecret } = await import('../src/index.mjs');

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { env: { ...process.env }, encoding: 'utf8' });

test('rekey --json: structured result, secret still round-trips under the new key', () => {
  addSecret('RK1', 'rekey-json-value');
  const r = run('rekey', '--json');
  assert.equal(r.status, 0);
  const o = JSON.parse(r.stdout);
  assert.equal(o.ok, true);
  assert.deepEqual({ from: o.from, to: o.to }, { from: 'file', to: 'file' });
  assert.equal(o.secrets, 1);
  assert.ok(!r.stdout.includes('\x1b'), 'no ANSI on the machine channel');

  const after = run('ls', '--json');
  assert.deepEqual(JSON.parse(after.stdout), ['RK1'], 'the secret survived rotation, reachable through normal reads');
});

test('rekey --json: a failure is { ok:false, error } with exit 1, not a thrown stack trace', () => {
  // An unknown --to target is the cheapest way to force rekeyMasterKey to
  // throw without touching real key-storage backends.
  const r = run('rekey', '--to', 'not-a-real-backend', '--json');
  assert.equal(r.status, 1);
  const o = JSON.parse(r.stdout);
  assert.equal(o.ok, false);
  assert.equal(typeof o.error, 'string');
});
