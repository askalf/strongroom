import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const vault = await import('../src/vault.mjs');

const tmpHome = (n) => path.join(os.tmpdir(), `keeper-kc-${process.pid}-${n}`);
function env({ home, keychain, fake, none }) {
  process.env.KEEPER_HOME = home;
  delete process.env.KEEPER_PASSPHRASE;
  keychain ? (process.env.KEEPER_KEYCHAIN = '1') : delete process.env.KEEPER_KEYCHAIN;
  fake ? (process.env.KEEPER_KEYCHAIN_FAKE = fake) : delete process.env.KEEPER_KEYCHAIN_FAKE;
  none ? (process.env.KEEPER_NO_KEYCHAIN = '1') : delete process.env.KEEPER_NO_KEYCHAIN;
}

test('keychain mode: key lives in the keychain, not a plaintext file; vault round-trips', () => {
  const home = tmpHome('a'), fake = path.join(home, 'kc.json');
  env({ home, keychain: true, fake });
  vault.putSecret('X', 'secret-val');
  assert.equal(vault.getSecret('X'), 'secret-val');
  assert.ok(!fs.existsSync(path.join(home, 'master.key')), 'no plaintext master.key in keychain mode');
  assert.ok(JSON.parse(fs.readFileSync(fake, 'utf8')).key, 'the master key is held in the keychain');
});

test('keychain mode: another process retrieves the key from the keychain (not from memory)', () => {
  const home = tmpHome('b'), fake = path.join(home, 'kc.json');
  env({ home, keychain: true, fake });
  vault.putSecret('Y', 'cross-proc-val');
  const child = spawnSync(process.execPath,
    ['--input-type=module', '-e', "import('./src/vault.mjs').then(v=>process.stdout.write(v.getSecret('Y')||'NULL'))"],
    { env: { ...process.env, KEEPER_HOME: home, KEEPER_KEYCHAIN: '1', KEEPER_KEYCHAIN_FAKE: fake }, encoding: 'utf8' });
  assert.equal(child.stdout.trim(), 'cross-proc-val', 'a separate process decrypts using the keychain key');
});

test('keychain fail-closed: requested but unavailable → throws, no silent downgrade', () => {
  env({ home: tmpHome('fc'), keychain: true, none: true });
  assert.throws(() => vault.putSecret('Z', 'v'), /no OS keychain/i);
  assert.equal(vault.getSecret('Z'), null);
});

const realKC = process.platform === 'win32' || process.platform === 'darwin'; // built-in DPAPI / Keychain
test('keychain (real OS): vault round-trips and the key is not plaintext on disk', { skip: !realKC }, () => {
  const home = tmpHome('real');
  env({ home, keychain: true });
  vault.putSecret('R', 'real-secret');
  assert.equal(vault.getSecret('R'), 'real-secret');
  assert.ok(!fs.existsSync(path.join(home, 'master.key')), 'no plaintext master.key');
  if (process.platform === 'win32') {
    const blob = fs.readFileSync(path.join(home, 'master.key.dpapi'), 'utf8').trim();
    assert.ok(blob.length > 64 && !/^[0-9a-f]{64}$/.test(blob), 'key stored as a DPAPI blob, not the raw hex');
  }
});
