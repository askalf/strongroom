// Master-key rotation battery. A secrets vault must be able to rotate its own
// master key: re-encrypt everything under a new key, atomically, without ever
// stranding the vault half-rekeyed — and the audit's authenticated tip (keyed
// off the master key) must survive the rotation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const BASE = path.join(os.tmpdir(), 'keeper-rekey-' + process.pid);
process.env.KEEPER_HOME = BASE;
delete process.env.KEEPER_PASSPHRASE; delete process.env.KEEPER_KEYCHAIN; delete process.env.KEEPER_NEW_PASSPHRASE;
const { addSecret, grant, redeem, rekeyMasterKey, vault, audit } = await import('../src/index.mjs');
const kp = (f) => path.join(process.env.KEEPER_HOME, f);

test('file mode: rekey rotates the key file and every secret round-trips', () => {
  addSecret('A', 'value-a');
  addSecret('B', 'value-b with spaces\nand a newline');
  const before = fs.readFileSync(kp('master.key'), 'utf8');
  const r = rekeyMasterKey();
  assert.equal(r.secrets, 2);
  assert.deepEqual({ from: r.from, to: r.to }, { from: 'file', to: 'file' });
  assert.notEqual(fs.readFileSync(kp('master.key'), 'utf8'), before, 'key file actually rotated');
  assert.equal(vault.getSecret('A'), 'value-a');
  assert.equal(vault.getSecret('B'), 'value-b with spaces\nand a newline');
  assert.ok(!fs.existsSync(kp('vault.json.new')), 'no staged vault left behind');
});

test('audit: the rekey is recorded and the authenticated tip re-MACs under the new key', () => {
  const v = audit.verify();
  assert.equal(v.ok, true, 'audit verifies after rotation (tip re-MACed)');
  const ev = audit.read().filter((e) => e.event === 'rekey');
  assert.ok(ev.length >= 1, 'rekey event recorded');
  assert.equal(ev.at(-1).secrets, 2);
});

test('leases survive a rekey (names, not ciphertexts)', () => {
  addSecret('LEASED', 'still-here');
  const lease = grant('LEASED', { uses: 1, ttlS: 120 });
  rekeyMasterKey();
  const r = redeem(lease.id);
  assert.equal(r.ok, true, 'lease granted before the rekey redeems after it');
  assert.equal(r.value, 'still-here');
});

test('a stale staged vault from a failed pre-commit attempt is discarded, not adopted', () => {
  fs.writeFileSync(kp('vault.json.new'), 'not even json', { mode: 0o600 });
  const r = rekeyMasterKey();
  assert.ok(r.secrets >= 1);
  assert.ok(!fs.existsSync(kp('vault.json.new')), 'garbage staged vault removed');
  assert.equal(vault.getSecret('LEASED'), 'still-here');
});

test('file → passphrase migration: key file retired, vault opens only with the new passphrase', () => {
  process.env.KEEPER_NEW_PASSPHRASE = 'correct horse battery staple';
  const r = rekeyMasterKey({ to: 'passphrase' });
  assert.deepEqual({ from: r.from, to: r.to }, { from: 'file', to: 'passphrase' });
  assert.ok(!fs.existsSync(kp('master.key')), 'old key file deleted — nothing is encrypted under it anymore');
  assert.equal(process.env.KEEPER_PASSPHRASE, 'correct horse battery staple', 'process now speaks the new passphrase');
  assert.equal(process.env.KEEPER_NEW_PASSPHRASE, undefined, 'new-passphrase env cleared after use');
  assert.equal(vault.getSecret('A'), 'value-a');
  assert.equal(audit.verify().ok, true, 'tip re-MACed under the passphrase-derived key');
});

test('a WRONG current passphrase aborts with nothing changed (no half-rekeyed vault)', () => {
  const vaultBytes = fs.readFileSync(kp('vault.json'), 'utf8');
  const saltBytes = fs.readFileSync(kp('salt'), 'utf8');
  const goodPass = process.env.KEEPER_PASSPHRASE;
  process.env.KEEPER_PASSPHRASE = 'wrong-passphrase';
  process.env.KEEPER_NEW_PASSPHRASE = 'irrelevant';
  assert.throws(() => rekeyMasterKey(), /cannot decrypt secret .* aborting, nothing changed/);
  process.env.KEEPER_PASSPHRASE = goodPass;
  delete process.env.KEEPER_NEW_PASSPHRASE;
  assert.equal(fs.readFileSync(kp('vault.json'), 'utf8'), vaultBytes, 'vault untouched');
  assert.equal(fs.readFileSync(kp('salt'), 'utf8'), saltBytes, 'salt untouched');
  assert.equal(vault.getSecret('A'), 'value-a', 'vault still opens with the right passphrase');
});

test('passphrase → passphrase rotation: new salt, old passphrase locked out', () => {
  const oldPass = process.env.KEEPER_PASSPHRASE;
  const oldSalt = fs.readFileSync(kp('salt'), 'utf8');
  process.env.KEEPER_NEW_PASSPHRASE = 'an entirely new passphrase';
  const r = rekeyMasterKey();
  assert.deepEqual({ from: r.from, to: r.to }, { from: 'passphrase', to: 'passphrase' });
  assert.notEqual(fs.readFileSync(kp('salt'), 'utf8'), oldSalt, 'salt rotated with the passphrase');
  assert.equal(vault.getSecret('A'), 'value-a', 'opens under the new passphrase');
  process.env.KEEPER_PASSPHRASE = oldPass; // the OLD passphrase must now fail closed
  assert.equal(vault.getSecret('A'), null, 'old passphrase no longer decrypts anything');
  process.env.KEEPER_PASSPHRASE = 'an entirely new passphrase';
});

test('passphrase target without KEEPER_NEW_PASSPHRASE refuses up front', () => {
  delete process.env.KEEPER_NEW_PASSPHRASE;
  assert.throws(() => rekeyMasterKey({ to: 'passphrase' }), /KEEPER_NEW_PASSPHRASE/);
});

test('keychain rotation (fake seam): stored key replaced, parked prev-key cleaned up', () => {
  // migrate passphrase → keychain first, then rotate within the keychain
  process.env.KEEPER_KEYCHAIN_FAKE = kp('fake-keychain.json');
  const r1 = rekeyMasterKey({ to: 'keychain' });
  assert.deepEqual({ from: r1.from, to: r1.to }, { from: 'passphrase', to: 'keychain' });
  assert.ok(!fs.existsSync(kp('salt')), 'old salt retired on backend switch');
  const k1 = JSON.parse(fs.readFileSync(kp('fake-keychain.json'), 'utf8')).key;
  assert.ok(k1, 'keychain holds the new key');
  assert.equal(vault.getSecret('A'), 'value-a');

  const r2 = rekeyMasterKey();
  assert.deepEqual({ from: r2.from, to: r2.to }, { from: 'keychain', to: 'keychain' });
  const store = JSON.parse(fs.readFileSync(kp('fake-keychain.json'), 'utf8'));
  assert.notEqual(store.key, k1, 'keychain key rotated');
  assert.equal(store['master-key-prev'], undefined, 'parked old key removed after commit');
  assert.equal(vault.getSecret('A'), 'value-a');
  assert.equal(audit.verify().ok, true, 'tip re-MACed under the keychain key');
});

test('an unknown target key store is refused', () => {
  assert.throws(() => rekeyMasterKey({ to: 'usb-stick' }), /unknown target key store/);
});
