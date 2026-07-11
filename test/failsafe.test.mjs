// Fail-safe contract: the egress paths an agent can reach (redeem, revoke, the
// broker's id handling) must NEVER throw on a malformed/hostile lease id — a
// vault that throws at redeem time is a denial-of-service on every caller. Owner
// APIs tolerate odd input too; only an explicit precondition (granting a secret
// that doesn't exist) is allowed to raise.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-failsafe-' + process.pid);
const { addSecret, removeSecret, grant, redeem, revoke, vault, lease } = await import('../src/index.mjs');

const circular = {}; circular.self = circular;
const BAD_IDS = [null, undefined, 123, 0, true, {}, [], Symbol('s'), 10n, ''];

test('redeem / revoke never throw on a malformed lease id (fail closed)', () => {
  for (const id of BAD_IDS) {
    let r;
    assert.doesNotThrow(() => { r = redeem(id); }, `redeem threw on ${String(id)}`);
    assert.equal(r.ok, false);
    assert.doesNotThrow(() => revoke(id), `revoke threw on ${String(id)}`);
    assert.doesNotThrow(() => lease.redeemLease(id), 'lease.redeemLease threw');
    assert.doesNotThrow(() => lease.revokeLease(id), 'lease.revokeLease threw');
    assert.doesNotThrow(() => lease.checkLease(id), 'lease.checkLease threw');
  }
});

test('addSecret tolerates a non-string name and still round-trips', () => {
  for (const name of [123, null, Symbol('k'), true]) {
    assert.doesNotThrow(() => addSecret(name, 'val-' + String(name)), 'addSecret threw on a non-string name');
    assert.equal(vault.getSecret(name), 'val-' + String(name)); // AAD is bound to the coerced name → still decrypts
  }
  // non-string values are coerced, not rejected
  for (const v of [42, null, 10n, { x: 1 }, circular]) assert.doesNotThrow(() => addSecret('v', v));
});

test('grant tolerates null/odd opts; invalid ttl/uses and a missing secret are loud, intentional errors', () => {
  addSecret('S', 'sk-live');
  assert.doesNotThrow(() => grant('S', null), 'grant threw on null opts');
  // non-numeric ttl/uses are REJECTED, not tolerated — a NaN ttl/uses would mint
  // an IMMORTAL lease (`now > NaN` and `NaN <= 0` are both false: never expires,
  // never exhausts), the exact opposite of what a lease is for
  assert.throws(() => grant('S', { ttlS: 'soon' }), /--ttl must be a positive number/);
  assert.throws(() => grant('S', { uses: 'lots' }), /--uses must be a positive number/);
  // other odd opts are still coerced/ignored, never a crash
  assert.doesNotThrow(() => grant('S', { paths: 'x', rate: {} }), 'grant threw on odd opts');
  // a real lease still works end to end
  const l = grant('S', { ttlS: 60, uses: 1 });
  assert.ok(l.id.startsWith('lease_'));
  assert.equal(redeem(l.id).value, 'sk-live');
  // granting a secret that doesn't exist is a loud, intentional error (not a crash)
  assert.throws(() => grant('does-not-exist'), /no such secret/);
});

test('vault getters never throw on a null/odd name', () => {
  for (const n of [null, undefined, 123, Symbol('s'), {}]) {
    assert.doesNotThrow(() => vault.getSecret(n));
    assert.doesNotThrow(() => vault.hasSecret(n));
    assert.doesNotThrow(() => removeSecret(n));
  }
});
