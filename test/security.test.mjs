// Adversarial security battery — keeper is a secrets vault, so its OWN security
// must hold. Each test asserts the SECURE behavior; they fail on a weak build.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-sec-')); // 0700, unpredictable name
process.env.KEEPER_HOME = HOME;
const { addSecret, grant, redeem, vault } = await import('../src/index.mjs');
const { startDaemon } = await import('../src/daemon.mjs');
const here = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(HOME, f), 'utf8');

test('SECURITY: the raw lease id is never written to disk (file read ≠ redeemable)', () => {
  addSecret('K', 'topsecret-value');
  const l = grant('K', { uses: 1 });
  const leasesFile = read('leases.json');
  assert.ok(!leasesFile.includes(l.id), 'raw lease id must NOT appear in leases.json (store the hash)');
  // an attacker who reads the file gets only the stored keys — which must not redeem
  for (const k of Object.keys(JSON.parse(leasesFile))) assert.equal(redeem(k).ok, false, 'a stored key must not be redeemable');
  // the real holder, with the raw id, still can
  assert.equal(redeem(l.id).ok, true);
});

test('SECURITY: a corrupt/tampered vault fails CLOSED (deny, never throw or leak garbage)', () => {
  addSecret('C', 'val-c');
  const l = grant('C', { uses: 5 });
  const v = JSON.parse(read('vault.json'));
  v.secrets.C.ct = 'deadbeefdeadbeef'; // corrupt the ciphertext
  fs.writeFileSync(path.join(HOME, 'vault.json'), JSON.stringify(v));
  assert.doesNotThrow(() => redeem(l.id));
  assert.equal(redeem(l.id).ok, false, 'a broken decrypt must DENY');
  assert.equal(vault.getSecret('C'), null, 'getSecret must never throw or return garbage');
});

test('SECURITY: an orphaned (stale) lease lock is reclaimed, never run unlocked', () => {
  addSecret('L', 'lock-value');
  const l = grant('L', { uses: 1 });
  const lf = path.join(HOME, '.leases.lock');
  fs.writeFileSync(lf, String(process.pid));        // a crashed holder's orphan lock
  const old = (Date.now() - 60000) / 1000;          // 60s ago → past the stale threshold
  fs.utimesSync(lf, old, old);
  const r = redeem(l.id);
  assert.equal(r.ok, true, 'a stale lock is stolen so redeem still works');
  assert.equal(r.value, 'lock-value');
  // Pre-fix the lock could not be acquired, so the critical section ran lock-less
  // and the orphan file was left behind. Post-fix it is stolen, acquired, and
  // released — its absence proves the section ran LOCKED, not unlocked.
  assert.ok(!fs.existsSync(lf), 'the stale lock was reclaimed AND released');
  assert.equal(redeem(l.id).ok, false, 'the single use was consumed exactly once');
});

test('SECURITY: ciphertext is bound to its name — no swap attack', () => {
  addSecret('LOW', 'low-value');
  addSecret('HIGH', 'high-value');
  const v = JSON.parse(read('vault.json'));
  v.secrets.HIGH = v.secrets.LOW; // attacker swaps a ciphertext between names
  fs.writeFileSync(path.join(HOME, 'vault.json'), JSON.stringify(v));
  assert.equal(vault.getSecret('HIGH'), null, 'decrypting under the wrong name must fail (AAD), not return the swapped plaintext');
});

test('SECURITY: a single-use lease cannot be double-spent under concurrency', async () => {
  addSecret('R', 'race-secret');
  const l = grant('R', { uses: 1 });
  const helper = path.join(here, '_redeem-once.mjs');
  const startAt = Date.now() + 700; // shared instant: every process is up + waiting, then they fire together
  const run = () => new Promise((res) => {
    const p = spawn(process.execPath, [helper, l.id, String(startAt)], { env: { ...process.env, KEEPER_HOME: HOME } });
    let out = ''; p.stdout.on('data', (d) => (out += d)); p.on('close', () => res(out.trim()));
  });
  const results = await Promise.all(Array.from({ length: 16 }, run)); // all spawned before any awaited
  const oks = results.filter((r) => r === 'OK').length;
  assert.equal(oks, 1, `exactly one redeem may win a single-use lease — got ${oks}`);
});

test('SECURITY: the redeem-daemon socket is owner-only (0600) even under a permissive umask', { skip: process.platform === 'win32' }, async () => {
  // The redeem-daemon endpoint hands out DECRYPTED secrets. On Unix, connect()
  // needs WRITE permission on the socket node, so if the socket inherits a
  // group/other-writable umask, another local user can reach it. Force the most
  // permissive umask (000): WITHOUT the chmod the socket lands 0777 (this assert
  // fails); WITH it the socket is 0600 — the same owner-only lockdown every other
  // keeper artifact (vault / leases / audit / master key / daemon.json) already has.
  const sockPath = path.join(HOME, 'sec-daemon.sock');
  const prevUmask = process.umask(0o000);
  let daemon;
  try {
    daemon = startDaemon({ socketPath: sockPath, infoFile: path.join(HOME, 'sec-daemon.json'), token: 'tok', onLog: () => {} });
    await once(daemon.server, 'listening');
    const mode = fs.statSync(sockPath).mode & 0o777;
    assert.equal(mode & 0o077, 0, `daemon socket must be owner-only — got 0${mode.toString(8)} (group/other can connect)`);
  } finally {
    process.umask(prevUmask);
    if (daemon) await new Promise((r) => daemon.close(r));
  }
});
