// Regression battery for the 2026-06-17 red-team findings. Each test reproduces
// a CONFIRMED bypass and asserts the now-secure behavior:
//   FIX 1  broker `--paths` scope defeated by `..` traversal (parser differential)
//   FIX 2  host-scoped lease redeemed with NO host returned the secret for any host
//   FIX 3  audit tail-truncation verified "intact"
//   FIX 4  legacy-demote + forged-GENESIS splice verified "intact"
// Plus false-positive guards (intact / empty / normal-path must still pass).
//
// Secret- and payload-shaped strings are assembled from fragments so this file
// carries no literal credential or RCE payload at rest.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

// Isolated vault home + a fake keychain (never a predictable tmp path) so the
// audit tip is keyed by a master key held "in the keychain", as in production.
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-redteam-'));
process.env.KEEPER_HOME = HOME;
process.env.KEEPER_KEYCHAIN = '1';
process.env.KEEPER_KEYCHAIN_FAKE = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-kc-')) + path.sep + 'kc.json';
delete process.env.KEEPER_NO_KEYCHAIN;
delete process.env.KEEPER_PASSPHRASE;

const { addSecret, grant, redeem, audit, lease } = await import('../src/index.mjs');
const { startBroker } = await import('../src/broker.mjs');
const { GENESIS, hashOf } = await import('@askalf/warden/audit');

const listen = (s) => new Promise((r) => s.on('listening', () => r(s.address().port)));

// A secret value assembled from fragments (so no literal secret lives in the file).
const SECRET = ['sk', 'live', 'r3dt34m', 'value'].join('-');

// ───────────────────────── FIX 1 — path-traversal scope bypass ─────────────────────────
test('FIX1: a chat-scoped lease cannot reach /v1/admin/keys via `..` traversal, and the upstream never sees the secret toward admin', async () => {
  const seen = []; // { path, auth }
  const up = http.createServer((req, res) => { seen.push({ path: req.url, auth: req.headers['authorization'] || null }); res.end('ok'); });
  up.listen(0, '127.0.0.1');
  const up_port = await listen(up);

  addSecret('CHAT_KEY', SECRET);
  const l = grant('CHAT_KEY', { uses: 9, upstream: `http://127.0.0.1:${up_port}`, inject: 'bearer', paths: ['/v1/chat/*'] });

  const br = startBroker({ port: 0 });
  const bp = await listen(br);

  // Send the traversal over a RAW socket — fetch()/WHATWG would canonicalize `..`
  // client-side and never put it on the wire. We must transmit the literal `..`.
  const rawGet = (target) => new Promise((resolve) => {
    const sock = net.connect(bp, '127.0.0.1', () => {
      sock.write(`GET ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`);
    });
    let buf = '';
    sock.on('data', (d) => (buf += d.toString()));
    sock.on('close', () => resolve(buf));
    sock.on('error', () => resolve(buf));
  });

  const dotdot = '/v1/chat/..' + '/admin/keys'; // canonicalizes to /v1/admin/keys
  const resp = await rawGet(`/${l.id}${dotdot}`);
  const statusLine = resp.split('\r\n')[0];
  assert.match(statusLine, /\b403\b/, 'traversal out of the /v1/chat/* scope must be denied (403)');

  // The upstream must NOT have received any request to the admin endpoint, and
  // certainly none carrying the injected real secret.
  const admin = seen.find((s) => s.path && s.path.includes('/admin/keys'));
  assert.equal(admin, undefined, 'broker must not forward an out-of-scope admin request upstream');
  assert.ok(!seen.some((s) => s.auth && s.auth.includes(SECRET)), 'the real secret must never be injected toward an out-of-scope path');

  // Control: a genuinely in-scope path still works and DOES get the secret.
  const okResp = await rawGet(`/${l.id}/v1/chat/completions`);
  assert.match(okResp.split('\r\n')[0], /\b200\b/, 'an in-scope path is still allowed');
  const okHit = seen.find((s) => s.path === '/v1/chat/completions');
  assert.ok(okHit && okHit.auth === 'Bearer ' + SECRET, 'an allowed path still gets the injected secret');

  up.close(); br.close();
});

// ───────────────────────── FIX 2 — host-scope skipped when host omitted ─────────────────────────
test('FIX2: a host-scoped lease denies redeem with no host / wrong host and allows the right host', () => {
  addSecret('HS', SECRET);
  const mk = () => grant('HS', { uses: 1, host: 'api.stripe.com' });

  assert.equal(redeem(mk().id, {}).reason, 'host-scope', 'no host must DENY a host-scoped lease (was the bypass)');
  assert.equal(redeem(mk().id, { host: undefined }).reason, 'host-scope', 'undefined host must DENY');
  assert.equal(redeem(mk().id, { host: '' }).reason, 'host-scope', 'empty host must DENY');
  assert.equal(redeem(mk().id, { host: 'evil.example' }).reason, 'host-scope', 'wrong host must DENY');

  const good = redeem(mk().id, { host: 'api.stripe.com' });
  assert.equal(good.ok, true, 'the matching host is allowed');
  assert.equal(good.value, SECRET);

  // peekLease (broker's non-enforcing reader) sees the binding without consuming.
  const l = mk();
  const peek = lease.peekLease(l.id);
  assert.equal(peek.ok, true);
  assert.equal(peek.lease.host, 'api.stripe.com');
  assert.equal(redeem(l.id, { host: 'api.stripe.com' }).ok, true, 'peek did not burn the use');
});

test('FIX2: a host-scoped lease works through the broker when its host matches its upstream', async () => {
  let sawAuth = null;
  const up = http.createServer((req, res) => { sawAuth = req.headers['authorization'] || null; res.end('ok'); });
  up.listen(0, '127.0.0.1');
  const up_port = await listen(up);

  addSecret('HSB', SECRET);
  // The broker derives the host from the upstream; bind the lease host to it.
  const l = grant('HSB', { uses: 1, host: '127.0.0.1', upstream: `http://127.0.0.1:${up_port}`, inject: 'bearer' });

  const br = startBroker({ port: 0 });
  const bp = await listen(br);
  const r = await fetch(`http://127.0.0.1:${bp}/${l.id}/v1/models`);
  assert.equal(r.status, 200, 'host-scoped lease whose host matches its upstream redeems through the broker');
  assert.equal(sawAuth, 'Bearer ' + SECRET, 'the secret is injected upstream');
  up.close(); br.close();
});

test('FIX2: a lease whose host does NOT match its own upstream is refused at the broker (never redeemed)', async () => {
  const up = http.createServer((req, res) => res.end('ok'));
  up.listen(0, '127.0.0.1');
  const up_port = await listen(up);
  addSecret('HSX', SECRET);
  const l = grant('HSX', { uses: 1, host: 'api.stripe.com', upstream: `http://127.0.0.1:${up_port}`, inject: 'bearer' });
  const br = startBroker({ port: 0 });
  const bp = await listen(br);
  assert.equal((await fetch(`http://127.0.0.1:${bp}/${l.id}/v1/x`)).status, 403, 'lease host must agree with its bound upstream');
  // the rejected call must not have consumed the single use
  assert.equal(lease.peekLease(l.id).lease.usesLeft, 1, 'host-scope deny burned no use');
  up.close(); br.close();
});

// ───────────────────────── FIX 3 — audit tail truncation ─────────────────────────
function buildChain(home) {
  process.env.KEEPER_HOME = home;
  addSecret('AUD', 'v');
  const l = grant('AUD', { uses: 2 });
  redeem(l.id); redeem(l.id);
  return path.join(home, 'audit.jsonl');
}

test('FIX3: truncating the audit tail makes verify() fail', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-aud3-'));
  const f = buildChain(home);
  assert.equal(audit.verify().ok, true, 'a freshly-built chain verifies intact (FP guard)');

  const lines = fs.readFileSync(f, 'utf8').trim().split('\n');
  assert.ok(lines.length >= 3, 'precondition: several entries');
  fs.writeFileSync(f, lines.slice(0, 2).join('\n') + '\n'); // drop the tail — a valid PREFIX remains
  const v = audit.verify();
  assert.equal(v.ok, false, 'a truncated audit must NOT verify as intact');
  assert.equal(v.reason, 'audit-truncated-or-spliced');
  process.env.KEEPER_HOME = HOME;
});

// ───────────────────────── FIX 4 — legacy-demote + forged-GENESIS splice ─────────────────────────
test('FIX4: demoting real entries to hashless "legacy" + appending a forged GENESIS-rooted entry makes verify() fail', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-aud4-'));
  const f = buildChain(home);
  assert.equal(audit.verify().ok, true, 'intact before tamper (FP guard)');

  const lines = fs.readFileSync(f, 'utf8').trim().split('\n');
  // Demote every genuine entry to a hashless "legacy" line (warden's verify skips
  // leading legacy lines), then forge one fresh GENESIS-rooted entry — the keyless
  // chain alone would accept this; the authenticated tip must not.
  const demoted = lines.map((x) => { const o = JSON.parse(x); delete o.hash; delete o.prev; return JSON.stringify(o); });
  const forgedRec = { ts: new Date().toISOString(), event: 'revoke', lease: 'f0f0f0f0f0f0', via: 'splice' };
  const forged = { ...forgedRec, prev: GENESIS, hash: hashOf(GENESIS, forgedRec) };
  fs.writeFileSync(f, demoted.join('\n') + '\n' + JSON.stringify(forged) + '\n');

  const v = audit.verify();
  assert.equal(v.ok, false, 'a legacy-demote + forged-genesis splice must NOT verify as intact');
  assert.ok(v.reason === 'audit-truncated-or-spliced' || v.reason === 'audit-tip-missing', `unexpected reason: ${v.reason}`);

  // And forging the tip itself (without the master key) is caught as well.
  const tipF = path.join(home, 'audit.tip.json');
  fs.writeFileSync(tipF, JSON.stringify({ n: 1, hash: forged.hash, mac: '00'.repeat(32) }));
  assert.equal(audit.verify().reason, 'audit-tip-forged', 'a tip forged without the master key is detected');
  process.env.KEEPER_HOME = HOME;
});

test('FIX3/4 FP guard: an intact audit verifies ok, and deleting the tip on a non-empty log is itself caught', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-audfp-'));
  buildChain(home);
  assert.equal(audit.verify().ok, true, 'genuine intact audit must stay ok');
  fs.rmSync(path.join(home, 'audit.tip.json'));
  const v = audit.verify();
  assert.equal(v.ok, false, 'a missing tip on a non-empty log is tampering');
  assert.equal(v.reason, 'audit-tip-missing');
  process.env.KEEPER_HOME = HOME;
});

test('FIX3/4 FP guard: a present-but-empty audit verifies ok (nothing to protect yet)', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-audempty-'));
  process.env.KEEPER_HOME = home;
  fs.writeFileSync(path.join(home, 'audit.jsonl'), ''); // present, empty
  assert.equal(audit.verify().ok, true, 'an empty audit (no entries) with no tip is ok');
  process.env.KEEPER_HOME = HOME;
});

// ───── FIX 5 (2026-06-18) — audit tip-downgrade when the master key is withheld ─────
test('FIX5: a tip-protected audit does NOT downgrade to "intact" when the master key is unavailable', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-downgrade-'));
  buildChain(home); // built WITH the keychain key → tip + protected marker written
  process.env.KEEPER_HOME = HOME;
  assert.ok(fs.existsSync(path.join(home, 'audit.protected')), 'precondition: tip-protected marker was written');
  assert.ok(fs.existsSync(path.join(home, 'audit.tip.json')), 'precondition: a tip exists');

  // Attacker truncates the log to a valid prefix AND deletes the tip. In key-file
  // mode the key sits beside audit.jsonl, so they can withhold it too — here we
  // simulate the withheld key with a missing keychain (masterKey throws → no key).
  const f = path.join(home, 'audit.jsonl');
  const lines = fs.readFileSync(f, 'utf8').trim().split('\n');
  fs.writeFileSync(f, lines.slice(0, 2).join('\n') + '\n');
  fs.rmSync(path.join(home, 'audit.tip.json'));

  // Verify in a FRESH process (no in-proc key cache), key unavailable.
  const idx = pathToFileURL(path.join(process.cwd(), 'src', 'index.mjs')).href;
  const run = (env) => {
    const out = execFileSync(process.execPath, ['--input-type=module', '-e',
      `import { audit } from ${JSON.stringify(idx)}; const v = audit.verify(); process.stdout.write(JSON.stringify({ ok: v.ok, reason: v.reason || null }));`],
      { env, encoding: 'utf8' });
    return JSON.parse(out);
  };

  const withheld = run({ ...process.env, KEEPER_HOME: home, KEEPER_KEYCHAIN: '1', KEEPER_KEYCHAIN_FAKE: path.join(home, 'NO_SUCH_KC.json'), KEEPER_PASSPHRASE: '' });
  assert.equal(withheld.ok, false, 'a withheld key on a tip-protected vault must NOT verify as intact (was the downgrade bypass)');
  assert.ok(['audit-key-unavailable', 'audit-truncated-or-spliced'].includes(withheld.reason), `unexpected reason: ${withheld.reason}`);
  process.env.KEEPER_HOME = HOME;
});

test('FIX5 FP guard: an empty vault (nothing recorded, no key/tip/marker) is not falsely flagged', () => {
  // The real false-positive risk: a fresh vault whose key is unavailable must not
  // be reported as tampered when there is simply nothing protected yet. (A vault
  // that HAS entries always has a key+marker — you can't store secrets without a
  // key — so the only no-marker case is an empty/fresh vault.)
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-empty-'));
  fs.writeFileSync(path.join(home, 'audit.jsonl'), ''); // present, empty
  const idx = pathToFileURL(path.join(process.cwd(), 'src', 'index.mjs')).href;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e',
    `import { audit } from ${JSON.stringify(idx)}; const v = audit.verify(); process.stdout.write(JSON.stringify({ ok: v.ok, reason: v.reason || null }));`],
    { env: { ...process.env, KEEPER_HOME: home, KEEPER_KEYCHAIN: '1', KEEPER_KEYCHAIN_FAKE: path.join(home, 'NO_KC.json'), KEEPER_PASSPHRASE: '' }, encoding: 'utf8' });
  const v = JSON.parse(out);
  assert.equal(v.ok, true, 'an empty audit with no key/tip/marker verifies ok (nothing to protect)');
  process.env.KEEPER_HOME = HOME;
});

// ───────────────────────── FP guard: normal broker flow still works ─────────────────────────
test('FP guard: a normal redeem through the broker to an allowed path still works end-to-end', async () => {
  let sawAuth = null, sawPath = null;
  const up = http.createServer((req, res) => { sawAuth = req.headers['authorization'] || null; sawPath = req.url; res.end('ok'); });
  up.listen(0, '127.0.0.1');
  const up_port = await listen(up);

  addSecret('NORMAL', SECRET);
  const l = grant('NORMAL', { uses: 1, upstream: `http://127.0.0.1:${up_port}`, inject: 'bearer', paths: ['/v1/chat/*'] });
  const br = startBroker({ port: 0 });
  const bp = await listen(br);
  const r = await fetch(`http://127.0.0.1:${bp}/${l.id}/v1/chat/completions?model=x`);
  assert.equal(r.status, 200);
  assert.equal(sawPath, '/v1/chat/completions?model=x', 'query string is preserved through canonicalization');
  assert.equal(sawAuth, 'Bearer ' + SECRET, 'the allowed call still gets the injected secret');
  up.close(); br.close();
});
