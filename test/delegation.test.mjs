// Lease delegation (attenuation). A parent agent turns its OWN lease into a
// NARROWER sub-lease for a sub-agent — shorter TTL, fewer uses, tighter
// host/upstream/paths/rate/concurrency, NEVER wider — with the parent lease
// fingerprint recorded in the child's grant audit event. These tests prove the
// attenuate-only invariant (every widening attempt is REJECTED and audited),
// that unset scopes inherit the parent's, that the child redeems within its
// tighter bounds, and that the delegation composes with the hash-chained audit
// into a parent→child trail (`from` = the parent fingerprint) that still verifies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-deleg-' + process.pid);
const { addSecret, grant, grantFromLease, redeem, audit } = await import('../src/index.mjs');
const { checkLease, attenuateLease, globSubsumes, pathsSubsumed } = await import('../src/lease.mjs');

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const noCaps = () => { delete process.env.KEEPER_MAX_TTL; delete process.env.KEEPER_MAX_USES; };
// The audit/child fingerprint: sha256(rawId).slice(0,12), matching index/lease.
const fp = (id) => crypto.createHash('sha256').update(String(id)).digest('hex').slice(0, 12);

test('attenuate: a sub-lease inherits the parent scope when nothing is tightened', () => {
  noCaps();
  addSecret('API', 'sk-secretvalue-123456');
  const parent = grant('API', { ttlS: 3600, uses: 5, host: 'api.example.com', upstream: 'https://api.example.com', paths: ['/v1/*'] });
  const child = grantFromLease(parent.id, {});
  assert.equal(child.secret, 'API', 'child binds the SAME secret');
  assert.equal(child.host, 'api.example.com', 'inherits host');
  assert.equal(child.upstream, 'https://api.example.com', 'inherits upstream');
  assert.deepEqual(child.paths, ['/v1/*'], 'inherits paths');
  assert.equal(child.usesLeft, 5, 'inherits remaining uses');
  assert.ok(child.expiresAt <= parent.expiresAt, 'child cannot outlive the parent');
  assert.equal(child.parent, fp(parent.id), 'child records the parent fingerprint');
  assert.equal(checkLease(child.id, { host: 'api.example.com' }).ok, true, 'child is a valid, independent lease (host-scoped, inherited)');
});

test('attenuate: TTL, uses, rate, concurrency can only NARROW', () => {
  noCaps();
  addSecret('API2', 'sk-secretvalue-abcdef');
  const parent = grant('API2', { ttlS: 3600, uses: 10, rate: 60, concurrency: 4 });
  // narrower on every axis → accepted
  const child = grantFromLease(parent.id, { ttlS: 600, uses: 3, rate: 10, concurrency: 1 });
  assert.equal(child.usesLeft, 3);
  assert.equal(child.rate, 10);
  assert.equal(child.concurrency, 1);
  assert.ok(child.expiresAt - child.createdAt <= 600 * 1000 + 50, 'ttl honored');
  // wider on any axis → REJECTED, naming the axis
  assert.throws(() => grantFromLease(parent.id, { uses: 99 }), /--uses 99 exceeds the parent lease's remaining/);
  assert.throws(() => grantFromLease(parent.id, { ttlS: 999999 }), /--ttl .* exceeds the parent lease's remaining/);
  assert.throws(() => grantFromLease(parent.id, { rate: 600 }), /--rate 600 exceeds the parent lease's 60/);
  assert.throws(() => grantFromLease(parent.id, { concurrency: 8 }), /--concurrency 8 exceeds the parent lease's 4/);
});

test('attenuate: an UNLIMITED parent axis may be capped by the child; a redirect is rejected', () => {
  noCaps();
  addSecret('API3', 'sk-secretvalue-ghijkl');
  // parent has no rate/concurrency cap and no host binding
  const parent = grant('API3', { ttlS: 3600, uses: 4, upstream: 'https://api.example.com' });
  const child = grantFromLease(parent.id, { rate: 30, concurrency: 2, host: 'api.example.com' });
  assert.equal(child.rate, 30, 'child may add a rate cap where the parent had none');
  assert.equal(child.concurrency, 2, 'child may add a concurrency cap');
  assert.equal(child.host, 'api.example.com', 'child may tighten the host where the parent left it open');
  // but it may NOT redirect a bound field to a different destination
  assert.throws(() => grantFromLease(parent.id, { upstream: 'https://evil.example.net' }),
    /--upstream .* differs from the parent lease's/);
});

test('attenuate: paths allowlist must be a SUBSET of the parent allowlist', () => {
  noCaps();
  addSecret('API4', 'sk-secretvalue-mnopqr');
  const parent = grant('API4', { ttlS: 3600, uses: 5, paths: ['/v1/chat/*', '/v1/models'] });
  // subset → accepted
  const child = grantFromLease(parent.id, { paths: ['/v1/chat/completions'] });
  assert.deepEqual(child.paths, ['/v1/chat/completions']);
  // a path OUTSIDE the parent allowlist → rejected
  assert.throws(() => grantFromLease(parent.id, { paths: ['/v1/admin/keys'] }),
    /is not within the parent lease's paths/);
  // a BROADER glob than the parent's → rejected
  assert.throws(() => grantFromLease(parent.id, { paths: ['/v1/*'] }),
    /is not within the parent lease's paths/);
});

test('attenuate: a scoped parent cannot be widened to allow-all paths', () => {
  noCaps();
  addSecret('API4b', 'sk-secretvalue-scoped');
  const parent = grant('API4b', { ttlS: 3600, uses: 3, paths: ['/v1/chat/*'] });
  // pathsSubsumed rejects a child allow-all against a scoped parent
  assert.equal(pathsSubsumed(['/v1/chat/*'], null), false, 'child allow-all vs scoped parent → not subsumed');
  // and inheriting keeps the parent's scope (never widens to all)
  const child = grantFromLease(parent.id, {});
  assert.deepEqual(child.paths, ['/v1/chat/*'], 'unset paths inherits the parent scope, never allow-all');
});

test('globSubsumes: parent glob covers exactly the paths within it', () => {
  assert.equal(globSubsumes('/v1/*', '/v1/chat'), true);
  assert.equal(globSubsumes('/v1/*', '/v1/chat/completions'), false, '* does not cross /');
  assert.equal(globSubsumes('/v1/chat/*', '/v1/chat/completions'), true);
  assert.equal(globSubsumes('/v1/chat/*', '/v1/chat/*'), true, 'identical globs subsume');
  assert.equal(globSubsumes('/v1/chat/*', '/v1/models'), false);
  assert.equal(globSubsumes('/v1/*', '/v1/*'), true);
  assert.equal(globSubsumes('/v1/chat/completions', '/v1/chat/*'), false, 'a literal cannot cover a child *');
  assert.equal(globSubsumes('/a/*/c', '/a/b/c'), true);
  assert.equal(globSubsumes('/*', '/anything'), true);
  assert.equal(globSubsumes('/*', '/a/b'), false, 'single * is one segment');
});

test('attenuate: the child records the parent fingerprint AND the grant is audited with `from`', () => {
  noCaps();
  addSecret('API5', 'sk-secretvalue-stuvwx');
  const parent = grant('API5', { ttlS: 3600, uses: 3 });
  const child = grantFromLease(parent.id, { uses: 1 });
  assert.equal(child.parent, fp(parent.id), 'child.parent is the parent lease fingerprint');
  const grants = audit.read().filter((e) => e.event === 'grant' && e.lease === fp(child.id));
  assert.equal(grants.length, 1, 'the child grant is audited');
  assert.equal(grants[0].from, fp(parent.id), 'the child grant audit event carries the parent fingerprint');
  // the whole chain still verifies (delegation composes with the hash-chained audit)
  assert.equal(audit.verify().ok, true, 'audit chain intact after delegation');
});

test('attenuate: a rejected (widening) delegation is audited as a policy deny', () => {
  noCaps();
  addSecret('API6', 'sk-secretvalue-yz0123');
  const parent = grant('API6', { ttlS: 3600, uses: 2 });
  assert.throws(() => grantFromLease(parent.id, { uses: 50 }));
  const denies = audit.read().filter((e) => e.event === 'deny' && e.reason === 'policy' && e.lease === fp(parent.id));
  assert.ok(denies.length >= 1, 'the widening attempt is visible in the audit log');
});

test('attenuate: an unknown / exhausted parent cannot be delegated', () => {
  noCaps();
  addSecret('API7', 'sk-secretvalue-456789');
  assert.throws(() => attenuateLease('lease_deadbeef', {}), /names no known lease/);
  const parent = grant('API7', { ttlS: 3600, uses: 1 });
  redeem(parent.id); // exhaust it
  assert.throws(() => grantFromLease(parent.id, {}), /exhausted — cannot delegate/);
});

test('attenuate: the child redeems independently and does NOT consume a parent use', () => {
  noCaps();
  addSecret('API8', 'sk-secretvalue-independent');
  const parent = grant('API8', { ttlS: 3600, uses: 3 });
  const child = grantFromLease(parent.id, { uses: 1 });
  const r = redeem(child.id);
  assert.equal(r.ok, true);
  assert.equal(r.value, 'sk-secretvalue-independent', 'child redeems the inherited secret');
  // child now exhausted, parent untouched (delegation didn't spend a parent use)
  assert.equal(checkLease(child.id).ok, false, 'child single-use is now exhausted');
  assert.equal(checkLease(parent.id).ok, true, 'the parent still has all its uses');
});

test('CLI: `keeper grant --from-lease` mints a narrower child; a widening attempt exits non-zero', () => {
  const env = { ...process.env, KEEPER_HOME: process.env.KEEPER_HOME };
  delete env.KEEPER_MAX_TTL; delete env.KEEPER_MAX_USES;
  const run = (args) => spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8' });
  run(['add', 'CLISEC', '--value=sk-cli-secret-value-123']);
  const g = run(['grant', 'CLISEC', '--ttl', '3600', '--uses', '5', '--paths', '/v1/*', '--json']);
  assert.equal(g.status, 0);
  const parent = JSON.parse(g.stdout);
  // narrower child → succeeds, prints the child id + parent fingerprint
  const d = run(['grant', '--from-lease', parent.id, '--uses', '2', '--paths', '/v1/chat', '--json']);
  assert.equal(d.status, 0, d.stderr);
  const child = JSON.parse(d.stdout);
  assert.equal(child.usesLeft, 2);
  assert.deepEqual(child.paths, ['/v1/chat']);
  assert.equal(typeof child.parent, 'string');
  // widening the child (more uses than the parent) → non-zero, cap named on stderr
  const w = run(['grant', '--from-lease', parent.id, '--uses', '99']);
  assert.notEqual(w.status, 0);
  assert.match(w.stderr, /exceeds the parent lease's remaining/);
});
