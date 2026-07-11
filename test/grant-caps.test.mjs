// Grant floor + operator ceiling. keeper's thesis is SHORT-LIVED, USE-LIMITED
// leases — these tests prove the vault can enforce that: KEEPER_MAX_TTL /
// KEEPER_MAX_USES cap every mint (CLI and library share the chokepoint), an
// over-cap grant is rejected + audited (never silently clamped), and the floor
// rejects zero/negative/NaN grants (a NaN ttl or uses would otherwise mint an
// IMMORTAL lease — `now > NaN` and `NaN <= 0` are both false).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-caps-' + process.pid);
const { addSecret, grant, audit } = await import('../src/index.mjs');
const { checkLease } = await import('../src/lease.mjs');

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const noCaps = () => { delete process.env.KEEPER_MAX_TTL; delete process.env.KEEPER_MAX_USES; };

test('floor: zero, negative, and non-numeric --ttl/--uses are rejected', () => {
  noCaps();
  addSecret('CAPS', 'v');
  assert.throws(() => grant('CAPS', { ttlS: 0 }), /--ttl must be a positive number/);
  assert.throws(() => grant('CAPS', { ttlS: -5 }), /--ttl must be a positive number/);
  assert.throws(() => grant('CAPS', { uses: 0 }), /--uses must be a positive number/);
  assert.throws(() => grant('CAPS', { uses: -1 }), /--uses must be a positive number/);
  // NaN would mint a lease that never expires and never exhausts — reject it
  assert.throws(() => grant('CAPS', { ttlS: 'abc' }), /--ttl must be a positive number/);
  assert.throws(() => grant('CAPS', { uses: NaN }), /--uses must be a positive number/);
});

test('ceiling: a grant over KEEPER_MAX_TTL / KEEPER_MAX_USES is rejected, names the cap, and is audited', () => {
  process.env.KEEPER_MAX_TTL = '3600';
  process.env.KEEPER_MAX_USES = '50';
  try {
    assert.throws(() => grant('CAPS', { ttlS: 999999999 }), /--ttl 999999999 exceeds KEEPER_MAX_TTL=3600/);
    assert.throws(() => grant('CAPS', { uses: 1000000 }), /--uses 1000000 exceeds KEEPER_MAX_USES=50/);
    const denies = audit.read().filter((e) => e.event === 'deny' && e.reason === 'policy' && e.secret === 'CAPS');
    assert.ok(denies.length >= 2, 'over-cap grant attempts are visible in the audit log');
    assert.ok(denies.some((e) => /KEEPER_MAX_TTL/.test(e.detail)), 'the audited deny names the cap');
  } finally { noCaps(); }
});

test('ceiling: an at-cap grant is accepted; unset caps leave behavior unchanged', () => {
  process.env.KEEPER_MAX_TTL = '3600';
  process.env.KEEPER_MAX_USES = '50';
  try {
    const l = grant('CAPS', { ttlS: 3600, uses: 50 });
    assert.equal(checkLease(l.id).ok, true, 'exactly-at-cap mints a valid lease');
  } finally { noCaps(); }
  // no ceiling set → today's behavior exactly: a huge grant still mints
  const big = grant('CAPS', { ttlS: 999999999, uses: 1000000 });
  assert.equal(checkLease(big.id).ok, true, 'without caps, large grants are unrestricted (non-breaking)');
});

test('CLI: an over-cap `keeper grant` exits non-zero with the cap named on stderr', () => {
  const r = spawnSync(process.execPath, [CLI, 'grant', 'CAPS', '--ttl', '7200'], {
    env: { ...process.env, KEEPER_HOME: process.env.KEEPER_HOME, KEEPER_MAX_TTL: '3600' },
    encoding: 'utf8',
  });
  assert.notEqual(r.status, 0, 'over-cap grant fails the command');
  assert.match(r.stderr, /--ttl 7200 exceeds KEEPER_MAX_TTL=3600/, 'error names the cap and the value');
  assert.equal(r.stdout.trim(), '', 'no lease id is printed');
});

test('CLI: --ttl 0 is rejected with a clear message', () => {
  const r = spawnSync(process.execPath, [CLI, 'grant', 'CAPS', '--ttl', '0'], {
    env: { ...process.env, KEEPER_HOME: process.env.KEEPER_HOME },
    encoding: 'utf8',
  });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /--ttl must be a positive number/);
});
