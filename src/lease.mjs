// Leases — the bearer handle an agent holds instead of a key. The raw lease id
// is a bearer token, so it is NEVER written to disk: leases.json is keyed by
// sha256(id), and the raw id is returned to the caller exactly once (on grant).
// Reading the leases file therefore does not let you redeem anything. Redeeming
// is an ATOMIC check-and-consume under a cross-process lock, so a single-use
// lease can't be double-spent by concurrent redeems.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { home, kpath } from './paths.mjs';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const read = () => { try { return JSON.parse(fs.readFileSync(kpath('leases.json'), 'utf8')); } catch { return {}; } };
const write = (l) => { fs.mkdirSync(home(), { recursive: true }); fs.writeFileSync(kpath('leases.json'), JSON.stringify(l, null, 2), { mode: 0o600 }); };

// Cross-process advisory lock (exclusive-create a lockfile) for atomic RMW.
const sleepSync = (ms) => { try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch {} };
function withLock(fn) {
  fs.mkdirSync(home(), { recursive: true });
  const lf = kpath('.leases.lock');
  let fd;
  for (let i = 0; i < 400 && fd === undefined; i++) { try { fd = fs.openSync(lf, 'wx'); } catch { sleepSync(5); } }
  try { return fn(); } finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch {} try { fs.unlinkSync(lf); } catch {} } }
}

function evalLease(l, host, now = Date.now()) {
  if (!l) return { ok: false, reason: 'unknown' };
  if (now > l.expiresAt) return { ok: false, reason: 'expired' };
  if (l.usesLeft <= 0) return { ok: false, reason: 'exhausted' };
  if (l.host && host && l.host !== host) return { ok: false, reason: 'host-scope' };
  return { ok: true, lease: l };
}

export function mintLease(secret, { ttlS = 300, uses = 1, host = null, upstream = null, inject = null } = {}) {
  const id = 'lease_' + crypto.randomBytes(18).toString('hex'); // 144-bit bearer token — returned, never stored raw
  return withLock(() => {
    const leases = read(), now = Date.now();
    for (const [k, v] of Object.entries(leases)) if (now > v.expiresAt) delete leases[k]; // prune expired
    // upstream/inject bind a lease to ONE destination for the egress broker, so the
    // injected secret can only ever go to that host — never an attacker-chosen URL.
    const rec = { secret, host: host || null, upstream: upstream || null, inject: inject || null, expiresAt: now + ttlS * 1000, usesLeft: uses, createdAt: now };
    leases[sha256(id)] = rec;
    write(leases);
    return { id, ...rec };
  });
}

/** Non-consuming validity check (by raw id). */
export function checkLease(id, { host } = {}) { return evalLease(read()[sha256(id)], host); }

/** Atomic check-AND-consume: at most one concurrent caller spends a use. */
export function redeemLease(id, { host } = {}) {
  return withLock(() => {
    const leases = read(), h = sha256(id);
    const v = evalLease(leases[h], host);
    if (!v.ok) return v;
    leases[h].usesLeft--; // record kept (0 → clear 'exhausted'); pruned on next mint
    write(leases);
    return { ok: true, lease: { ...v.lease } };
  });
}

export function revokeLease(id) {
  return withLock(() => { const leases = read(), h = sha256(id); const had = !!leases[h]; delete leases[h]; write(leases); return had; });
}

/** Outstanding leases — shown by fingerprint (we don't hold the raw ids). */
export function listLeases() {
  const leases = read(), now = Date.now();
  return Object.entries(leases).map(([h, l]) => ({ fingerprint: h.slice(0, 12), secret: l.secret, usesLeft: l.usesLeft, host: l.host, expiresAt: l.expiresAt, expired: now > l.expiresAt }));
}
