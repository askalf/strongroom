// Leases — the thing an agent actually holds. A lease is a random, opaque handle
// to a secret, bound to a TTL, a use count, and (optionally) a destination host.
// The raw secret never leaves the vault until a lease is redeemed at the egress
// point, and only while the lease is still valid. The agent's context only ever
// contains the lease id.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { home, kpath } from './paths.mjs';

const read = () => { try { return JSON.parse(fs.readFileSync(kpath('leases.json'), 'utf8')); } catch { return {}; } };
const write = (l) => { fs.mkdirSync(home(), { recursive: true }); fs.writeFileSync(kpath('leases.json'), JSON.stringify(l, null, 2), { mode: 0o600 }); };

export function mintLease(secret, { ttlS = 300, uses = 1, host = null } = {}) {
  const id = 'lease_' + crypto.randomBytes(12).toString('hex');
  const leases = read();
  const now = Date.now();
  for (const [k, v] of Object.entries(leases)) if (now > v.expiresAt) delete leases[k]; // prune expired
  leases[id] = { secret, host: host || null, expiresAt: now + ttlS * 1000, usesLeft: uses, createdAt: now };
  write(leases);
  return { id, ...leases[id] };
}

/** Validate a lease WITHOUT consuming it. → { ok } or { ok:false, reason }. */
export function checkLease(id, { host } = {}) {
  const l = read()[id];
  if (!l) return { ok: false, reason: 'unknown' };
  if (Date.now() > l.expiresAt) return { ok: false, reason: 'expired' };
  if (l.usesLeft <= 0) return { ok: false, reason: 'exhausted' };
  if (l.host && host && l.host !== host) return { ok: false, reason: 'host-scope' };
  return { ok: true, lease: l };
}

/** Spend one use. The record is kept (usesLeft can reach 0 → a clear 'exhausted'
 *  denial + audit trail); expired/spent leases are pruned on the next mint. */
export function consumeLease(id) {
  const leases = read();
  if (!leases[id]) return;
  leases[id].usesLeft--;
  write(leases);
}

export function revokeLease(id) { const leases = read(); const had = !!leases[id]; delete leases[id]; write(leases); return had; }

export function listLeases() {
  const leases = read(), now = Date.now();
  return Object.entries(leases).map(([id, l]) => ({ id, ...l, expired: now > l.expiresAt }));
}
