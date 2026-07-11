// keeper — own your agent secrets. An encrypted vault that hands agents scoped,
// short-lived, single-use LEASES instead of raw keys, redeems them only at the
// egress point, and audits every access (tamper-evidently). Completes the
// agent-security stack: warden contains the call, canon vets the tool, keeper
// holds the keys.
import crypto from 'node:crypto';
import * as vault from './vault.mjs';
import * as lease from './lease.mjs';
import * as audit from './audit.mjs';

export { vault, lease, audit };

// Log a lease by fingerprint, never its raw id — the audit is on disk too.
const fp = (id) => crypto.createHash('sha256').update(typeof id === 'string' ? id : String(id ?? '')).digest('hex').slice(0, 12);

/** Store a secret (encrypted at rest). */
export function addSecret(name, value) {
  vault.putSecret(name, value);
  audit.record({ event: 'add', secret: name });
}

export function removeSecret(name) {
  const had = vault.removeSecret(name);
  audit.record({ event: 'remove', secret: name });
  return had;
}

/** Mint a lease for a secret. The agent gets THIS (the id), never the secret. */
export function grant(name, opts = {}) {
  opts = opts || {};
  if (!vault.hasSecret(name)) throw new Error(`no such secret: ${name}`);
  let l;
  try { l = lease.mintLease(name, opts); }
  catch (e) {
    // An over-cap or invalid grant attempt is a policy event worth seeing in
    // the tamper-evident log (the message names the cap, never a secret value).
    audit.record({ event: 'deny', secret: name, reason: 'policy', detail: e.message });
    throw e;
  }
  audit.record({ event: 'grant', secret: name, lease: fp(l.id), host: l.host, upstream: l.upstream, rate: l.rate, paths: l.paths, concurrency: l.concurrency, ttlS: opts.ttlS ?? 300, uses: opts.uses ?? 1 });
  return l;
}

/** Redeem a lease at the egress point → the secret, IF the lease is still valid.
 *  The check-and-consume is atomic (one winner per use); a denial or a broken
 *  decrypt is audited and the call fails CLOSED (never throws, never leaks). */
export function redeem(leaseId, { host } = {}) {
  // Decrypt happens INSIDE the atomic consume (the materialize callback), so a
  // decrypt-failure denies WITHOUT burning a use.
  const c = lease.redeemLease(leaseId, { host }, (l) => vault.getSecret(l.secret));
  if (!c.ok) { audit.record({ event: 'deny', lease: fp(leaseId), reason: c.reason, host: host || null }); return { ok: false, reason: c.reason }; }
  audit.record({ event: 'redeem', lease: fp(leaseId), secret: c.lease.secret, host: host || null });
  return { ok: true, value: c.value, name: c.lease.secret, upstream: c.lease.upstream, inject: c.lease.inject };
}

export function revoke(leaseId) {
  const had = lease.revokeLease(leaseId);
  audit.record({ event: 'revoke', lease: fp(leaseId) });
  return had;
}

/** Rotate the master key (see vault.rekeyVault). Audited AFTER the swap, which
 *  also re-MACs the audit's authenticated tip under the NEW key — the tip is
 *  keyed off the master key, so a rotation that skipped this would leave
 *  `keeper audit --verify` unable to authenticate its own log. */
export function rekeyMasterKey(opts = {}) {
  const r = vault.rekeyVault(opts || {});
  audit.record({ event: 'rekey', secrets: r.secrets, from: r.from, to: r.to });
  return r;
}
