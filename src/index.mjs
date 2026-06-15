// keeper — own your agent secrets. An encrypted vault that hands agents scoped,
// short-lived, single-use LEASES instead of raw keys, redeems them only at the
// egress point, and audits every access (tamper-evidently). Completes the
// agent-security stack: warden contains the call, canon vets the tool, keeper
// holds the keys.
import * as vault from './vault.mjs';
import * as lease from './lease.mjs';
import * as audit from './audit.mjs';

export { vault, lease, audit };

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
  if (!vault.hasSecret(name)) throw new Error(`no such secret: ${name}`);
  const l = lease.mintLease(name, opts);
  audit.record({ event: 'grant', secret: name, lease: l.id, host: l.host, ttlS: opts.ttlS ?? 300, uses: opts.uses ?? 1 });
  return l;
}

/** Redeem a lease at the egress point → the secret, IF the lease is still valid
 *  (not expired, uses remaining, host in scope). A denial is audited and never
 *  consumes a use. */
export function redeem(leaseId, { host } = {}) {
  const c = lease.checkLease(leaseId, { host });
  if (!c.ok) { audit.record({ event: 'deny', lease: leaseId, reason: c.reason, host: host || null }); return { ok: false, reason: c.reason }; }
  const value = vault.getSecret(c.lease.secret);
  lease.consumeLease(leaseId);
  audit.record({ event: 'redeem', lease: leaseId, secret: c.lease.secret, host: host || null });
  return { ok: true, value, name: c.lease.secret };
}

export function revoke(leaseId) {
  const had = lease.revokeLease(leaseId);
  audit.record({ event: 'revoke', lease: leaseId });
  return had;
}
