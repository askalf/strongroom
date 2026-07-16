// Leases — the bearer handle an agent holds instead of a key. The raw lease id
// is a bearer token, so it is NEVER written to disk: leases.json is keyed by
// sha256(id), and the raw id is returned to the caller exactly once (on grant).
// Reading the leases file therefore does not let you redeem anything. Redeeming
// is an ATOMIC check-and-consume under a cross-process lock, so a single-use
// lease can't be double-spent by concurrent redeems.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { home, kpath } from './paths.mjs';

// Coerce so a non-string lease id (a malformed/hostile id arriving at the broker
// from the URL) hashes to a value that simply won't match — redeem/revoke fail
// CLOSED ('unknown' / false) instead of throwing at the egress point.
const sha256 = (s) => crypto.createHash('sha256').update(typeof s === 'string' ? s : String(s ?? '')).digest('hex');
const read = () => { try { return JSON.parse(fs.readFileSync(kpath('leases.json'), 'utf8')); } catch { return {}; } };
const write = (l) => { fs.mkdirSync(home(), { recursive: true }); fs.writeFileSync(kpath('leases.json'), JSON.stringify(l, null, 2), { mode: 0o600 }); };

// Cross-process advisory lock (exclusive-create a lockfile) for atomic RMW.
const sleepSync = (ms) => { try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch {} };
const LOCK_STALE_MS = 10000; // a lockfile older than this was orphaned by a crashed holder
// Exported for the vault's rekey: rotating the master key must not interleave
// with a redeem's decrypt (which runs inside this same lock via redeemLease).
export function withLock(fn) {
  fs.mkdirSync(home(), { recursive: true });
  const lf = kpath('.leases.lock');
  let fd;
  for (let i = 0; i < 400 && fd === undefined; i++) {
    try { fd = fs.openSync(lf, 'wx'); }
    catch {
      // A holder killed mid-section leaves the lockfile forever. If it's stale,
      // reclaim it so the atomic section can't be permanently disabled; else wait.
      try { if (Date.now() - fs.statSync(lf).mtimeMs > LOCK_STALE_MS) fs.unlinkSync(lf); } catch {}
      sleepSync(5);
    }
  }
  // NEVER run the critical section without the lock — doing so reopens the
  // single-use double-spend window the lock exists to close. Fail CLOSED: the
  // egress callers (redeemLease/revokeLease) catch this and deny.
  if (fd === undefined) throw new Error('keeper: lease lock unavailable');
  try { return fn(); } finally { try { fs.closeSync(fd); } catch {} try { fs.unlinkSync(lf); } catch {} }
}

function evalLease(l, host, now = Date.now()) {
  if (!l) return { ok: false, reason: 'unknown' };
  if (now > l.expiresAt) return { ok: false, reason: 'expired' };
  if (l.usesLeft <= 0) return { ok: false, reason: 'exhausted' };
  // A host-scoped lease DENIES unless the destination host matches exactly —
  // including when the host is MISSING. (Previously `&& host` short-circuited, so
  // a host-scoped lease redeemed with no host returned the secret for any host.)
  if (l.host && l.host !== host) return { ok: false, reason: 'host-scope' };
  return { ok: true, lease: l };
}

/** Read a lease's binding (upstream/paths/rate/host) WITHOUT host-scope enforcement
 *  or consuming a use — the broker needs the binding to learn the destination host
 *  before it can pass it to the enforced redeem. Still checks expiry/uses. */
export function peekLease(id) {
  const l = read()[sha256(id)];
  if (!l) return { ok: false, reason: 'unknown' };
  const now = Date.now();
  if (now > l.expiresAt) return { ok: false, reason: 'expired' };
  if (l.usesLeft <= 0) return { ok: false, reason: 'exhausted' };
  return { ok: true, lease: l };
}

// Operator ceiling: a positive number in KEEPER_MAX_TTL / KEEPER_MAX_USES caps
// every lease minted from this vault; unset/invalid → no ceiling (opt-in).
const cap = (name) => { const v = Number(process.env[name]); return Number.isFinite(v) && v > 0 ? v : null; };

export function mintLease(secret, opts = {}) {
  const { host = null, upstream = null, inject = null, rate = null, paths = null, concurrency = null } = opts || {};
  // Coerce once so the floor/ceiling checks see real numbers (the CLI already
  // passes Number(...); a library caller may hand us strings).
  const ttlS = Number(opts?.ttlS ?? 300), uses = Number(opts?.uses ?? 1);
  // Floor: a zero/negative lease is dead on arrival — and a NaN one is IMMORTAL
  // (`now > NaN` and `NaN <= 0` are both false, so it would never expire and
  // never exhaust). Reject instead of minting.
  if (!Number.isFinite(ttlS) || ttlS <= 0) throw new Error(`keeper: --ttl must be a positive number of seconds (got ${opts?.ttlS})`);
  if (!Number.isFinite(uses) || uses <= 0) throw new Error(`keeper: --uses must be a positive number (got ${opts?.uses})`);
  // Ceiling: enforced here — the one chokepoint every mint path shares (CLI,
  // library grant(), future callers) — so "leases from this vault stay small"
  // is vault policy, not caller discipline. Over-cap REJECTS (explicit and
  // auditable) rather than silently clamping to the cap.
  const maxTtl = cap('KEEPER_MAX_TTL'), maxUses = cap('KEEPER_MAX_USES');
  if (maxTtl && ttlS > maxTtl) throw new Error(`keeper: --ttl ${ttlS} exceeds KEEPER_MAX_TTL=${maxTtl}`);
  if (maxUses && uses > maxUses) throw new Error(`keeper: --uses ${uses} exceeds KEEPER_MAX_USES=${maxUses}`);
  const id = 'lease_' + crypto.randomBytes(18).toString('hex'); // 144-bit bearer token — returned, never stored raw
  return withLock(() => {
    const leases = read(), now = Date.now();
    for (const [k, v] of Object.entries(leases)) if (now > v.expiresAt) delete leases[k]; // prune expired
    // upstream/inject bind a lease to ONE destination for the egress broker (the secret
    // can only go to that host); rate caps req/min; paths scopes which endpoints it may hit.
    const rec = {
      secret, host: host || null, upstream: upstream || null, inject: inject || null,
      rate: rate || null, paths: (paths && paths.length) ? paths : null, concurrency: concurrency || null,
      expiresAt: now + ttlS * 1000, usesLeft: uses, createdAt: now,
    };
    leases[sha256(id)] = rec;
    write(leases);
    return { id, ...rec };
  });
}

// --- Lease delegation (attenuation) ------------------------------------------
// A parent agent turns its OWN lease into a NARROWER sub-lease for a sub-agent:
// shorter TTL, fewer uses, tighter host/upstream/paths/rate/concurrency — NEVER
// wider. This is capability attenuation (macaroon-style): the child is an
// independent lease whose every scope is <= the parent's AT MINT TIME, so a
// sub-agent can never do more than its parent could. The child does NOT consume
// a parent use — the guarantee is per-capability (child scope ⊆ parent scope,
// enforced here) — and the child record carries the PARENT's fingerprint, which
// index.grantFromLease also stamps into the grant audit event so the delegation
// composes with the hash-chained audit into a full parent→child trail.

// Does parent glob `p` allow EVERY path the child glob `c` can reach? `*` matches
// a run of non-`/`, non-`?` chars (one path segment), exactly as the broker's
// pathAllowed matches. A DP over the two PATTERNS (not a string): a child `*`
// REQUIRES an aligned parent `*` (a parent literal can't cover the arbitrary
// output of a child `*`), while a parent `*` can absorb child literals/`*` within
// one segment. `/` must align with `/` (neither side's `*` crosses it).
export function globSubsumes(p, c) {
  const memo = new Map();
  const allStars = (s, i) => { for (let k = i; k < s.length; k++) if (s[k] !== '*') return false; return true; };
  const go = (i, j) => {
    const key = i + ',' + j;
    if (memo.has(key)) return memo.get(key);
    let res;
    if (i >= p.length) {
      // parent exhausted → matches ONLY the empty string; the child can only be
      // subsumed if it too produces nothing more.
      res = j >= c.length;
    } else if (j >= c.length) {
      // child produced its whole string; parent must still be able to match ''
      // → every remaining parent token is `*` (each can match empty).
      res = allStars(p, i);
    } else if (p[i] === '*') {
      const cc = c[j];
      // parent `*` matches empty (advance parent), OR absorbs one child token IF
      // that token stays within a segment: a child literal in [^/?], or a child
      // `*` (whose output is also within a segment). It can NOT absorb `/` or a
      // literal `?` (both are outside `*`'s class).
      const absorbable = cc !== '/' && cc !== '?';
      res = go(i + 1, j) || (absorbable ? go(i, j + 1) : false);
    } else if (p[i] === '/') {
      res = c[j] === '/' && go(i + 1, j + 1);
    } else {
      // parent literal (incl. a literal `?`): a child `*` can emit something else
      // → not covered; a child `/` is never this literal; a child literal must
      // match exactly.
      res = c[j] !== '*' && c[j] !== '/' && p[i] === c[j] && go(i + 1, j + 1);
    }
    memo.set(key, res);
    return res;
  };
  return go(0, 0);
}

/** Is the child path-allowlist within the parent's? Sound (conservative): each
 *  child glob must be subsumed by SOME single parent glob — this won't recognize
 *  a child covered only by the UNION of two parent globs, but it NEVER accepts a
 *  child that can escape the parent (no widening slips through). */
export function pathsSubsumed(parentPaths, childPaths) {
  if (!parentPaths || !parentPaths.length) return true;      // parent allows all → any allowlist is narrower
  if (!childPaths || !childPaths.length) return false;       // parent scoped, child = allow-all → WIDER
  return childPaths.every((c) => parentPaths.some((p) => globSubsumes(p, c)));
}

// A destination binding (host/upstream/inject): a sub-lease may TIGHTEN an unset
// field, INHERIT a set one, but never REDIRECT it (pointing the secret somewhere
// the parent couldn't is widening).
function narrowBinding(name, parentVal, childVal) {
  const cv = (childVal === undefined || childVal === null || childVal === '') ? null : childVal;
  if (!parentVal) return cv;         // parent unbound → child may bind (narrow) or stay unbound
  if (cv === null) return parentVal; // child unspecified → inherit
  if (cv !== parentVal) throw new Error(`keeper: --${name} '${cv}' differs from the parent lease's '${parentVal}' — a sub-lease may only inherit or, if unset, tighten ${name}`);
  return parentVal;
}

// A numeric ceiling (rate/concurrency): a LOWER cap is narrower; null/unset =
// UNLIMITED = wider. So if the parent set one the child inherits it unless it
// sets a smaller one; if the parent is unlimited the child may add a cap.
function narrowCeil(name, parentVal, childVal) {
  const cv = Number(childVal);
  const provided = childVal !== undefined && childVal !== null && Number.isFinite(cv) && cv > 0;
  if (!parentVal) return provided ? cv : null;
  if (!provided) return parentVal;
  if (cv > parentVal) throw new Error(`keeper: --${name} ${cv} exceeds the parent lease's ${parentVal} — a sub-lease may only lower it`);
  return cv;
}

/** Attenuate a parent lease into a narrower child lease for a sub-agent. Reads
 *  the parent, validates every requested scope is <= the parent's (else throws,
 *  naming the field), and mints an independent child bounded by those limits —
 *  all under the same lock so the parent can't expire/exhaust mid-attenuation.
 *  Returns the child record (with `id`, once) plus `parent` = the parent's
 *  fingerprint. Does NOT consume a parent use. */
export function attenuateLease(parentId, opts = {}) {
  opts = opts || {};
  return withLock(() => {
    const leases = read(), now = Date.now();
    const parent = leases[sha256(parentId)];
    // You can only delegate a lease you hold that is still spendable.
    if (!parent) throw new Error('keeper: --from-lease names no known lease (raw ids are never stored; expired leases are pruned)');
    if (now > parent.expiresAt) throw new Error('keeper: --from-lease is expired — cannot delegate');
    if (parent.usesLeft <= 0) throw new Error('keeper: --from-lease is exhausted — cannot delegate');

    // TTL — a sub-lease may not outlive its parent. Default: the parent's
    // REMAINING ttl.
    const remainingMs = parent.expiresAt - now;
    let ttlMs;
    if (opts.ttlS === undefined || opts.ttlS === null) ttlMs = remainingMs;
    else {
      const ttlS = Number(opts.ttlS);
      if (!Number.isFinite(ttlS) || ttlS <= 0) throw new Error(`keeper: --ttl must be a positive number of seconds (got ${opts.ttlS})`);
      ttlMs = ttlS * 1000;
      if (ttlMs > remainingMs) throw new Error(`keeper: --ttl ${ttlS}s exceeds the parent lease's remaining ${Math.floor(remainingMs / 1000)}s — a sub-lease may not outlive its parent`);
    }

    // Uses — a sub-lease may not exceed the parent's remaining uses. Default:
    // all of them (a straight, TTL-bounded copy).
    let uses;
    if (opts.uses === undefined || opts.uses === null) uses = parent.usesLeft;
    else {
      uses = Number(opts.uses);
      if (!Number.isFinite(uses) || uses <= 0) throw new Error(`keeper: --uses must be a positive number (got ${opts.uses})`);
      if (uses > parent.usesLeft) throw new Error(`keeper: --uses ${uses} exceeds the parent lease's remaining ${parent.usesLeft} use(s)`);
    }

    // Operator ceiling still applies as an extra upper bound (defense in depth;
    // the parent bound is usually stricter, but a mid-life parent could exceed a
    // later-lowered cap).
    const maxTtl = cap('KEEPER_MAX_TTL'), maxUses = cap('KEEPER_MAX_USES');
    if (maxTtl && ttlMs / 1000 > maxTtl) throw new Error(`keeper: --ttl ${Math.floor(ttlMs / 1000)} exceeds KEEPER_MAX_TTL=${maxTtl}`);
    if (maxUses && uses > maxUses) throw new Error(`keeper: --uses ${uses} exceeds KEEPER_MAX_USES=${maxUses}`);

    // Destination — tighten-or-inherit, never redirect.
    const host = narrowBinding('host', parent.host, opts.host);
    const upstream = narrowBinding('upstream', parent.upstream, opts.upstream);
    const inject = narrowBinding('inject', parent.inject, opts.inject);
    // Rate / concurrency ceilings — lower or inherit.
    const rate = narrowCeil('rate', parent.rate, opts.rate);
    const concurrency = narrowCeil('concurrency', parent.concurrency, opts.concurrency);

    // Paths — child allowlist must be a subset of the parent's.
    let paths;
    const childPaths = (opts.paths && opts.paths.length) ? opts.paths : null;
    if (childPaths === null) paths = parent.paths || null; // inherit; can't widen to allow-all
    else {
      if (!pathsSubsumed(parent.paths, childPaths)) throw new Error(`keeper: --paths ${childPaths.join(',')} is not within the parent lease's paths ${(parent.paths || ['*']).join(',')} — a sub-lease may only narrow`);
      paths = childPaths;
    }

    const id = 'lease_' + crypto.randomBytes(18).toString('hex');
    for (const [k, v] of Object.entries(leases)) if (now > v.expiresAt) delete leases[k]; // prune expired
    const rec = {
      secret: parent.secret, host, upstream, inject,
      rate, paths, concurrency,
      expiresAt: now + ttlMs, usesLeft: uses, createdAt: now,
      parent: sha256(parentId).slice(0, 12), // parent lease fingerprint — the delegation trail
    };
    leases[sha256(id)] = rec;
    write(leases);
    return { id, ...rec };
  });
}

/** Non-consuming validity check (by raw id). */
export function checkLease(id, { host } = {}) { return evalLease(read()[sha256(id)], host); }

/** Atomic check-AND-consume: at most one concurrent caller spends a use.
 *  `materialize(lease)` (optional) fetches the secret WHILE the lock is held —
 *  if it returns null (decrypt-failed / no key), the use is NOT consumed, so a
 *  broken decrypt never burns a use. Keeps check + fetch + consume atomic. */
export function redeemLease(id, { host } = {}, materialize = null) {
  try {
    return withLock(() => {
      const leases = read(), h = sha256(id);
      const v = evalLease(leases[h], host);
      if (!v.ok) return v;
      let value;
      if (materialize) {
        value = materialize(v.lease);
        if (value == null) return { ok: false, reason: 'decrypt-failed' }; // do NOT consume
      }
      leases[h].usesLeft--; // commit the consume only after success; record kept (0 → 'exhausted'), pruned on next mint
      write(leases);
      return { ok: true, lease: { ...v.lease }, value };
    });
  } catch { return { ok: false, reason: 'locked' }; } // lock unavailable → fail CLOSED, never run unlocked
}

export function revokeLease(id) {
  // Called from cleanup `finally` blocks — must not throw if the lock is stuck.
  try {
    return withLock(() => { const leases = read(), h = sha256(id); const had = !!leases[h]; delete leases[h]; write(leases); return had; });
  } catch { return false; }
}

/** Outstanding leases — shown by fingerprint (we don't hold the raw ids). */
export function listLeases() {
  const leases = read(), now = Date.now();
  return Object.entries(leases).map(([h, l]) => ({ fingerprint: h.slice(0, 12), secret: l.secret, usesLeft: l.usesLeft, host: l.host, expiresAt: l.expiresAt, expired: now > l.expiresAt, parent: l.parent || null }));
}
