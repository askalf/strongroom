// Tamper-evident audit of every secret access — reuses warden's hash-chained
// audit (the shared security-stack primitive). Each grant / redeem / deny /
// revoke is chained, so a deleted or edited entry breaks verification.
//
// The keyless hash chain catches MID-chain edits, but on its own it does NOT
// catch (a) tail truncation — a valid prefix still verifies — or (b) a splice
// that demotes real entries to hashless "legacy" lines and re-roots a forged
// suffix at the PUBLIC genesis. We close both with an AUTHENTICATED TIP: a small
// sidecar that commits to the chain's length AND last hash under an HMAC keyed by
// a subkey of the vault master key (held in the OS keychain / off-disk, NEVER in
// audit.jsonl). An attacker who can rewrite the audit file cannot forge the tip
// without the master key, so truncating or splicing the log is now detectable.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { ChainedFileAudit, verifyAuditFile } from '@askalf/warden/audit';
import * as vault from './vault.mjs';
import { home, kpath } from './paths.mjs';

const TIP_LABEL = 'keeper-audit-tip-v1';
const tipPath = () => kpath('audit.tip.json');
// Durable marker: set once a tip is first written, so verify() can tell a vault
// whose tip protection was STRIPPED (key + tip deleted — the key-file-fallback
// downgrade) apart from one that was never protected (no keychain / passphrase).
const protectedMarker = () => kpath('audit.protected');

// HMAC subkey derived from the vault master key (or null on a fresh / keychain-
// unavailable vault — in which case we skip the tip entirely and never crash).
const auditKey = () => vault.deriveSubkey(TIP_LABEL);
const tipMac = (key, n, hash) => crypto.createHmac('sha256', key).update(n + ':' + hash).digest('hex');

// Total non-empty lines + the last line's chained hash — the two facts the tip
// commits to. Computed identically on write and on verify so they compare clean.
function tailOf(p) {
  let data;
  try { data = fs.readFileSync(p, 'utf8'); } catch { return { n: 0, hash: '' }; }
  const lines = data.split('\n').filter((l) => l.trim());
  let hash = '';
  for (let i = lines.length - 1; i >= 0; i--) {
    try { const o = JSON.parse(lines[i]); if (o && typeof o.hash === 'string') { hash = o.hash; break; } } catch {}
  }
  return { n: lines.length, hash };
}

function writeTip(p, key) {
  const { n, hash } = tailOf(p);
  if (!n) return; // nothing chained yet → nothing to commit
  const tip = { n, hash, mac: tipMac(key, n, hash) };
  const dst = tipPath();
  try {
    const tmp = dst + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(tip), { mode: 0o600 });
    fs.renameSync(tmp, dst); // atomic replace
  } catch {
    try { fs.writeFileSync(dst, JSON.stringify(tip), { mode: 0o600 }); } catch {} // best effort
  }
  try { if (!fs.existsSync(protectedMarker())) fs.writeFileSync(protectedMarker(), JSON.stringify({ since: new Date().toISOString() }), { mode: 0o600 }); } catch {}
}

function readTip() {
  try { return JSON.parse(fs.readFileSync(tipPath(), 'utf8')); } catch { return null; }
}

// Stateless per call (a CLI invocation = one event): each record re-seeds from
// the file's last hash, so the chain is correct regardless of process lifetime.
// After chaining, refresh the authenticated tip (when a master key exists).
export function record(event) {
  fs.mkdirSync(home(), { recursive: true });
  const p = kpath('audit.jsonl');
  const entry = new ChainedFileAudit(p).record({ ts: new Date().toISOString(), ...event });
  const key = auditKey();
  if (key) writeTip(p, key);
  return entry;
}

export function verify() {
  const p = kpath('audit.jsonl');
  const base = verifyAuditFile(p); // chain integrity as before: { ok, entries } | { ok:false, at }
  if (!base.ok) return base;

  // Authenticated-tip check — only meaningful once a master key exists. Without
  // one we fall back to the keyless chain result (and DON'T fail closed, so a
  // fresh / passphraseless vault still verifies its chain).
  const key = auditKey();
  if (!key) {
    // No master key to authenticate the tip. A vault that was NEVER tip-protected
    // (no keychain / passphrase ever) has no tip to check — its keyless chain
    // result stands. But if it WAS protected and the key is now unavailable, the
    // tip can't be authenticated: refuse to attest "intact" rather than silently
    // downgrading to the forgeable keyless chain (the key-file-fallback downgrade).
    if (!fs.existsSync(protectedMarker())) return base;
    const tip0 = readTip();
    const { n: tn, hash: th } = tailOf(p);
    const mismatch = tip0 && (tn !== tip0.n || th !== tip0.hash);
    return { ...base, ok: false, reason: mismatch ? 'audit-truncated-or-spliced' : 'audit-key-unavailable' };
  }

  const { n, hash } = tailOf(p);
  const tip = readTip();
  if (!tip) {
    if (n > 0) return { ...base, ok: false, reason: 'audit-tip-missing' }; // tip deletion is tampering
    return base; // empty audit, no tip → nothing to protect
  }
  // The tip must be authentic (HMAC over n:hash) AND match the current tail.
  const expected = tipMac(key, tip.n, tip.hash);
  const got = String(tip.mac || '');
  if (got.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected))) {
    return { ...base, ok: false, reason: 'audit-tip-forged' };
  }
  if (n !== tip.n || hash !== tip.hash) return { ...base, ok: false, reason: 'audit-truncated-or-spliced' };
  return base;
}

export function read() {
  try {
    return fs.readFileSync(kpath('audit.jsonl'), 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch { return []; }
}
