// Encrypted secret store. Secrets are AES-256-GCM encrypted at rest, with the
// secret NAME bound in as additional authenticated data (AAD) so a ciphertext
// can't be swapped between names. The master key is either derived from a
// passphrase (scrypt — never on disk, recommended) or a random key file in
// ~/.keeper (0600 + a restrictive ACL on Windows). Decryption failures fail
// CLOSED — a tampered/corrupt vault returns null, never a throw or garbage.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { home, kpath } from './paths.mjs';
import { keychainGet, keychainSet, keychainDelete, keychainAvailable } from './keychain.mjs';
import { withLock } from './lease.mjs';

// 0600 is a no-op on Windows (ACL-based) — strip inheritance + grant only the user.
function lockdown(file) {
  if (process.platform !== 'win32' || !process.env.USERNAME) return;
  try { execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:F`], { stdio: 'ignore' }); } catch {}
}

// Which key store the current environment selects (the same precedence masterKey uses).
const backend = () =>
  process.env.KEEPER_PASSPHRASE ? 'passphrase'
    : (process.env.KEEPER_KEYCHAIN === '1' || process.env.KEEPER_KEYCHAIN === 'true') ? 'keychain'
      : 'file';

const scrypt = (pass, salt) => crypto.scryptSync(pass, salt, 32, { N: 16384, r: 8, p: 1 });

const _keyCache = new Map();
function masterKey() {
  const ck = [process.env.KEEPER_HOME || '', process.env.KEEPER_PASSPHRASE || '', process.env.KEEPER_KEYCHAIN || ''].join('|');
  if (_keyCache.has(ck)) return _keyCache.get(ck);
  let key;
  const pass = process.env.KEEPER_PASSPHRASE;
  const useKeychain = process.env.KEEPER_KEYCHAIN === '1' || process.env.KEEPER_KEYCHAIN === 'true';
  if (pass) {
    // passphrase mode: the key is derived, never stored — only a salt is.
    const sf = kpath('salt');
    let salt;
    try { salt = Buffer.from(fs.readFileSync(sf, 'utf8').trim(), 'hex'); }
    catch { salt = crypto.randomBytes(16); fs.mkdirSync(home(), { recursive: true }); fs.writeFileSync(sf, salt.toString('hex'), { mode: 0o600 }); lockdown(sf); }
    key = scrypt(pass, salt);
  } else if (useKeychain) {
    // OS keychain — the key is held by the OS (Keychain / Secret Service / DPAPI),
    // never plaintext on disk. Fail CLOSED if requested but unavailable: never
    // silently downgrade a secrets vault to a weaker key store.
    if (!keychainAvailable()) throw new Error('KEEPER_KEYCHAIN set but no OS keychain available (security / secret-tool / DPAPI)');
    let hex = keychainGet();
    if (!hex) { hex = crypto.randomBytes(32).toString('hex'); keychainSet(hex); }
    key = Buffer.from(hex, 'hex');
  } else {
    // key-file fallback: convenient, but the key sits on disk.
    const kf = kpath('master.key');
    try { key = Buffer.from(fs.readFileSync(kf, 'utf8').trim(), 'hex'); }
    catch { key = crypto.randomBytes(32); fs.mkdirSync(home(), { recursive: true }); fs.writeFileSync(kf, key.toString('hex'), { mode: 0o600 }); lockdown(kf); }
  }
  _keyCache.set(ck, key);
  return key;
}

// Does a master key ALREADY exist, without creating one? Used so a feature
// (e.g. the audit tip) can attach to the key only once the vault is initialized,
// and silently no-op on a fresh / keychain-unavailable vault instead of forcing a
// key into existence as a side effect. Never throws.
function masterKeyExists() {
  try {
    if (process.env.KEEPER_PASSPHRASE) return true; // derivable from the passphrase (+salt)
    if (process.env.KEEPER_KEYCHAIN === '1' || process.env.KEEPER_KEYCHAIN === 'true') {
      return keychainAvailable() && !!keychainGet(); // a key is actually stored
    }
    return fs.existsSync(kpath('master.key')); // key-file mode: the file is present
  } catch { return null; }
}

/** Derive a NAMED subkey from the vault master key (HMAC-SHA256), WITHOUT ever
 *  exposing the master key itself. Returns a Buffer, or null if no master key
 *  exists yet (fresh vault) or it can't be obtained (keychain unavailable) — the
 *  caller no-ops in that case. The master key stays encapsulated in this module. */
export function deriveSubkey(label) {
  if (!masterKeyExists()) return null;
  let mk;
  try { mk = masterKey(); } catch { return null; } // never let a key-store error break audit
  return crypto.createHmac('sha256', mk).update(String(label)).digest();
}

function encryptWith(key, plain, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(String(aad), 'utf8')); // String() so a non-string secret name can't throw on Buffer.from
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ct: ct.toString('hex') };
}

function decryptWith(key, rec, aad) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(rec.iv, 'hex'));
  d.setAAD(Buffer.from(String(aad), 'utf8'));
  d.setAuthTag(Buffer.from(rec.tag, 'hex'));
  return Buffer.concat([d.update(Buffer.from(rec.ct, 'hex')), d.final()]).toString('utf8');
}

const encrypt = (plain, aad) => encryptWith(masterKey(), plain, aad);
const decrypt = (rec, aad) => decryptWith(masterKey(), rec, aad);

const read = () => { try { return JSON.parse(fs.readFileSync(kpath('vault.json'), 'utf8')); } catch { return { secrets: {} }; } };
function write(v) { fs.mkdirSync(home(), { recursive: true }); const f = kpath('vault.json'); fs.writeFileSync(f, JSON.stringify(v, null, 2), { mode: 0o600 }); lockdown(f); }

// Coerce the name to a string KEY (not just the AAD): a Symbol object-key isn't
// stringified, so JSON.stringify would silently DROP the secret on write — worse
// than a throw for a vault. String() makes every name serialize and round-trip.
export function putSecret(name, value) { name = String(name); const v = read(); v.secrets[name] = encrypt(value, name); write(v); }
export function getSecret(name) {
  name = String(name);
  const r = read().secrets[name];
  if (!r) return null;
  try { return decrypt(r, name); } catch { return null; } // fail closed: tampered / swapped / corrupt → null
}
export const hasSecret = (name) => !!read().secrets[String(name)];
export const listSecrets = () => Object.keys(read().secrets);
export function removeSecret(name) { name = String(name); const v = read(); const had = !!v.secrets[name]; delete v.secrets[name]; write(v); return had; }

/** Rotate the master key: decrypt every secret with the CURRENT key, re-encrypt
 *  under a NEW one, and swap. `to` picks the new key store ('passphrase' |
 *  'keychain' | 'file'); default = the current backend, i.e. rotate in place.
 *  A passphrase target reads the NEW passphrase from KEEPER_NEW_PASSPHRASE.
 *
 *  Order of operations (all under the cross-process lease lock, so a redeem's
 *  decrypt can't interleave with the swap):
 *    1. decrypt EVERY secret with the old key — any failure aborts with nothing
 *       written (a wrong passphrase must not half-rekey a vault);
 *    2. stage the fully re-encrypted vault at vault.json.new (nothing live yet);
 *    3. commit the new key store, then atomically rename the staged vault live;
 *    4. retire old-key artifacts (old salt / key file / keychain entries).
 *  If a crash lands between 3's two steps, the staged vault is still on disk:
 *  the next rekey run, under the NEW credentials, adopts a staged vault that the
 *  current key fully decrypts (and discards a stale one that it can't).
 *  In-process state (key cache, KEEPER_PASSPHRASE/KEEPER_KEYCHAIN) is updated to
 *  the new key; a separately-running daemon/broker fails CLOSED on the old key
 *  and must be restarted. */
export function rekeyVault({ to } = {}) {
  const from = backend();
  const target = to || from;
  if (!['passphrase', 'keychain', 'file'].includes(target)) throw new Error(`keeper rekey: unknown target key store '${target}' (use passphrase | keychain | file)`);
  if (target === 'passphrase' && !process.env.KEEPER_NEW_PASSPHRASE) throw new Error('keeper rekey: set KEEPER_NEW_PASSPHRASE to the passphrase to rotate to');
  if (target === 'keychain' && !keychainAvailable()) throw new Error('keeper rekey: keychain target but no OS keychain available');

  return withLock(() => {
    const vNew = kpath('vault.json.new');

    // Finish or discard an interrupted rekey. A staged vault the CURRENT key
    // fully decrypts (covering every live secret) is the committed new state —
    // adopt it; anything else is a stale pre-commit leftover — discard it.
    if (fs.existsSync(vNew)) {
      let adopted = false;
      try {
        const staged = JSON.parse(fs.readFileSync(vNew, 'utf8'));
        const k = masterKey();
        const names = Object.keys(staged.secrets || {});
        const liveNames = Object.keys(read().secrets);
        adopted = liveNames.every((n) => names.includes(n))
          && names.every((n) => { try { return decryptWith(k, staged.secrets[n], n) != null; } catch { return false; } });
        if (adopted) fs.renameSync(vNew, kpath('vault.json'));
      } catch { adopted = false; }
      if (!adopted) { try { fs.unlinkSync(vNew); } catch {} }
    }

    // 1. Decrypt everything with the old key — or abort with nothing changed.
    const oldKey = masterKey();
    const v = read();
    const names = Object.keys(v.secrets);
    const plain = {};
    for (const n of names) {
      let val; try { val = decryptWith(oldKey, v.secrets[n], n); } catch { val = null; }
      if (val == null) throw new Error(`keeper rekey: cannot decrypt secret '${n}' with the current master key — aborting, nothing changed`);
      plain[n] = val;
    }

    // 2. Build the new key and stage the re-encrypted vault.
    let newKey, newSaltHex = null, newKeyHex = null;
    if (target === 'passphrase') {
      const salt = crypto.randomBytes(16);
      newSaltHex = salt.toString('hex');
      newKey = scrypt(process.env.KEEPER_NEW_PASSPHRASE, salt);
    } else {
      newKey = crypto.randomBytes(32);
      newKeyHex = newKey.toString('hex');
    }
    const nv = { ...v, secrets: {} };
    for (const n of names) nv.secrets[n] = encryptWith(newKey, plain[n], n);
    fs.mkdirSync(home(), { recursive: true });
    fs.writeFileSync(vNew, JSON.stringify(nv, null, 2), { mode: 0o600 });
    lockdown(vNew);

    // Park the old keychain key under a second account until the swap commits —
    // recoverable during the window, without ever touching plaintext disk.
    if (from === 'keychain') { const cur = keychainGet(); if (cur) keychainSet(cur, 'master-key-prev'); }

    // 3. Commit: the new key store first, then the vault (atomic rename).
    if (target === 'passphrase') { const sf = kpath('salt'); fs.writeFileSync(sf, newSaltHex, { mode: 0o600 }); lockdown(sf); }
    else if (target === 'keychain') keychainSet(newKeyHex);
    else { const kf = kpath('master.key'); fs.writeFileSync(kf, newKeyHex, { mode: 0o600 }); lockdown(kf); }
    fs.renameSync(vNew, kpath('vault.json'));

    // 4. Retire what belonged to the old key. Rotation hygiene: old key material
    // must not linger once nothing is encrypted under it.
    if (from === 'passphrase' && target !== 'passphrase') { try { fs.unlinkSync(kpath('salt')); } catch {} }
    if (from === 'file' && target !== 'file') { try { fs.unlinkSync(kpath('master.key')); } catch {} }
    if (from === 'keychain') {
      keychainDelete('master-key-prev');
      if (target !== 'keychain') keychainDelete();
    }

    // This process must speak the new key from here on (the audit tip re-MAC
    // right after rekey depends on it): swap the env selection + bust the cache.
    if (target === 'passphrase') process.env.KEEPER_PASSPHRASE = process.env.KEEPER_NEW_PASSPHRASE;
    else delete process.env.KEEPER_PASSPHRASE;
    if (target === 'keychain') process.env.KEEPER_KEYCHAIN = '1'; else delete process.env.KEEPER_KEYCHAIN;
    delete process.env.KEEPER_NEW_PASSPHRASE;
    _keyCache.clear();

    return { secrets: names.length, from, to: target };
  });
}
