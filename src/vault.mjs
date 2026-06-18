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
import { keychainGet, keychainSet, keychainAvailable } from './keychain.mjs';

// 0600 is a no-op on Windows (ACL-based) — strip inheritance + grant only the user.
function lockdown(file) {
  if (process.platform !== 'win32' || !process.env.USERNAME) return;
  try { execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:F`], { stdio: 'ignore' }); } catch {}
}

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
    key = crypto.scryptSync(pass, salt, 32, { N: 16384, r: 8, p: 1 });
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

function encrypt(plain, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  c.setAAD(Buffer.from(String(aad), 'utf8')); // String() so a non-string secret name can't throw on Buffer.from
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ct: ct.toString('hex') };
}

function decrypt(rec, aad) {
  const d = crypto.createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(rec.iv, 'hex'));
  d.setAAD(Buffer.from(String(aad), 'utf8'));
  d.setAuthTag(Buffer.from(rec.tag, 'hex'));
  return Buffer.concat([d.update(Buffer.from(rec.ct, 'hex')), d.final()]).toString('utf8');
}

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
