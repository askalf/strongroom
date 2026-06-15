// Encrypted secret store. Secrets are AES-256-GCM encrypted at rest under a
// 32-byte master key in ~/.keeper/master.key (0600) — never plaintext env vars,
// never in a prompt. The vault file holds only ciphertext + IV + auth tag.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { home, kpath } from './paths.mjs';

function masterKey() {
  const kf = kpath('master.key');
  try { return Buffer.from(fs.readFileSync(kf, 'utf8').trim(), 'hex'); } catch {}
  const key = crypto.randomBytes(32);
  fs.mkdirSync(home(), { recursive: true });
  fs.writeFileSync(kf, key.toString('hex'), { mode: 0o600 });
  return key;
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ct: ct.toString('hex') };
}

function decrypt(rec) {
  const d = crypto.createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(rec.iv, 'hex'));
  d.setAuthTag(Buffer.from(rec.tag, 'hex'));
  return Buffer.concat([d.update(Buffer.from(rec.ct, 'hex')), d.final()]).toString('utf8');
}

const read = () => { try { return JSON.parse(fs.readFileSync(kpath('vault.json'), 'utf8')); } catch { return { secrets: {} }; } };
const write = (v) => { fs.mkdirSync(home(), { recursive: true }); fs.writeFileSync(kpath('vault.json'), JSON.stringify(v, null, 2), { mode: 0o600 }); };

export function putSecret(name, value) { const v = read(); v.secrets[name] = encrypt(value); write(v); }
export function getSecret(name) { const r = read().secrets[name]; return r ? decrypt(r) : null; }
export const hasSecret = (name) => !!read().secrets[name];
export const listSecrets = () => Object.keys(read().secrets);
export function removeSecret(name) { const v = read(); const had = !!v.secrets[name]; delete v.secrets[name]; write(v); return had; }
