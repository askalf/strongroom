// OS-keychain master-key storage — the key is held by the operating system, tied
// to your login, never written as plaintext. Zero deps: each platform's native CLI/API.
//   macOS   → Keychain        (security)
//   Linux   → Secret Service  (secret-tool / libsecret)
//   Windows → DPAPI user-scope (PowerShell; an encrypted blob only this user can read)
// KEEPER_KEYCHAIN_FAKE=<file> is a TEST seam (a plain JSON file standing in for the keychain).
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { kpath } from './paths.mjs';

const SERVICE = 'keeper', ACCOUNT = 'master-key';
const run = (cmd, args, input) => execFileSync(cmd, args, { input, stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' });
const fake = () => process.env.KEEPER_KEYCHAIN_FAKE;

export function keychainAvailable() {
  if (process.env.KEEPER_NO_KEYCHAIN) return false; // explicit opt-out / test seam
  if (fake()) return true;
  if (process.platform === 'darwin' || process.platform === 'win32') return true; // security / DPAPI are built in
  if (process.platform === 'linux') { try { run('secret-tool', ['--version']); return true; } catch { return false; } }
  return false;
}

/** Read the stored master key (hex), or null if none. */
export function keychainGet() {
  if (fake()) { try { return JSON.parse(fs.readFileSync(fake(), 'utf8')).key || null; } catch { return null; } }
  try {
    if (process.platform === 'darwin') return run('security', ['find-generic-password', '-a', ACCOUNT, '-s', SERVICE, '-w']).trim() || null;
    if (process.platform === 'linux') return run('secret-tool', ['lookup', 'service', SERVICE, 'account', ACCOUNT]).trim() || null;
    if (process.platform === 'win32') {
      const blob = kpath('master.key.dpapi');
      if (!fs.existsSync(blob)) return null;
      const b64 = fs.readFileSync(blob, 'utf8').trim();
      const ps = `Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String('${b64}'); $p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'); [Console]::Out.Write([Text.Encoding]::UTF8.GetString($p))`;
      return run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]).trim() || null;
    }
  } catch { return null; }
  return null;
}

/** Store the master key (hex) in the OS keychain. */
export function keychainSet(hex) {
  if (fake()) { fs.mkdirSync(path.dirname(fake()), { recursive: true }); fs.writeFileSync(fake(), JSON.stringify({ key: hex }), { mode: 0o600 }); return; }
  if (process.platform === 'darwin') { run('security', ['add-generic-password', '-a', ACCOUNT, '-s', SERVICE, '-w', hex, '-U']); return; }
  if (process.platform === 'linux') { run('secret-tool', ['store', '--label=keeper master key', 'service', SERVICE, 'account', ACCOUNT], hex); return; }
  if (process.platform === 'win32') {
    const ps = `Add-Type -AssemblyName System.Security; $p=[Text.Encoding]::UTF8.GetBytes('${hex}'); $b=[Security.Cryptography.ProtectedData]::Protect($p,$null,'CurrentUser'); [Console]::Out.Write([Convert]::ToBase64String($b))`;
    const b64 = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]).trim();
    fs.mkdirSync(path.dirname(kpath('master.key.dpapi')), { recursive: true });
    fs.writeFileSync(kpath('master.key.dpapi'), b64, { mode: 0o600 });
    return;
  }
  throw new Error('no OS keychain available on this platform');
}

export const keychainKind = () =>
  process.platform === 'darwin' ? 'macOS Keychain'
    : process.platform === 'win32' ? 'Windows DPAPI (user scope)'
      : process.platform === 'linux' ? 'Secret Service (libsecret)'
        : 'unknown';
