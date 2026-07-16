#!/usr/bin/env node
// keeper CLI — store secrets, grant scoped short-lived leases, redeem at egress.
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { addSecret, removeSecret, grant, grantFromLease, redeem, revoke, rekeyMasterKey, vault, lease, audit } from './index.mjs';
import { startBroker } from './broker.mjs';
import { startDaemon } from './daemon.mjs';
import { redeemViaDaemon } from './client.mjs';
import { keychainAvailable, keychainKind } from './keychain.mjs';

const raw = process.argv.slice(2);
const sep = raw.indexOf('--');
const pre = sep >= 0 ? raw.slice(0, sep) : raw;
const post = sep >= 0 ? raw.slice(sep + 1) : [];
const cmd = pre[0];
const opt = (name, def) => {
  const i = pre.indexOf(name);
  if (i >= 0) { const nx = pre[i + 1]; return nx !== undefined && !nx.startsWith('--') ? nx : true; } // `--name value` or bare `--name`
  const eq = pre.find((x) => x.startsWith(name + '='));
  return eq ? eq.slice(name.length + 1) : def;
};
// Was a flag supplied at all (as `--name`, `--name value`, or `--name=…`)? Lets
// `grant --from-lease` tell "caller OMITTED --ttl" (→ inherit the parent's) from
// "caller PASSED --ttl" (→ attenuate to it): undefined vs a value downstream.
const has = (name) => pre.includes(name) || pre.some((x) => x.startsWith(name + '='));
const pos = pre.slice(1).filter((a) => !a.startsWith('--'));
// Machine contract (grant/leases/ls/audit): stdout carries exactly ONE JSON
// value — no ANSI, no prose, no stderr summary — so a control plane scripting
// keeper never scrapes human output. Default (no --json) output is unchanged.
const asJson = Boolean(opt('--json', false));

const tty = process.stdout.isTTY;
const C = { red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', rst: '\x1b[0m' };
const c = (col, s) => (tty ? col + s + C.rst : s);
const out = (s = '') => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');
// A doer with no master key sets KEEPER_DAEMON=1 → redeem/exec route through the
// local redeem-daemon (which holds the key) instead of the vault.
const viaDaemon = () => !!process.env.KEEPER_DAEMON;

function usage() {
  out(`${c(C.bold, 'keeper')} — own your agent secrets · vault · lease · redeem · audit

  keeper add <name>                    store a secret (value from stdin, or --value=)
  keeper ls [--json]                   list secret names (never values)
  keeper rm <name>                     delete a secret
  keeper grant <name> [opts]           mint a lease the agent holds instead of the key
       --ttl <s>=300  --uses <n>=1  --host <host>
                                       (KEEPER_MAX_TTL / KEEPER_MAX_USES, if set, cap every grant)
       --upstream <base-url>  --inject <bearer|x-api-key|Header-Name>   (for the broker)
       --rate <req/min>  --paths <glob,glob>  --concurrency <n>
                                       (broker: cap rate + simultaneous requests, scope endpoints)
       --json                          machine-readable: ONE JSON object on stdout, nothing else
  keeper grant --from-lease <lease> [tighter opts]
                                       DELEGATE: attenuate a lease you hold into a narrower
                                       sub-lease for a sub-agent — shorter --ttl, fewer --uses,
                                       tighter --host/--upstream/--paths/--rate/--concurrency.
                                       NEVER wider; unset scopes inherit the parent's. The child
                                       records the parent's fingerprint in its grant audit event.
  keeper redeem <lease> [--host <h>]   exchange a valid lease for the secret (egress side)
  keeper exec <lease> --as <ENV> [--host <h>] -- <cmd...>
                                       redeem + run <cmd> with the secret in its env only
  keeper broker [--port 8771] [--timeout <ms>=30000]
                                       run the egress-injection proxy: point your client's
                                       base URL at http://127.0.0.1:<port>/<lease> — the
                                       broker injects the secret upstream, the agent holds none
                                       (--timeout bounds each upstream call; also KEEPER_BROKER_TIMEOUT_MS)
  keeper serve [--socket <path>]       run the redeem-daemon (HOLDS the key) on a local socket;
                                       a doer sets KEEPER_DAEMON=1 + KEEPER_SOCKET/_TOKEN and
                                       redeems its leases without ever holding the master key
  keeper leases [--json]               list outstanding leases
  keeper revoke <lease>                kill a lease
  keeper audit [--verify] [--json]     show the access log (--verify checks the hash chain)
  keeper rekey [--to passphrase|keychain|file]
                                       rotate the master key: re-encrypt every secret under a
                                       new key (passphrase target reads KEEPER_NEW_PASSPHRASE)
  keeper keychain                      master-key backend status (set KEEPER_KEYCHAIN=1 to use the OS keychain)

  Master key: KEEPER_PASSPHRASE (scrypt, off-disk) · KEEPER_KEYCHAIN=1 (OS keychain) · else a 0600 key file.`);
}

function valueFromStdin() {
  const v = opt('--value', null);
  if (v && v !== true) return v;
  if (process.stdin.isTTY) return null;
  try { return fs.readFileSync(0, 'utf8').replace(/\r?\n$/, ''); } catch { return null; }
}

const T = {
  add() {
    if (!pos[0]) return (usage(), 2);
    const val = valueFromStdin();
    if (val == null || val === '') { err('keeper add: provide the secret on stdin (echo … | keeper add NAME) or --value='); return 2; }
    addSecret(pos[0], val);
    out(`${c(C.grn, '✓')} stored ${c(C.bold, pos[0])} ${c(C.dim, '(encrypted)')}`);
    return 0;
  },
  ls() {
    const names = vault.listSecrets();
    if (asJson) return (out(JSON.stringify(names)), 0);
    if (!names.length) return (out(c(C.dim, 'vault is empty')), 0);
    names.forEach((n) => out(`${c(C.grn, '●')} ${n}`));
    return 0;
  },
  rm() { if (!pos[0]) return (usage(), 2); out(removeSecret(pos[0]) ? `${c(C.grn, '✓')} removed ${pos[0]}` : c(C.dim, `no such secret: ${pos[0]}`)); return 0; },
  grant() {
    // Delegation mode: `keeper grant --from-lease <parentLease> [tighter opts]`
    // attenuates a lease the caller HOLDS into a narrower sub-lease for a
    // sub-agent — no <name> positional, the secret is inherited from the parent.
    // Every unset scope inherits the parent's; any set one must be <= it, else
    // the mint is rejected (and audited). ttl/uses left unset default to the
    // parent's REMAINING ttl / uses (a straight, no-wider copy).
    const fromLease = opt('--from-lease', null);
    if (fromLease && fromLease !== true) {
      try {
        const l = grantFromLease(fromLease, {
          ttlS: has('--ttl') ? Number(opt('--ttl', undefined)) : undefined,
          uses: has('--uses') ? Number(opt('--uses', undefined)) : undefined,
          host: opt('--host', null) || null, upstream: opt('--upstream', null) || null, inject: opt('--inject', null) || null,
          rate: has('--rate') ? Number(opt('--rate', 0)) : undefined, concurrency: has('--concurrency') ? Number(opt('--concurrency', 0)) : undefined,
          paths: has('--paths') ? String(opt('--paths', '') || '').split(',').map((s) => s.trim()).filter(Boolean) : undefined,
        });
        if (asJson) {
          out(JSON.stringify({
            id: l.id, secret: l.secret, usesLeft: l.usesLeft, expiresAt: l.expiresAt,
            ttlS: Math.round((l.expiresAt - l.createdAt) / 1000),
            host: l.host, upstream: l.upstream, inject: l.inject, rate: l.rate, paths: l.paths, concurrency: l.concurrency,
            parent: l.parent,
          }));
          return 0;
        }
        out(c(C.bold, l.id));
        err(c(C.dim, `  ↳ ${l.secret} · from ${l.parent} · ${l.usesLeft} use(s) · ttl ${Math.round((l.expiresAt - Date.now()) / 1000)}s${l.host ? ' · host ' + l.host : ''}${l.upstream ? ' · → ' + l.upstream : ''}${l.rate ? ' · ' + l.rate + '/min' : ''}${l.concurrency ? ' · ≤' + l.concurrency + ' in-flight' : ''}${l.paths ? ' · paths ' + l.paths.join(',') : ''}`));
        return 0;
      } catch (e) { err(`${c(C.red, '✗')} ${e.message}`); return 1; }
    }
    if (!pos[0]) return (usage(), 2);
    try {
      const l = grant(pos[0], {
        ttlS: Number(opt('--ttl', 300)), uses: Number(opt('--uses', 1)), host: opt('--host', null) || null,
        upstream: opt('--upstream', null) || null, inject: opt('--inject', null) || null,
        rate: Number(opt('--rate', 0)) || null, concurrency: Number(opt('--concurrency', 0)) || null,
        paths: String(opt('--paths', '') || '').split(',').map((s) => s.trim()).filter(Boolean),
      });
      if (asJson) {
        // The same one-time id + metadata the human path returns — just
        // machine-readable, stdout-only. Nothing new is persisted or leaked.
        out(JSON.stringify({
          id: l.id, secret: l.secret, usesLeft: l.usesLeft, expiresAt: l.expiresAt,
          ttlS: Math.round((l.expiresAt - l.createdAt) / 1000),
          host: l.host, upstream: l.upstream, inject: l.inject, rate: l.rate, paths: l.paths, concurrency: l.concurrency,
        }));
        return 0;
      }
      out(c(C.bold, l.id));
      err(c(C.dim, `  ↳ ${pos[0]} · ${l.usesLeft} use(s) · ttl ${Math.round((l.expiresAt - Date.now()) / 1000)}s${l.host ? ' · host ' + l.host : ''}${l.upstream ? ' · → ' + l.upstream : ''}${l.rate ? ' · ' + l.rate + '/min' : ''}${l.concurrency ? ' · ≤' + l.concurrency + ' in-flight' : ''}${l.paths ? ' · paths ' + l.paths.join(',') : ''}`));
      return 0;
    } catch (e) { err(`${c(C.red, '✗')} ${e.message}`); return 1; }
  },
  broker() {
    const port = Number(opt('--port', 8771));
    const host = opt('--host', '127.0.0.1');
    const timeoutMs = Number(opt('--timeout', 0)) || 0; // 0 → KEEPER_BROKER_TIMEOUT_MS, then the 30s default
    startBroker({ port, host, timeoutMs, onLog: (m) => err(c(C.dim, 'keeper: ' + m)) });
    return new Promise(() => {}); // run until killed
  },
  rekey() {
    try {
      const to = opt('--to', null);
      const r = rekeyMasterKey({ to: to && to !== true ? to : undefined });
      out(`${c(C.grn, '✓')} master key rotated (${r.from} → ${r.to}) · ${r.secrets} secret(s) re-encrypted`);
      if (r.to === 'passphrase') err(c(C.dim, '  ↳ use the NEW passphrase in KEEPER_PASSPHRASE from now on'));
      err(c(C.dim, '  ↳ restart any running keeper daemon/broker — they hold the old key and will fail closed'));
      return 0;
    } catch (e) { err(`${c(C.red, '✗')} ${e.message}`); return 1; }
  },
  keychain() {
    const on = process.env.KEEPER_KEYCHAIN === '1' || process.env.KEEPER_KEYCHAIN === 'true';
    const avail = keychainAvailable();
    out(`backend:    ${keychainKind()}`);
    out(`available:  ${avail ? c(C.grn, 'yes') : c(C.red, 'no')}`);
    out(`active:     ${on ? c(C.grn, 'yes (KEEPER_KEYCHAIN=1)') : c(C.dim, 'no — set KEEPER_KEYCHAIN=1 to use it')}`);
    if (on && !avail) { out(c(C.red, '  ⚠ requested but unavailable — keeper will fail closed')); return 1; }
    return 0;
  },
  async redeem() {
    if (!pos[0]) return (usage(), 2);
    const r = viaDaemon() ? await redeemViaDaemon(pos[0], { host: opt('--host', undefined) }) : redeem(pos[0], { host: opt('--host', undefined) });
    if (!r.ok) { err(`${c(C.red, '✗')} denied: ${r.reason}`); return 1; }
    process.stdout.write(r.value); // raw, for piping — no newline
    return 0;
  },
  async exec() {
    if (!pos[0] || !post.length) return (usage(), 2);
    const as = opt('--as', null);
    if (!as || as === true) { err('keeper exec: --as <ENV_NAME> is required'); return 2; }
    const r = viaDaemon() ? await redeemViaDaemon(pos[0], { host: opt('--host', undefined) }) : redeem(pos[0], { host: opt('--host', undefined) });
    if (!r.ok) { err(`${c(C.red, '✗')} denied: ${r.reason}`); return 1; }
    const res = spawnSync(post[0], post.slice(1), { env: { ...process.env, [as]: r.value }, stdio: 'inherit' });
    return res.status ?? (res.error ? 1 : 0);
  },
  serve() {
    const sp = opt('--socket', undefined);
    startDaemon({ ...(sp && sp !== true ? { socketPath: sp } : {}), onLog: (m) => err(c(C.dim, 'keeper: ' + m)) });
    return new Promise(() => {}); // run until killed
  },
  leases() {
    const ls = lease.listLeases();
    if (asJson) return (out(JSON.stringify(ls)), 0); // already secret-safe: fingerprint, never the raw id
    if (!ls.length) return (out(c(C.dim, 'no outstanding leases')), 0);
    ls.forEach((l) => out(`${l.expired ? c(C.dim, '○') : c(C.grn, '●')} ${c(C.bold, l.fingerprint)} ${c(C.dim, `→ ${l.secret} · ${l.usesLeft} use(s)${l.expired ? ' · EXPIRED' : ''}${l.host ? ' · ' + l.host : ''}${l.parent ? ' · ⤷ from ' + l.parent : ''}`)}`));
    return 0;
  },
  revoke() { if (!pos[0]) return (usage(), 2); out(revoke(pos[0]) ? `${c(C.grn, '✓')} revoked ${pos[0]}` : c(C.dim, `no such lease: ${pos[0]}`)); return 0; },
  audit() {
    if (asJson) {
      // --verify → the verdict object ({ ok, entries } | { ok:false, reason|at }),
      // exit code preserved; plain → the parsed event array (mirrors audit.read()).
      if (opt('--verify', false)) { const v = audit.verify(); out(JSON.stringify(v)); return v.ok ? 0 : 1; }
      return (out(JSON.stringify(audit.read())), 0);
    }
    const events = audit.read();
    for (const e of events) out(`${c(C.dim, e.ts)}  ${eventColor(e.event)} ${e.secret || e.lease || ''}${e.from ? c(C.dim, ' ⤷ from ' + e.from) : ''}${e.reason ? c(C.red, ' (' + e.reason + ')') : ''}${e.host ? c(C.dim, ' · ' + e.host) : ''}`);
    if (opt('--verify', false)) {
      const v = audit.verify();
      const where = v.reason ? `(${v.reason})` : v.at != null ? `at entry ${v.at}` : '';
      out(v.ok ? c(C.grn, `\n✓ audit chain intact (${v.entries} entries)`) : c(C.red, `\n✗ audit TAMPERED ${where}`.trimEnd()));
      return v.ok ? 0 : 1;
    }
    return 0;
  },
};

function eventColor(ev) {
  const m = { add: C.grn, grant: C.grn, redeem: C.yel, deny: C.red, sanitize: C.red, revoke: C.red, remove: C.dim, rekey: C.yel };
  return c(m[ev] || C.rst, ev.padEnd(6));
}

if (!cmd || cmd === '-h' || cmd === '--help' || !T[cmd]) { usage(); process.exit(cmd && !['-h', '--help'].includes(cmd) ? 2 : 0); }
if (cmd === 'broker' || cmd === 'serve') T[cmd](); // long-running; keep the event loop alive
else Promise.resolve(T[cmd]()).then((code) => process.exit(code ?? 0));
