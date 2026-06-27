// keeper redeem-daemon — a long-lived LOCAL process that HOLDS the master key
// and answers lease→secret over a local socket (unix domain / Windows named
// pipe; never TCP). A doer holds only a lease id + the daemon's token, never the
// key: it can redeem the leases it was handed (atomic + audited) and nothing
// else (lease ids are 144-bit and single-use). This is what makes "no key on
// the device" real for the git-askpass / remote-agent paths — the broker does
// the same for base-URL-swappable API calls.
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { redeem, revoke, lease } from './index.mjs';
import { keeperSocket, daemonInfoFile } from './client.mjs';

export function startDaemon({ socketPath = keeperSocket(), infoFile = daemonInfoFile(), token, onLog = () => {} } = {}) {
  // A token is ALWAYS required — this endpoint hands out secrets. Honor
  // $KEEPER_DAEMON_TOKEN (so the platform can pin a known token for its doers),
  // else generate one and publish it ONLY into the 0600 info file.
  const tok = token || process.env.KEEPER_DAEMON_TOKEN || crypto.randomBytes(18).toString('base64url');
  let served = 0;

  const onConnection = (sock) => {
    let buf = '';
    sock.setTimeout(30000, () => sock.destroy()); // drop idle / half-open connections
    sock.on('data', (d) => {
      buf += d.toString();
      if (buf.length > 1 << 20) { sock.destroy(); return; } // 1 MB cap — no-newline client can't OOM us
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let req;
        try { req = JSON.parse(line); } catch { sock.write(JSON.stringify({ ok: false, reason: 'bad-json' }) + '\n'); continue; }
        if (req.token !== tok) { sock.write(JSON.stringify({ ok: false, reason: 'unauthorized' }) + '\n'); continue; }
        try {
          if (req.op === 'redeem') {
            const r = redeem(String(req.lease ?? ''), { host: req.host }); // daemon holds the key; atomic + audited
            served++;
            sock.write(JSON.stringify(r) + '\n');
          } else if (req.op === 'check') {
            const c = lease.checkLease(String(req.lease ?? ''), { host: req.host });
            sock.write(JSON.stringify({ ok: c.ok, reason: c.reason }) + '\n'); // NEVER the value
          } else if (req.op === 'revoke') {
            sock.write(JSON.stringify({ ok: revoke(String(req.lease ?? '')) }) + '\n');
          } else if (req.op === 'stats') {
            sock.write(JSON.stringify({ ok: true, served, pid: process.pid }) + '\n');
          } else {
            sock.write(JSON.stringify({ ok: false, reason: 'unknown-op' }) + '\n');
          }
        } catch {
          // Never echo the error text — it could contain secret-adjacent data.
          sock.write(JSON.stringify({ ok: false, reason: 'error' }) + '\n');
        }
      }
    });
    sock.on('error', () => {});
  };

  if (process.platform !== 'win32') {
    try { fs.mkdirSync(path.dirname(socketPath), { recursive: true }); } catch {} // ensure the socket dir exists
    try { fs.unlinkSync(socketPath); } catch {} // clear a stale socket
  }
  const server = net.createServer(onConnection);
  server.on('error', (e) => onLog('listen error: ' + e.message));
  server.listen(socketPath, () => {
    // Lock the socket to the owner the instant it exists, BEFORE the token is
    // published. On Unix, connect() needs WRITE permission on the socket node, so
    // a group/other-writable umask (e.g. 0777 under umask 000, 0755 under 0022)
    // would let another local user reach this secret-serving endpoint. chmod 0600
    // is the same owner-only lockdown every other keeper artifact already gets
    // (vault / leases / audit / master key / the token-bearing daemon.json). On
    // Windows the endpoint is a named pipe, not a filesystem node — nothing to chmod.
    if (process.platform !== 'win32') { try { fs.chmodSync(socketPath, 0o600); } catch {} }
    try {
      fs.mkdirSync(path.dirname(infoFile), { recursive: true });
      fs.writeFileSync(infoFile, JSON.stringify({ socket: socketPath, pid: process.pid, token: tok, started: new Date().toISOString() }), { mode: 0o600 });
    } catch (e) { onLog('info-file write failed: ' + e.message); }
    onLog('redeem-daemon listening on ' + socketPath);
  });

  const cleanup = () => {
    try { fs.unlinkSync(infoFile); } catch {}
    if (process.platform !== 'win32') { try { fs.unlinkSync(socketPath); } catch {} }
  };
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { cleanup(); process.exit(0); });
  process.once('exit', cleanup);

  return {
    server, token: tok,
    close(cb) { try { server.close(() => { cleanup(); cb && cb(); }); } catch { cleanup(); cb && cb(); } },
  };
}
