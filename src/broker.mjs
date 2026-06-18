// Egress-injection broker. The agent points its HTTP client's base URL at
//   http://127.0.0.1:<port>/<lease>
// and makes normal API calls with NO key. For each request the broker checks the
// lease (path allowlist + rate limit), redeems it (atomic + audited), then makes
// the real upstream request itself — injecting the secret into a header at the
// network boundary. The secret never enters the agent's context, and because the
// lease is BOUND to one upstream (and optionally to specific paths), it can only
// be injected toward that host / those endpoints — not an attacker URL.
//
// Local-only (127.0.0.1), plaintext HTTP to the agent, real HTTPS upstream.
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { Readable } from 'node:stream';
import { redeem, lease as leaseMod, audit } from './index.mjs';

// Hop-by-hop + auth headers we never pass through from the agent (we inject auth).
const DROP = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te',
  'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'authorization', 'x-api-key', 'cookie',
]);

const fpLease = (id) => crypto.createHash('sha256').update(typeof id === 'string' ? id : String(id ?? '')).digest('hex').slice(0, 12);
const send = (res, code, obj) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(obj)); };

function injectAuth(headers, inject, secret) {
  const spec = inject || 'bearer';
  if (spec === 'bearer') headers['authorization'] = 'Bearer ' + secret;
  else if (spec === 'x-api-key') headers['x-api-key'] = secret;
  else headers[String(spec).toLowerCase()] = secret; // custom header name → secret value
}

// Canonicalize the request target ONCE, BEFORE the allowlist check, so the path
// we authorize is the SAME path we send upstream (no parser differential). Split
// off the query, percent-decode the path, resolve `.`/`..` segments, and force a
// leading `/`. Net: `/v1/chat/../admin/keys` → `/v1/admin/keys` so a `..` escape
// is evaluated against the allowlist as the path that actually leaves the box.
function canonicalize(rest) {
  const raw = rest || '/';
  const qi = raw.indexOf('?');
  const rawPath = qi >= 0 ? raw.slice(0, qi) : raw;
  const query = qi >= 0 ? raw.slice(qi) : ''; // includes the leading '?'
  let decoded;
  try { decoded = decodeURIComponent(rawPath); } catch { decoded = rawPath; } // malformed %xx → use raw, never throw
  let norm = path.posix.normalize(decoded);
  if (!norm.startsWith('/')) norm = '/' + norm; // normalize may strip a leading '..' to '' — re-anchor
  return { path: norm, query, full: norm + query };
}

// Path allowlist — glob patterns ( * matches any non-query, non-`/` chars ). The
// non-`/`-crossing `*` means a `/v1/chat/*` lease scopes to ONE path segment's
// worth of endpoint under /v1/chat/, not the whole host. Empty = allow all.
function pathAllowed(p, patterns) {
  return patterns.some((g) => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/?]*') + '$').test(p));
}

// Per-lease sliding-window rate limit (req/min), in this broker process.
const windows = new Map();
function withinRate(fp, perMin) {
  if (!perMin) return true;
  const now = Date.now();
  const ts = (windows.get(fp) || []).filter((t) => now - t < 60_000);
  if (ts.length >= perMin) { windows.set(fp, ts); return false; }
  ts.push(now); windows.set(fp, ts);
  return true;
}

async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined;
  const chunks = [];
  for await (const ch of req) chunks.push(ch);
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

export function startBroker({ port = 8771, host = '127.0.0.1', onLog = () => {} } = {}) {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.url === '/' || req.url === '/healthz') return send(res, 200, { ok: true, service: 'keeper-broker' });
      const m = req.url.match(/^\/([^/?]+)(.*)$/);
      if (!m) return send(res, 400, { error: 'keeper: expected /<lease>/<path>' });
      const lid = m[1], rest = m[2] || '/';
      const fp = fpLease(lid);

      // Canonicalize ONCE up front — the path we authorize is the path we send.
      const canon = canonicalize(rest);

      // Peek the lease (non-consuming, NO host enforcement) to read its binding +
      // limits before spending a use. We must learn the upstream host here so we
      // can pass it to the host-ENFORCED redeem below (a host-scoped lease now
      // denies when no host is supplied — see lease.mjs).
      const peek = leaseMod.peekLease(lid);
      if (!peek.ok) { audit.record({ event: 'deny', lease: fp, reason: peek.reason, via: 'broker' }); return send(res, 403, { error: 'keeper: denied (' + peek.reason + ')' }); }
      const meta = peek.lease;
      if (!meta.upstream) return send(res, 400, { error: 'keeper: lease is not bound to an upstream (grant with --upstream)' });
      // Derive the destination host from the bound upstream. A host-scoped lease
      // must agree with its own upstream, else it could never redeem here.
      let upHost = null;
      try { upHost = new URL(meta.upstream).hostname; } catch {}
      if (meta.host && meta.host !== upHost) { audit.record({ event: 'deny', lease: fp, reason: 'host-scope', via: 'broker' }); return send(res, 403, { error: 'keeper: denied (host-scope)' }); }
      if (meta.paths && !pathAllowed(canon.path, meta.paths)) { audit.record({ event: 'deny', lease: fp, reason: 'path', path: canon.path, via: 'broker' }); return send(res, 403, { error: 'keeper: path not allowed' }); }
      if (!withinRate(fp, meta.rate)) { audit.record({ event: 'deny', lease: fp, reason: 'rate', via: 'broker' }); res.setHeader('retry-after', '60'); return send(res, 429, { error: 'keeper: rate limit exceeded' }); }

      const body = await readBody(req);
      const r = redeem(lid, { host: upHost }); // atomic check-and-consume + audit, host-enforced
      if (!r.ok) return send(res, 403, { error: 'keeper: denied (' + r.reason + ')' }); // lost a race for the last use / host-scope

      const url = r.upstream.replace(/\/$/, '') + canon.full;
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k.toLowerCase())) headers[k] = v;
      injectAuth(headers, r.inject, r.value); // the only place the real secret touches the request

      const up = await fetch(url, { method: req.method, headers, body, redirect: 'manual', duplex: body ? 'half' : undefined });
      onLog(`${req.method} ${fp} → ${new URL(url).host}${canon.path} ${up.status}`); // never the secret or raw lease

      res.statusCode = up.status;
      up.headers.forEach((v, k) => { if (!DROP.has(k.toLowerCase())) res.setHeader(k, v); });
      if (up.body) Readable.fromWeb(up.body).pipe(res); else res.end();
    } catch (e) {
      send(res, 502, { error: 'keeper broker: ' + ((e && e.message) || String(e)) });
    }
  });
  server.listen(port, host, () => onLog(`keeper broker on http://${host}:${server.address().port} — point your client base URL at http://${host}:${server.address().port}/<lease>`));
  return server;
}
