// Egress-injection broker. The agent points its HTTP client's base URL at
//   http://127.0.0.1:<port>/<lease>
// and makes normal API calls with NO key. For each request the broker checks the
// lease (path allowlist + rate limit + concurrency cap), redeems it (atomic +
// audited), then makes the real upstream request itself — injecting the secret
// into a header at the network boundary. The secret never enters the agent's
// context, and because the lease is BOUND to one upstream (and optionally to
// specific paths), it can only be injected toward that host / those endpoints —
// not an attacker URL. The RESPONSE is sanitized on the way back: if the
// upstream ever reflects the injected secret (echo/debug endpoints, verbose
// errors, misconfigured proxies), the broker redacts it from the relayed
// headers and body — otherwise a reflecting upstream would hand the raw key
// straight into the agent's context, defeating the injection boundary.
//
// Local-only (127.0.0.1), plaintext HTTP to the agent, real HTTPS upstream.
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { Readable, Transform } from 'node:stream';
import { redeem, lease as leaseMod, audit } from './index.mjs';

// Hop-by-hop + auth headers we never pass through from the agent (we inject auth).
// accept-encoding is dropped too (identity is forced below): the response body
// must arrive uncompressed so the secret scan sees the actual bytes.
const DROP = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te',
  'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'authorization', 'x-api-key', 'cookie',
  'accept-encoding',
]);
// Never relayed from the upstream response: fetch() hands us a DECODED body, so
// a passed-through content-encoding would mislabel it — and we re-chunk anyway.
const RESP_DROP = new Set(['content-encoding']);

const REDACTED = '[keeper:redacted]';
// Don't scan for secrets shorter than this — every real API key is far longer,
// and redacting a tiny common substring would shred the response.
const MIN_SCAN_LEN = 8;

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
export function canonicalize(rest) { // exported for the fuzz harness (test/fuzz)
  const raw = rest || '/';
  const qi = raw.indexOf('?');
  const rawPath = qi >= 0 ? raw.slice(0, qi) : raw;
  const query = qi >= 0 ? raw.slice(qi) : ''; // includes the leading '?'
  let decoded;
  try { decoded = decodeURIComponent(rawPath); } catch { decoded = rawPath; } // malformed %xx → use raw, never throw
  // Anchor to root BEFORE normalizing: posix.normalize only resolves `..`
  // against an absolute root, so normalizing first and prepending `/` after
  // would leave a climbing `/..` for a relative target (e.g. `..` → `/..`).
  // Normalizing an already-absolute path clamps every `..` at `/`.
  const norm = path.posix.normalize('/' + decoded);
  return { path: norm, query, full: norm + query };
}

// Path allowlist — glob patterns ( * matches any non-query, non-`/` chars ). The
// non-`/`-crossing `*` means a `/v1/chat/*` lease scopes to ONE path segment's
// worth of endpoint under /v1/chat/, not the whole host. Empty = allow all.
export function pathAllowed(p, patterns) { // exported for the fuzz harness (test/fuzz)
  return patterns.some((g) => {
    // Escape every regex metacharacter (including `?`, which is NOT a keeper
    // glob wildcard — only `*` is) so a literal `?` in a pattern can't produce
    // an invalid regex; then turn `*` into a non-`/`, non-`?` wildcard.
    let re;
    try { re = new RegExp('^' + g.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '[^/?]*') + '$'); }
    catch { return false; } // an un-compilable pattern matches nothing — fail closed, never throw
    return re.test(p);
  });
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

// Per-lease in-flight request count (concurrency cap, bound at grant). The rate
// limit caps requests-per-minute; this caps SIMULTANEOUS requests — a runaway or
// hijacked agent can't hold N parallel streams open through one lease.
const inflight = new Map();

// Redact every occurrence of the secret from a stream WITHOUT breaking
// streaming (SSE stays event-by-event). A secret can split across chunk
// boundaries, so each pass holds back the longest tail that is a prefix of the
// secret — with a high-entropy key that tail is almost always empty, so bytes
// flow through untouched and undelayed. Redaction only changes the body length;
// content-length is never relayed (we re-chunk), so the response stays valid.
function redactStream(secretBuf, onFirstHit) {
  const marker = Buffer.from(REDACTED);
  let carry = Buffer.alloc(0);
  let hit = false;
  return new Transform({
    transform(chunk, _enc, cb) {
      let buf = Buffer.concat([carry, chunk]);
      const out = [];
      let start = 0, idx;
      while ((idx = buf.indexOf(secretBuf, start)) !== -1) {
        out.push(buf.subarray(start, idx), marker);
        start = idx + secretBuf.length;
        if (!hit) { hit = true; onFirstHit(); }
      }
      const rest = buf.subarray(start);
      let keep = 0;
      for (let k = Math.min(rest.length, secretBuf.length - 1); k > 0; k--) {
        if (rest.subarray(rest.length - k).equals(secretBuf.subarray(0, k))) { keep = k; break; }
      }
      carry = Buffer.from(rest.subarray(rest.length - keep));
      out.push(rest.subarray(0, rest.length - keep));
      cb(null, Buffer.concat(out));
    },
    // A held-back tail is only ever a PARTIAL prefix of the secret (a complete
    // match would have been redacted above), so flushing it raw is safe.
    flush(cb) { cb(null, carry.length ? carry : undefined); },
  });
}

async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined;
  const chunks = [];
  for await (const ch of req) chunks.push(ch);
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

export function startBroker({ port = 8771, host = '127.0.0.1', onLog = () => {}, timeoutMs = 0 } = {}) {
  // Time-to-response-headers bound on the upstream request. 0 / unset falls
  // through to KEEPER_BROKER_TIMEOUT_MS, then a 30s default; an explicit large
  // value opts out for slow legitimate upstreams.
  const upstreamTimeoutMs = Number(timeoutMs) || Number(process.env.KEEPER_BROKER_TIMEOUT_MS) || 30000;
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
      if (meta.concurrency && (inflight.get(fp) || 0) >= meta.concurrency) {
        audit.record({ event: 'deny', lease: fp, reason: 'concurrency', via: 'broker' });
        res.setHeader('retry-after', '1');
        return send(res, 429, { error: 'keeper: concurrency limit exceeded' });
      }
      // Count this request in-flight from here until the response is done or the
      // client goes away ('close' fires for both). Everything below ends `res`.
      inflight.set(fp, (inflight.get(fp) || 0) + 1);
      res.on('close', () => { const n = (inflight.get(fp) || 1) - 1; n > 0 ? inflight.set(fp, n) : inflight.delete(fp); });

      const body = await readBody(req);
      const r = redeem(lid, { host: upHost }); // atomic check-and-consume + audit, host-enforced
      if (!r.ok) return send(res, 403, { error: 'keeper: denied (' + r.reason + ')' }); // lost a race for the last use / host-scope

      const url = r.upstream.replace(/\/$/, '') + canon.full;
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k.toLowerCase())) headers[k] = v;
      headers['accept-encoding'] = 'identity'; // uncompressed response — required for the secret scan below
      injectAuth(headers, r.inject, r.value); // the only place the real secret touches the request

      // Bound the upstream call. Without this a black-hole upstream (accepts the
      // socket, never sends headers) holds the request open indefinitely — and
      // since the concurrency slot above is only released when `res` closes, a
      // patient client pointed at a hung upstream would wedge a concurrency-
      // capped lease PERMANENTLY (N hung requests → every later call 429s until
      // the broker restarts). The use is already, correctly, spent — the secret
      // was injected and the request left the box; this only bounds the hang.
      // The timer governs time-to-headers; once streaming, the client-disconnect
      // abort below takes over (a vanished agent frees the upstream stream too).
      const ac = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; ac.abort(); }, upstreamTimeoutMs);
      res.on('close', () => ac.abort());
      let up;
      try {
        up = await fetch(url, { method: req.method, headers, body, redirect: 'manual', duplex: body ? 'half' : undefined, signal: ac.signal });
      } catch (e) {
        if (timedOut) {
          audit.record({ event: 'deny', lease: fp, reason: 'timeout', via: 'broker' });
          onLog(`${req.method} ${fp} → ${new URL(url).host}${canon.path} timeout after ${upstreamTimeoutMs}ms`);
          return send(res, 504, { error: 'keeper broker: upstream timeout' }); // never the secret or raw lease id
        }
        if (res.destroyed || res.writableEnded) return; // client hung up first — no one left to answer
        throw e; // → the existing 502 contract below
      } finally { clearTimeout(timer); }
      onLog(`${req.method} ${fp} → ${new URL(url).host}${canon.path} ${up.status}`); // never the secret or raw lease

      // Relay the response, redacting the secret anywhere the upstream reflected
      // it. One audit event per request per surface (header/body) — a reflected
      // secret is an incident worth seeing in the log, not just silently fixed.
      const scan = typeof r.value === 'string' && r.value.length >= MIN_SCAN_LEN ? r.value : null;
      res.statusCode = up.status;
      let headerHit = false;
      up.headers.forEach((v, k) => {
        if (DROP.has(k.toLowerCase()) || RESP_DROP.has(k.toLowerCase())) return;
        if (scan && v.includes(scan)) { headerHit = true; v = v.split(scan).join(REDACTED); }
        res.setHeader(k, v);
      });
      if (headerHit) audit.record({ event: 'sanitize', lease: fp, where: 'header', via: 'broker' });
      if (!up.body) return res.end();
      // The client-disconnect abort above errors this stream mid-relay (as does
      // an upstream reset) — without a handler that's an uncaught 'error' that
      // takes the whole broker down. There's nothing left to relay: just stop.
      const upBody = Readable.fromWeb(up.body);
      upBody.on('error', () => res.destroy());
      if (!scan) return void upBody.pipe(res);
      upBody
        .pipe(redactStream(Buffer.from(scan), () => audit.record({ event: 'sanitize', lease: fp, where: 'body', via: 'broker' })))
        .pipe(res);
    } catch (e) {
      send(res, 502, { error: 'keeper broker: ' + ((e && e.message) || String(e)) });
    }
  });
  server.listen(port, host, () => onLog(`keeper broker on http://${host}:${server.address().port} — point your client base URL at http://${host}:${server.address().port}/<lease>`));
  return server;
}
