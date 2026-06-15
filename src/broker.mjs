// Egress-injection broker. The agent points its HTTP client's base URL at
//   http://127.0.0.1:<port>/<lease>
// and makes normal API calls with NO key. For each request the broker redeems
// the lease (atomic + audited), then makes the real upstream request itself —
// injecting the secret into a header at the network boundary. The secret never
// enters the agent's context, and because the lease is BOUND to one upstream,
// it can only ever be injected toward that host (not an attacker URL).
//
// Local-only (127.0.0.1), plaintext HTTP to the agent, real HTTPS upstream.
import http from 'node:http';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { redeem } from './index.mjs';

// Hop-by-hop + auth headers we never pass through from the agent (we inject auth).
const DROP = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te',
  'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'authorization', 'x-api-key', 'cookie',
]);

const fpLease = (id) => crypto.createHash('sha256').update(id).digest('hex').slice(0, 12);

function injectAuth(headers, inject, secret) {
  const spec = inject || 'bearer';
  if (spec === 'bearer') headers['authorization'] = 'Bearer ' + secret;
  else if (spec === 'x-api-key') headers['x-api-key'] = secret;
  else headers[String(spec).toLowerCase()] = secret; // custom header name → secret value
}

async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined;
  const chunks = [];
  for await (const ch of req) chunks.push(ch);
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

const send = (res, code, obj) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(obj)); };

export function startBroker({ port = 8771, host = '127.0.0.1', onLog = () => {} } = {}) {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.url === '/' || req.url === '/healthz') return send(res, 200, { ok: true, service: 'keeper-broker' });
      const m = req.url.match(/^\/([^/?]+)(.*)$/);
      if (!m) return send(res, 400, { error: 'keeper: expected /<lease>/<path>' });
      const lease = m[1], rest = m[2] || '/';

      const body = await readBody(req);
      const r = redeem(lease); // atomic check-and-consume + audit; consumes a use
      if (!r.ok) return send(res, 403, { error: 'keeper: denied (' + r.reason + ')' });
      if (!r.upstream) return send(res, 400, { error: 'keeper: lease is not bound to an upstream (grant with --upstream)' });

      const url = r.upstream.replace(/\/$/, '') + rest;
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k.toLowerCase())) headers[k] = v;
      injectAuth(headers, r.inject, r.value); // the only place the real secret touches the request

      const up = await fetch(url, { method: req.method, headers, body, redirect: 'manual', duplex: body ? 'half' : undefined });
      onLog(`${req.method} ${fpLease(lease)} → ${new URL(url).host} ${up.status}`); // never the secret or raw lease

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
