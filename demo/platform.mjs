// keeper in the platform — the fleet ships a LEASE, not a key, so the device
// never holds the credential (even if it is compromised, OpenClaw-style).
//   node demo/platform.mjs
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-platform-' + process.pid);
import { addSecret, grant, revoke } from '../src/index.mjs';
import { startBroker } from '../src/broker.mjs';

const L = (s = '') => console.log(s);
const listen = (s) => new Promise((r) => s.on('listening', () => r(s.address().port)));

// a stub upstream "API" that echoes the credential it received
const api = http.createServer((req, res) => res.end(JSON.stringify({ sawKey: req.headers['authorization'] || null })));
api.listen(0, '127.0.0.1');
const apiPort = await listen(api);

L('keeper in the platform — the fleet ships a lease, not a key\n');

// ── FLEET ── stores the task secret in keeper, grants a SCOPED lease, dispatches only the lease
addSecret('TASK_API_KEY', 'sk-live-PRODUCTION-KEY');
const l = grant('TASK_API_KEY', { ttlS: 300, uses: 50, upstream: `http://127.0.0.1:${apiPort}`, inject: 'bearer', paths: ['/v1/*'] });
L('[fleet]   stored the task key in keeper; granted a scoped lease (5 min, 50 uses, /v1/* only)');
L('[fleet]   dispatches to the device:  ' + l.id);
L('          (the platform today writes the raw key to ~/.claude/.credentials.json — plaintext on the device)\n');

// ── DEVICE ── what lands on the device is the LEASE, not the key
const deviceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keeper-device-')); // 0700, unpredictable name
const disk = path.join(deviceDir, 'device-creds.txt');
fs.writeFileSync(disk, l.id);
const broker = startBroker({ port: 0 });
const bport = await listen(broker);
L('[device]  on-disk credential file holds:  ' + fs.readFileSync(disk, 'utf8'));
L('[device]  runs its API call through the local keeper broker (no key in the agent process) ...');
const r1 = await (await fetch(`http://127.0.0.1:${bport}/${l.id}/v1/models`)).json();
L('[api]     upstream received:  ' + r1.sawKey + '   <- the real key, injected at egress\n');

// ── COMPROMISE ── pop the device and you get a lease, not a key
L('[attack]  device compromised. The attacker reads the disk and finds:');
L('          ' + fs.readFileSync(disk, 'utf8') + '   — a scoped, expiring, revocable lease. NOT the key.\n');

// ── RESPONSE ── revoke; the lease dies, the production key never rotates
revoke(l.id);
const r2 = await fetch(`http://127.0.0.1:${bport}/${l.id}/v1/models`);
L('[fleet]   revokes the lease -> next call: HTTP ' + r2.status + '   (the production key never had to rotate)');

api.close(); broker.close();
try { fs.unlinkSync(disk); } catch {}
