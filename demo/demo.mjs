// keeper demo — the agent never holds the raw key.  node demo/demo.mjs
import os from 'node:os';
import path from 'node:path';
process.env.KEEPER_HOME = path.join(os.tmpdir(), 'keeper-demo-' + process.pid);
import { addSecret, grant, redeem, vault, audit } from '../src/index.mjs';

const line = (s = '') => console.log(s);

line('── store a secret (encrypted at rest) ─────────────────────');
addSecret('OPENAI_API_KEY', 'sk-live-REALSECRET-do-not-leak');
line(`  vault: ${vault.listSecrets().join(', ')}   (values are AES-256-GCM, never plaintext)`);

line('\n── grant the agent a scoped, single-use lease ─────────────');
const l = grant('OPENAI_API_KEY', { ttlS: 300, uses: 1, host: 'api.openai.com' });
line(`  the agent receives:  ${l.id}`);
line(`  …which is NOT the key. It is bound to 1 use · 300s · host api.openai.com.`);

line('\n── redeem at the egress point (only here is the key revealed) ─');
const ok = redeem(l.id, { host: 'api.openai.com' });
line(`  redeem (correct host) → ${ok.ok ? ok.value : 'denied'}`);
const again = redeem(l.id, { host: 'api.openai.com' });
line(`  redeem again          → ${again.ok ? again.value : 'DENIED: ' + again.reason}   (single-use spent)`);

line('\n── the lease cannot be used off-scope ─────────────────────');
const l2 = grant('OPENAI_API_KEY', { uses: 1, host: 'api.openai.com' });
const wrong = redeem(l2.id, { host: 'attacker.example' });
line(`  redeem (wrong host)   → DENIED: ${wrong.reason}`);

line('\n── every access is in a tamper-evident audit ──────────────');
for (const e of audit.read()) line(`  ${e.event.padEnd(6)} ${e.secret || e.lease || ''}${e.reason ? ' (' + e.reason + ')' : ''}${e.host ? ' · ' + e.host : ''}`);
const v = audit.verify();
line(`\n  ${v.ok ? '✓ audit chain intact (' + v.entries + ' entries)' : '✗ tampered'} — the agent ran on leases; the key never entered its context.`);
