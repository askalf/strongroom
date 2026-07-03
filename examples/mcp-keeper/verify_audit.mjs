// Re-verify the audit chain a demo run left behind, then prove it is actually
// tamper-evident: a mid-chain edit and a tail truncation must BOTH be caught.
//
//   node verify_audit.mjs keeper-home
//
// keeper's audit is warden's hash-chained file audit plus an AUTHENTICATED TIP:
// an HMAC (keyed by a subkey of the vault master key) over the chain's length
// and last hash. The keyless chain catches mid-chain edits; the tip closes the
// two holes a bare chain leaves open — tail truncation and a splice re-rooted
// at genesis.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const homeArg = process.argv[2] || 'keeper-home';
const HOME = path.resolve(homeArg);
if (!fs.existsSync(path.join(HOME, 'audit.jsonl'))) {
  console.error(`no audit at ${HOME} — run \`npm run demo\` first`);
  process.exit(2);
}

const ok = (cond, msg) => {
  if (!cond) { console.error('FAIL: ' + msg); process.exit(1); }
  console.log('   ✓ ' + msg);
};

// keeper resolves its home from the env per call, so one process can verify
// the real home and the tampered copies in turn.
process.env.KEEPER_HOME = HOME;
delete process.env.KEEPER_PASSPHRASE;
delete process.env.KEEPER_KEYCHAIN;
const { audit } = await import('../../src/index.mjs');

console.log('1. verify the untouched audit');
const clean = audit.verify();
ok(clean.ok === true, `chain + authenticated tip intact (${clean.entries} entries)`);

const copyHome = (name) => {
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), name));
  fs.cpSync(HOME, dst, { recursive: true });
  return dst;
};

console.log('2. tamper mid-chain: flip one byte of an early entry');
const edited = copyHome('keeper-audit-edit-');
const auditPath = path.join(edited, 'audit.jsonl');
const lines = fs.readFileSync(auditPath, 'utf8').split('\n');
lines[1] = lines[1].replace(/"event":"/, '"event":"X');
fs.writeFileSync(auditPath, lines.join('\n'));
process.env.KEEPER_HOME = edited;
ok(audit.verify().ok === false, 'edited chain FAILS verification');

console.log('3. truncate the tail: drop the last entry, keep everything else');
const truncated = copyHome('keeper-audit-trunc-');
const tPath = path.join(truncated, 'audit.jsonl');
const tLines = fs.readFileSync(tPath, 'utf8').split('\n').filter((l) => l.trim());
fs.writeFileSync(tPath, tLines.slice(0, -1).join('\n') + '\n');
process.env.KEEPER_HOME = truncated;
const trunc = audit.verify();
ok(trunc.ok === false, `truncated chain FAILS verification (${trunc.reason})`);

fs.rmSync(edited, { recursive: true, force: true });
fs.rmSync(truncated, { recursive: true, force: true });
console.log('\nAUDIT_VERIFY_PASS');
