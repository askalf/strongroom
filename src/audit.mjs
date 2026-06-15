// Tamper-evident audit of every secret access — reuses warden's hash-chained
// audit (the shared security-stack primitive). Each grant / redeem / deny /
// revoke is chained, so a deleted or edited entry breaks verification.
import fs from 'node:fs';
import { ChainedFileAudit, verifyAuditFile } from '@askalf/warden/audit';
import { home, kpath } from './paths.mjs';

// Stateless per call (a CLI invocation = one event): each record re-seeds from
// the file's last hash, so the chain is correct regardless of process lifetime.
export function record(event) {
  fs.mkdirSync(home(), { recursive: true });
  return new ChainedFileAudit(kpath('audit.jsonl')).record({ ts: new Date().toISOString(), ...event });
}

export const verify = () => verifyAuditFile(kpath('audit.jsonl'));

export function read() {
  try {
    return fs.readFileSync(kpath('audit.jsonl'), 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch { return []; }
}
