import os from 'node:os';
import path from 'node:path';

// Everything lives under ~/.keeper (override with KEEPER_HOME). The master key,
// the encrypted vault, the leases, and the tamper-evident audit are all 0600.
export const home = () => process.env.KEEPER_HOME || path.join(os.homedir(), '.keeper');
export const kpath = (f) => path.join(home(), f);
