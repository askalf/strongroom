// Capture the server's LIVE tools/list into mcp/tools.json — the exact
// agent-facing surface (names, descriptions, schemas) that truecopy pins and
// poison-scans in CI (mcp-gate.yml). Deterministic output: tools sorted by
// name, 2-space JSON, LF, trailing newline — truecopy hashes raw bytes, so
// serialization stability IS the contract.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Hermetic vault, same as smoke.mjs — the server boots with a throwaway
// KEEPER_HOME; no secret is needed just to enumerate tools.
const KEEPER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'strongroom-mcp-capture-'));
process.env.KEEPER_HOME = KEEPER_HOME;
delete process.env.KEEPER_PASSPHRASE;
delete process.env.KEEPER_KEYCHAIN;
delete process.env.KEEPER_DAEMON;

const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(here, 'server.mjs')],
  env: { ...process.env, KEEPER_HOME, STRONGROOM_BROKER_PORT: '0' },
  stderr: 'ignore',
});
const client = new Client({ name: 'capture-tools', version: '0.0.0' });
await client.connect(transport);
const { tools } = await client.listTools();
await client.close();

const stable = tools
  .map(({ name, description, inputSchema }) => ({ name, description, inputSchema }))
  .sort((a, b) => a.name.localeCompare(b.name));

const out = path.join(here, 'tools.json');
fs.writeFileSync(out, JSON.stringify({ server: '@askalf/strongroom-mcp', tools: stable }, null, 2) + '\n');
console.error(`[capture-tools] wrote ${out}: ${stable.length} tools (${stable.map((t) => t.name).join(', ')})`);
