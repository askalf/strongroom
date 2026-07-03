// A real MCP server (stdio transport) that holds NO raw API key.
//
// Its entire credential surface is two environment variables:
//   UPSTREAM_LEASE — an opaque keeper lease id (a capability, not a credential)
//   BROKER_URL     — the keeper egress broker's base URL
//
// Every outbound call goes through the broker, which checks the lease and
// injects the REAL key at the network boundary — so compromising this server
// process yields a scoped, expiring, revocable lease, never the key.
//
// It also demonstrates the credential-granting tool done RIGHT: when a client
// asks for upstream access, `get_upstream_credential` returns the LEASE-backed
// base URL — safe to land in agent context, history, and logs, because it is
// not a secret. An MCP tool that returned a raw key here would be writing that
// key into every caller's context window.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const LEASE = process.env.UPSTREAM_LEASE;
const BROKER = process.env.BROKER_URL;
if (!LEASE || !BROKER) {
  console.error('[status-mcp] missing UPSTREAM_LEASE / BROKER_URL');
  process.exit(2);
}
const base = `${BROKER}/${LEASE}`;

const server = new McpServer({ name: 'status-mcp', version: '1.0.0' });

server.registerTool(
  'deployment_status',
  {
    title: 'Deployment status',
    description: 'Fetch the current deployment status of a service from the status API.',
    inputSchema: { service: z.string().describe('Service name, e.g. "forge"') },
  },
  async ({ service }) => {
    const r = await fetch(`${base}/v1/status?service=${encodeURIComponent(service)}`);
    if (!r.ok) {
      return { content: [{ type: 'text', text: `upstream denied (${r.status})` }], isError: true };
    }
    const data = await r.json();
    return { content: [{ type: 'text', text: data.status }] };
  },
);

server.registerTool(
  'get_upstream_credential',
  {
    title: 'Get upstream credential (a lease, never a key)',
    description:
      'Returns a scoped, expiring, revocable base URL for direct upstream access. ' +
      'The raw API key is never returned — it never crosses the MCP wire.',
    inputSchema: {},
  },
  async () => ({
    content: [{
      type: 'text',
      text: JSON.stringify({
        kind: 'keeper-lease',
        base_url: base,
        note: 'path-scoped, expiring, revocable — a capability, not a credential',
      }),
    }],
  }),
);

await server.connect(new StdioServerTransport());
console.error('[status-mcp] up — keyless, lease-held');
