/**
 * mcp/vuln-server/index.js — MCP Server: Vulnerability Probing
 *
 * JSON-RPC over stdin/stdout.
 * Delegates to unifiedEngine.js — all scanning logic lives there.
 *
 * Tools: unified_scan, scan_endpoint
 */

import { createInterface } from 'readline';
import { runUnifiedScan, scanEndpoint } from '../../vuln/unifiedEngine.js';

const TOOLS = {
    unified_scan: async (args) => {
        const { target, endpoints = [], forms = [], vulnTypes = null } = args;
        if (!target) return { tool: 'unified_scan', success: false, output: [], error: 'target required' };
        const findings = await runUnifiedScan({ target, endpoints, forms, vulnTypes });
        return { tool: 'unified_scan', success: true, output: findings };
    },
    scan_endpoint: async (args) => {
        const { url, param, method, vulnTypes, target } = args;
        if (!url) return { tool: 'scan_endpoint', success: false, output: [], error: 'url required' };
        const findings = await scanEndpoint({ url, param, method, vulnTypes, target });
        return { tool: 'scan_endpoint', success: true, output: findings };
    },
};

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', async (line) => {
    let req;
    try { req = JSON.parse(line); } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
        return;
    }
    const { id, method, params } = req;
    if (method !== 'tools/call') {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } }) + '\n');
        return;
    }
    const { name, arguments: args = {} } = params || {};
    const handler = TOOLS[name];
    if (!handler) {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${name}` } }) + '\n');
        return;
    }
    try {
        const result = await handler(args);
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
    } catch (err) {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32603, message: err.message } }) + '\n');
    }
});
