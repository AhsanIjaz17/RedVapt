/**
 * utils/directoryBrute.js — Directory Brute-Force Tool (FFUF via MCP)
 */

import { mcpCall } from '../engine/mcp/mcpSessionClient.js';

export const schema = {
    description: "Brute-force common directories and files on a target web server.",
    parameters: {
        type: "object",
        properties: {
            domain: { type: "string", description: "Target domain (no protocol)" },
            wordlist: { type: "string", description: "Optional absolute path to wordlist" }
        },
        required: ["domain"]
    }
};

export async function execute({ domain, wordlist }) {
    const result = await mcpCall('recon-server', 'ffuf', { domain, wordlist });
    if (!result || !result.success) {
        return { found: [], error: result?.error || 'ffuf not available' };
    }
    return { found: result.output || [], summary: `${(result.output || []).length} paths discovered.` };
}
