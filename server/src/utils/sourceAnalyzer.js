/**
 * utils/sourceAnalyzer.js — JS Source Analysis Tool (MCP jsintel-server)
 *
 * Downloads a JS file and extracts: endpoints, secrets, API paths.
 */

import { mcpCall } from '../engine/mcp/mcpSessionClient.js';

export const schema = {
    description: "Analyze a JavaScript file for hidden API endpoints, secrets, and authentication tokens.",
    parameters: {
        type: "object",
        properties: {
            url: { type: "string", description: "URL of the JavaScript file to analyze" }
        },
        required: ["url"]
    }
};

export async function execute({ url }) {
    // Step 1: download the JS file
    const download = await mcpCall('jsintel-server', 'download_js', { url });
    if (!download || !download.success) {
        return { url, endpoints: [], secrets: [], error: download?.error || 'Failed to download JS' };
    }
    const { content } = download.output;

    // Step 2: run in parallel — endpoint extraction + secret scanning
    const [epResult, secretResult] = await Promise.all([
        mcpCall('jsintel-server', 'extract_endpoints', { content, baseUrl: url }),
        mcpCall('jsintel-server', 'scan_secrets', { content, source: url }),
    ]);

    return {
        url,
        endpoints: epResult.success ? epResult.output : [],
        secrets: secretResult.success ? secretResult.output : [],
        summary: `${epResult.output?.length ?? 0} endpoints, ${secretResult.output?.length ?? 0} secrets found.`,
    };
}
