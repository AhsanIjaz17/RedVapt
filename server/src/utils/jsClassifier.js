/**
 * utils/jsClassifier.js — MCP Wrapper for JS Classification
 *
 * Delegating to the 'jsintel-server' MCP tool: classify_js.
 */

import { mcpCall } from '../engine/mcp/mcpSessionClient.js';

/**
 * Classify a list of JS URLs by exploitation value.
 * 
 * @param {string[]} jsFiles - Array of JS URLs
 * @returns {Promise<Array>} Classified files with scores
 */
export async function classifyJsFiles(jsFiles) {
    if (!jsFiles || jsFiles.length === 0) return [];

    console.log(`[jsClassifier] Delegating classification of ${jsFiles.length} files to MCP jsintel-server...`);

    const result = await mcpCall('jsintel-server', 'classify_js', {
        jsFiles
    });

    if (!result.success) {
        console.warn(`[jsClassifier] Warning: ${result.error}`);
        // Fallback: return unscored
        return jsFiles.map(url => ({ url, score: 0 }));
    }

    return result.output;
}
