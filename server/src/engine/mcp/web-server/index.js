/**
 * mcp/web-server/index.js — MCP Server: Web Crawling & Form Extraction
 *
 * JSON-RPC over stdin/stdout.
 * Tools: crawl, extract_forms, validate_endpoint
 *
 * SECURITY:
 *   - URL scope validation before crawl
 *   - No shell calls — uses axios for HTTP
 *   - Private IP ranges blocked
 */

import axios from 'axios';
import * as cheerio from 'cheerio';
import { createInterface } from 'readline';

const PRIVATE_RANGES = /^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0)/i;
const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function isAllowed(url, targetHost) {
    if (!url) return false;
    if (PRIVATE_RANGES.test(url)) return false;
    try {
        const u = new URL(url);
        return u.hostname === targetHost || u.hostname.endsWith(`.${targetHost}`);
    } catch { return false; }
}

const httpClient = axios.create({
    timeout: 10_000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RedVapt/1.0) AppleWebKit/537.36' },
    httpsAgent: new (await import('https')).Agent({ rejectUnauthorized: false }),
});

// ── Tool: crawl ───────────────────────────────────────────────────────────────
async function crawl({ url, maxPages = 30, maxDepth = 2 }) {
    if (!url || typeof url !== 'string') return { tool: 'crawl', success: false, output: null, error: 'url required' };
    if (PRIVATE_RANGES.test(url)) return { tool: 'crawl', success: false, output: null, error: 'private URL blocked' };

    let targetHost;
    try { targetHost = new URL(url).hostname; } catch { return { tool: 'crawl', success: false, output: null, error: 'invalid url' }; }

    const visited = new Set();
    const queue = [{ url, depth: 0 }];
    const endpoints = new Set();
    const forms = [];
    const jsFiles = new Set();
    let pagesVisited = 0;

    while (queue.length > 0 && pagesVisited < maxPages) {
        const { url: current, depth } = queue.shift();
        if (visited.has(current) || !isAllowed(current, targetHost)) continue;
        visited.add(current);
        pagesVisited++;

        try {
            const resp = await httpClient.get(current);
            const body = typeof resp.data === 'string' ? resp.data : '';
            const $ = cheerio.load(body);

            endpoints.add(current);

            // Extract links
            if (depth < maxDepth) {
                $('a[href]').each((_, el) => {
                    try {
                        const href = $(el).attr('href');
                        const abs = new URL(href, current).href;
                        if (isAllowed(abs, targetHost) && !visited.has(abs)) {
                            queue.push({ url: abs, depth: depth + 1 });
                            endpoints.add(abs);
                        }
                    } catch { /* skip invalid */ }
                });
            }

            // Extract forms
            $('form').each((_, el) => {
                const action = $(el).attr('action') || current;
                const method = ($(el).attr('method') || 'GET').toUpperCase();
                const inputs = [];
                $('input, select, textarea', el).each((_, inp) => {
                    const name = $(inp).attr('name');
                    const type = $(inp).attr('type') || 'text';
                    if (name) inputs.push({ name, type });
                });
                if (inputs.length > 0) {
                    let absAction = action;
                    try { absAction = new URL(action, current).href; } catch { /* keep as-is */ }
                    forms.push({ action: absAction, method, inputs, source: current });
                }
            });

            // Extract JS files
            $('script[src]').each((_, el) => {
                try {
                    const src = $(el).attr('src');
                    const abs = new URL(src, current).href;
                    jsFiles.add(abs);
                } catch { /* skip */ }
            });

        } catch { /* network error — skip this page */ }
    }

    return {
        tool: 'crawl',
        success: true,
        output: {
            endpoints: [...endpoints],
            forms,
            jsFiles: [...jsFiles],
            pagesVisited,
            summary: { totalEndpoints: endpoints.size, formsFound: forms.length, jsFilesFound: jsFiles.size },
        },
    };
}

// ── Tool: extract_forms ───────────────────────────────────────────────────────
async function extract_forms({ url }) {
    if (!url) return { tool: 'extract_forms', success: false, output: [], error: 'url required' };
    if (PRIVATE_RANGES.test(url)) return { tool: 'extract_forms', success: false, output: [], error: 'private URL blocked' };
    try {
        const resp = await httpClient.get(url);
        const body = typeof resp.data === 'string' ? resp.data : '';
        const $ = cheerio.load(body);
        const forms = [];
        $('form').each((_, el) => {
            const action = $(el).attr('action') || url;
            const method = ($(el).attr('method') || 'GET').toUpperCase();
            const inputs = [];
            $('input, select, textarea', el).each((_, inp) => {
                const name = $(inp).attr('name');
                const type = $(inp).attr('type') || 'text';
                if (name) inputs.push({ name, type });
            });
            if (inputs.length > 0) {
                let absAction = action;
                try { absAction = new URL(action, url).href; } catch { /* keep */ }
                forms.push({ action: absAction, method, inputs, is_high_value: inputs.some(i => /pass|auth|token|secret|admin/i.test(i.name)) });
            }
        });
        return { tool: 'extract_forms', success: true, output: forms };
    } catch (err) {
        return { tool: 'extract_forms', success: false, output: [], error: err.message?.slice(0, 200) };
    }
}

// ── Tool: validate_endpoint ───────────────────────────────────────────────────
async function validate_endpoint({ url }) {
    if (!url) return { tool: 'validate_endpoint', success: false, output: null, error: 'url required' };
    if (PRIVATE_RANGES.test(url)) return { tool: 'validate_endpoint', success: false, output: null, error: 'private URL blocked' };
    try {
        const start = Date.now();
        const resp = await httpClient.head(url);
        const elapsed = Date.now() - start;
        return {
            tool: 'validate_endpoint', success: true,
            output: {
                url, status: resp.status,
                content_type: resp.headers['content-type'] || null,
                server: resp.headers['server'] || null,
                elapsed_ms: elapsed,
                is_live: resp.status < 400,
            },
        };
    } catch (err) {
        return { tool: 'validate_endpoint', success: false, output: null, error: err.message?.slice(0, 200) };
    }
}

// ── Tool dispatch ─────────────────────────────────────────────────────────────
const TOOLS = { crawl, extract_forms, validate_endpoint };

// ── JSON-RPC stdio loop ───────────────────────────────────────────────────────
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
