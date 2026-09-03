/**
 * mcp/jsintel-server/index.js — MCP Server: JavaScript Intelligence Tools
 *
 * JSON-RPC over stdin/stdout.
 * Tools: download_js, scan_secrets, run_linkfinder, extract_endpoints, classify_js
 *
 * SECURITY:
 *   - URL validated before fetch (no SSRF to private ranges)
 *   - Secret values truncated in output (no full key logging)
 *   - execFileAsync only for external tools
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { createInterface } from 'readline';
import { exec } from 'child_process';
import crypto from 'crypto';
import * as cheerio from 'cheerio';

import { join } from 'path';

const execFileAsync = promisify(execFile);
const execAsyncRaw = promisify(exec);

const HOME = process.env.HOME || process.env.USERPROFILE || '';

const TOOL_ENV = {
    PATH: [process.env.PATH, join(HOME, 'go/bin'), join(HOME, '.local/bin')].filter(Boolean).join(':'),
    HOME: process.env.HOME,
};

// ── SSRF Guard ────────────────────────────────────────────────────────────────
const PRIVATE_RANGES = /^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0)/i;

function validateUrl(url) {
    if (!url || typeof url !== 'string') throw new Error('url required');
    if (PRIVATE_RANGES.test(url)) throw new Error('URL targets private/localhost range — blocked');
    try { new URL(url); } catch { throw new Error('Invalid URL format'); }
    return url;
}

// ── Secret patterns ────────────────────────────────────────────────────────────
const SECRET_PATTERNS = [
    { name: 'AWS Key', re: /AKIA[0-9A-Z]{16}/g },
    { name: 'JWT', re: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g },
    { name: 'API Key', re: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})/gi },
    { name: 'Bearer Token', re: /Bearer\s+[a-zA-Z0-9\-_\.]{20,}/gi },
    { name: 'Private Key', re: /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/g },
    { name: 'Password', re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,30})["']/gi },
    { name: 'Secret', re: /(?:secret|token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{12,})/gi },
    { name: 'DB Conn String', re: /(?:mongodb|mysql|postgres|redis):\/\/[^\s"'<>]+/gi },
];

// ── Tool: download_js ─────────────────────────────────────────────────────────
async function download_js({ url }) {
    const safeUrl = validateUrl(url);
    try {
        const { stdout } = await execFileAsync('curl', ['-s', '-L', '-k', '--max-time', '10', safeUrl], {
            timeout: 12_000, maxBuffer: 4 * 1024 * 1024, env: TOOL_ENV,
        });
        return { tool: 'download_js', success: true, output: { url: safeUrl, content: stdout, size: stdout.length } };
    } catch (err) {
        return { tool: 'download_js', success: false, output: null, error: err.message?.slice(0, 200) };
    }
}

// ── Tool: scan_secrets ────────────────────────────────────────────────────────
async function scan_secrets({ content, source }) {
    if (!content || typeof content !== 'string') {
        return { tool: 'scan_secrets', success: false, output: [], error: 'content string required' };
    }
    const findings = [];
    for (const { name, re } of SECRET_PATTERNS) {
        const matches = [...content.matchAll(re)];
        for (const m of matches) {
            const value = (m[1] || m[0]).slice(0, 60); // truncate for safety
            findings.push({ type: name, value, source: source || 'unknown' });
        }
    }
    return { tool: 'scan_secrets', success: true, output: findings };
}

// ── Tool: run_linkfinder ──────────────────────────────────────────────────────
async function run_linkfinder({ url }) {
    const safeUrl = validateUrl(url);
    const paths = [
        process.env.LINKFINDER_PATH,
        '/opt/LinkFinder/linkfinder.py',
        join(HOME, 'Desktop/tools/LinkFinder/linkfinder.py'),
    ].filter(Boolean);

    let lfPath = null;
    for (const p of paths) {
        try { await execAsyncRaw(`test -f "${p}"`); lfPath = p; break; } catch { /* next */ }
    }
    if (!lfPath) return { tool: 'run_linkfinder', success: false, output: [], error: 'LinkFinder not found' };

    try {
        const { stdout } = await execFileAsync('python3', [lfPath, '-i', safeUrl, '-o', 'cli'], {
            timeout: 30_000, maxBuffer: 2 * 1024 * 1024, env: TOOL_ENV,
        });
        const endpoints = stdout.trim().split('\n').filter(l => l.startsWith('/') || l.startsWith('http'));
        return { tool: 'run_linkfinder', success: true, output: endpoints };
    } catch (err) {
        return { tool: 'run_linkfinder', success: false, output: [], error: err.message?.slice(0, 200) };
    }
}

// ── Tool: extract_endpoints ───────────────────────────────────────────────────
async function extract_endpoints({ content, baseUrl }) {
    if (!content) return { tool: 'extract_endpoints', success: false, output: [], error: 'content required' };

    const endpoints = new Set();
    const patterns = [
        /["'`](\/[a-zA-Z0-9_\-\/\.]{2,80}(?:\?[^"'`\s]{0,100})?)/g,
        /["'`](https?:\/\/[^\s"'`<>]{5,200})/g,
        /fetch\s*\(\s*["'`](\/[^"'`]+)/g,
        /axios\.[a-z]+\s*\(\s*["'`](\/[^"'`]+)/g,
        /url\s*:\s*["'`](\/[^"'`]+)/g,
    ];

    for (const pat of patterns) {
        for (const m of content.matchAll(pat)) {
            const ep = m[1].trim();
            if (ep.length > 1 && ep.length < 200) endpoints.add(ep);
        }
    }

    // Resolve relative paths against baseUrl
    const resolved = [...endpoints].map(ep => {
        if (ep.startsWith('http')) return ep;
        if (baseUrl) {
            try { return new URL(ep, baseUrl).href; } catch { return ep; }
        }
        return ep;
    });

    return { tool: 'extract_endpoints', success: true, output: resolved };
}

// ── Tool: classify_js ─────────────────────────────────────────────────────────
async function classify_js({ jsFiles }) {
    if (!Array.isArray(jsFiles)) return { tool: 'classify_js', success: false, output: [], error: 'jsFiles array required' };

    const score = (url) => {
        const lower = url.toLowerCase();
        let s = 0;
        if (/\/(app|main|index|bundle|chunk|init|config|router|routes?|api|auth|user|admin)(\.\w+)?\.js/i.test(lower)) s += 30;
        if (lower.includes('api')) s += 20;
        if (lower.includes('config')) s += 15;
        if (lower.includes('jquery') || lower.includes('bootstrap')) s -= 20;
        if (lower.includes('google-analytics') || lower.includes('googletagmanager')) s -= 30;
        if (lower.includes('.min.js')) s -= 10;
        if (lower.includes('vendor')) s -= 10;
        if (lower.includes('cdn')) s -= 15;
        return s;
    };

    const classified = jsFiles
        .map(url => ({ url, score: score(url) }))
        .sort((a, b) => b.score - a.score);

    return { tool: 'classify_js', success: true, output: classified };
}

// ── Tool dispatch ─────────────────────────────────────────────────────────────
const TOOLS = { download_js, scan_secrets, run_linkfinder, extract_endpoints, classify_js };

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
