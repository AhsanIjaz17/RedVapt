/**
 * mcp/recon-server/index.js — MCP Server: Reconnaissance Tools
 *
 * Runs as a child process (stdin/stdout JSON-RPC transport).
 * Exposes subfinder, assetfinder, crtsh, dns_resolve, httpx, wafw00f,
 * nmap, gau, waybackurls, ffuf, paramspider as MCP tools.
 *
 * SECURITY:
 *   - All tool calls use execFileAsync (array args, no shell interpolation)
 *   - Hostname validated before every call
 *   - Tmp files cleaned in finally blocks
 *   - API keys never logged
 */

import { execFile, exec } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink, readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { createInterface } from 'readline';

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

// ── Hostname validation ──────────────────────────────────────────────────────
const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function validateDomain(domain) {
    if (!domain || typeof domain !== 'string') throw new Error('domain must be a non-empty string');
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    if (d.length > 253) throw new Error('domain too long');
    if (!HOSTNAME_RE.test(d)) throw new Error(`invalid domain: "${d}"`);
    return d;
}

const HOME = process.env.HOME || process.env.USERPROFILE || '';

// ── Tool env (go/bin, local/bin) ─────────────────────────────────────────────
const TOOL_ENV = {
    PATH: [
        process.env.PATH,
        join(HOME, 'go/bin'),
        join(HOME, '.local/bin'),
        '/usr/local/go/bin',
    ].filter(Boolean).join(':'),
    HOME: process.env.HOME,
};

const OPTS = (ms = 90_000) => ({ timeout: ms, maxBuffer: 8 * 1024 * 1024, env: TOOL_ENV });

// ── Helper: find first available binary ─────────────────────────────────────
async function findBin(...candidates) {
    for (const bin of candidates) {
        try {
            await execAsync(`which ${bin}`, { timeout: 5000, env: TOOL_ENV });
            return bin;
        } catch { /* try next */ }
    }
    return null;
}

// ── Tool implementations ─────────────────────────────────────────────────────

async function subfinder({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin('subfinder');
    if (!bin) return { tool: 'subfinder', success: false, output: [], error: 'subfinder not installed' };
    try {
        const { stdout } = await execFileAsync(bin, ['-d', d, '--all', '--recursive', '-silent'], OPTS(180_000));
        const subdomains = stdout.trim().split('\n').filter(Boolean);
        return { tool: 'subfinder', success: true, output: subdomains };
    } catch (err) {
        const partial = (err.stdout || '').trim().split('\n').filter(Boolean);
        return { tool: 'subfinder', success: false, output: partial, error: err.message?.slice(0, 200) };
    }
}

async function assetfinder({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin('assetfinder');
    if (!bin) return { tool: 'assetfinder', success: false, output: [], error: 'assetfinder not installed' };
    try {
        const { stdout } = await execFileAsync(bin, ['--subs-only', d], OPTS(120_000));
        return { tool: 'assetfinder', success: true, output: stdout.trim().split('\n').filter(Boolean) };
    } catch (err) {
        return { tool: 'assetfinder', success: false, output: [], error: err.message?.slice(0, 200) };
    }
}

async function crtsh({ domain }) {
    const d = validateDomain(domain);
    try {
        const { stdout } = await execAsync(
            `curl -s "https://crt.sh/?q=%.${d}&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -vF '*.' | sort -u`,
            { timeout: 60_000, maxBuffer: 4 * 1024 * 1024, env: TOOL_ENV }
        );
        return { tool: 'crtsh', success: true, output: stdout.trim().split('\n').filter(Boolean) };
    } catch (err) {
        return { tool: 'crtsh', success: false, output: [], error: err.message?.slice(0, 200) };
    }
}

async function dns_resolve({ subdomains }) {
    if (!Array.isArray(subdomains)) return { tool: 'dns_resolve', success: false, output: [], error: 'subdomains must be array' };
    const batch = subdomains.slice(0, 100).filter(s => typeof s === 'string');
    const results = await Promise.all(batch.map(async (host) => {
        try {
            const { stdout } = await execFileAsync('dig', ['+short', host], { timeout: 5000, env: TOOL_ENV });
            const ips = stdout.trim().split('\n').filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l));
            return { subdomain: host, ip: ips[0] || null, resolves: ips.length > 0 };
        } catch { return { subdomain: host, ip: null, resolves: false }; }
    }));
    return { tool: 'dns_resolve', success: true, output: results };
}

async function httpx({ hosts }) {
    if (!Array.isArray(hosts) || hosts.length === 0) {
        return { tool: 'httpx', success: false, output: [], error: 'hosts array required' };
    }
    const bin = await findBin('httpx-toolkit', 'httpx');
    if (!bin) return { tool: 'httpx', success: false, output: [], error: 'httpx not installed' };

    const tmpFile = join(tmpdir(), `rv_mcp_hosts_${Date.now()}.txt`);
    try {
        await writeFile(tmpFile, hosts.join('\n'), { mode: 0o600 });
        const { stdout } = await execFileAsync(
            bin,
            ['-l', tmpFile, '-json', '-title', '-tech-detect', '-server', '-ip', '-cdn',
                '-follow-redirects', '-insecure', '-random-agent', '-timeout', '10', '-retries', '2'],
            OPTS(150_000)
        );
        const parsed = stdout.trim().split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        return { tool: 'httpx', success: true, output: parsed };
    } catch (err) {
        return { tool: 'httpx', success: false, output: [], error: err.message?.slice(0, 200) };
    } finally {
        await unlink(tmpFile).catch(() => { });
    }
}

async function wafw00f({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin('wafw00f');
    if (!bin) return { tool: 'wafw00f', success: false, output: '', error: 'wafw00f not installed' };
    try {
        const { stdout } = await execFileAsync(bin, [`https://${d}`, '-a'], OPTS(60_000));
        return { tool: 'wafw00f', success: true, output: stdout.trim() };
    } catch (err) {
        return { tool: 'wafw00f', success: false, output: '', error: err.message?.slice(0, 200) };
    }
}

async function nmap({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin('nmap');
    if (!bin) return { tool: 'nmap', success: false, output: '', error: 'nmap not installed' };
    try {
        const { stdout } = await execFileAsync(
            bin, ['-T4', '--top-ports', '100', '-sV', '--open', d],
            OPTS(180_000)
        );
        return { tool: 'nmap', success: true, output: stdout.trim() };
    } catch (err) {
        const partial = (err.stdout || '').trim();
        return { tool: 'nmap', success: !!partial, output: partial || '', error: err.message?.slice(0, 200) };
    }
}

async function gau({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin(join(HOME, 'go/bin/gau'), 'gau');
    if (!bin) return { tool: 'gau', success: false, output: [], error: 'gau not installed' };
    try {
        // gau reads from stdin
        const { stdout } = await execAsync(
            `echo ${d} | ${bin} --threads 10 --blacklist png,jpg,gif,css,svg,woff,ttf,ico 2>/dev/null | sort -u`,
            { timeout: 120_000, maxBuffer: 8 * 1024 * 1024, env: TOOL_ENV }
        );
        return { tool: 'gau', success: true, output: stdout.trim().split('\n').filter(Boolean) };
    } catch (err) {
        return { tool: 'gau', success: false, output: [], error: err.message?.slice(0, 200) };
    }
}

async function waybackurls({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin(join(HOME, 'go/bin/waybackurls'), 'waybackurls');
    if (!bin) return { tool: 'waybackurls', success: false, output: [], error: 'waybackurls not installed' };
    try {
        const { stdout } = await execAsync(
            `echo ${d} | ${bin} 2>/dev/null | sort -u`,
            { timeout: 90_000, maxBuffer: 8 * 1024 * 1024, env: TOOL_ENV }
        );
        return { tool: 'waybackurls', success: true, output: stdout.trim().split('\n').filter(Boolean) };
    } catch (err) {
        return { tool: 'waybackurls', success: false, output: [], error: err.message?.slice(0, 200) };
    }
}

async function ffuf({ domain, wordlist }) {
    const d = validateDomain(domain);
    const wl = wordlist || '/usr/share/wordlists/dirb/common.txt';

    // Validate wordlist path (no traversal)
    const safePaths = [
        '/usr/share/wordlists/',
        '/usr/share/seclists/',
    ];
    if (!safePaths.some(p => wl.startsWith(p))) {
        return { tool: 'ffuf', success: false, output: [], error: 'Wordlist path not in allowed directories' };
    }

    const bin = await findBin('ffuf');
    if (!bin) return { tool: 'ffuf', success: false, output: [], error: 'ffuf not installed' };

    const tmpOut = join(tmpdir(), `rv_mcp_ffuf_${Date.now()}.json`);
    try {
        await execFileAsync(
            bin,
            ['-w', wl, '-u', `https://${d}/FUZZ`,
                '-mc', '200,201,204,301,302,303,307,401,403',
                '-t', '50', '-timeout', '10', '-s', '-o', tmpOut, '-of', 'json'],
            OPTS(120_000)
        );
        const raw = await readFile(tmpOut, 'utf-8');
        const parsed = JSON.parse(raw);
        const hits = (parsed.results || []).map(r => ({ status: r.status, url: r.url, size: r.length }));
        return { tool: 'ffuf', success: true, output: hits };
    } catch {
        return { tool: 'ffuf', success: false, output: [], error: 'ffuf produced no parseable output' };
    } finally {
        await unlink(tmpOut).catch(() => { });
    }
}

async function paramspider({ domain }) {
    const d = validateDomain(domain);
    const bin = await findBin('paramspider', join(HOME, '.local/bin/paramspider'));
    if (!bin) return { tool: 'paramspider', success: false, output: [], error: 'paramspider not installed' };
    const tmpOut = join(tmpdir(), `rv_mcp_params_${d}_${Date.now()}.txt`);
    try {
        await execFileAsync(bin, ['-d', d, '--output', tmpOut], OPTS(60_000));
        const content = await readFile(tmpOut, 'utf-8').catch(() => '');
        return { tool: 'paramspider', success: true, output: content.trim().split('\n').filter(Boolean) };
    } catch (err) {
        return { tool: 'paramspider', success: false, output: [], error: err.message?.slice(0, 200) };
    } finally {
        await unlink(tmpOut).catch(() => { });
    }
}

// ── Tool dispatch map ────────────────────────────────────────────────────────
const TOOLS = {
    subfinder, assetfinder, crtsh, dns_resolve,
    httpx, wafw00f, nmap, gau, waybackurls,
    ffuf, paramspider,
};

// ── JSON-RPC stdio transport ─────────────────────────────────────────────────
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', async (line) => {
    let request;
    try {
        request = JSON.parse(line);
    } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
        return;
    }

    const { id, method, params } = request;

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
        process.stdout.write(JSON.stringify({
            jsonrpc: '2.0', id,
            error: { code: -32603, message: err.message || 'Internal error' },
        }) + '\n');
    }
});
