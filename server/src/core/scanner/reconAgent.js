/**
 * reconAgent.js — RedVapt Reconnaissance Agent (v4)
 *
 * 5-PHASE METHODOLOGY:
 * Phase 1 — Asset Discovery   (sublist3r, subfinder, assetfinder, crt.sh)
 * Phase 2 — Normalization     (DNS resolve, deduplicate)
 * Phase 3 — Service Discovery (httpx, wafw00f, wappalyzer)
 * Phase 4 — Infrastructure    (nmap)
 * Phase 5 — Surface Expansion (subjs, getJS, gau, waybackurls, LinkFinder,
 *                               ParamSpider, FFUF, JS Classification)
 *
 * SECURITY: execAsync only receives validated hostnames — no user-controlled shell chars.
 * All resolved data is returned as structured reportData for the ReAct agent.
 */

import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import { AsyncLocalStorage } from 'async_hooks';
import { writeFile, unlink, readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { scoreEndpoints, buildIntelligenceSummary } from '../../engine/vuln/unifiedIntelligence.js';
import config from '../../utils/env.js';
import { RECON, TIMEOUTS } from '../../utils/constants.js';

import { createScanDB } from '../../utils/db.js';
import {
  parseSubfinder,
  parseWaybackurlsEndpoints,
  parseDnsResolve,
  parseHttpx,
  parseHttpxJson,
  parseWafw00f,
  parseNmap,
  parseGauEndpoints,
  parseLinkFinder,
  parseParamSpider,
  parseSubjs,
  parseGetjs,
  parseWappalyzer,
} from '../../utils/parsers.js';

import { classifyJsFiles } from '../../utils/jsClassifier.js';
import * as webCrawler from '../../utils/webCrawler.js';
import { discoverParameters } from '../../utils/paramDiscovery.js';
import { chromium } from 'playwright';


export const scanContext = new AsyncLocalStorage();
const _execAsync = promisify(exec);
const _execFileAsync = promisify(execFile);

async function execAsync(cmd, opts = {}) {
  const ctx = scanContext.getStore();
  if (ctx?.signal) {
    if (ctx.signal.aborted) throw new Error('AbortError: Scan stopped by user');
    opts.signal = ctx.signal;
  }
  return _execAsync(cmd, opts);
}

async function execFileAsync(file, args, opts = {}) {
  const ctx = scanContext.getStore();
  if (ctx?.signal) {
    if (ctx.signal.aborted) throw new Error('AbortError: Scan stopped by user');
    opts.signal = ctx.signal;
  }
  return _execFileAsync(file, args, opts);
}

// ── Tool environment — includes go/bin so subjs, getJS, gau, waybackurls work ──
const HOME = process.env.HOME || process.env.USERPROFILE || '';
const TOOL_ENV = {
  PATH: [
    process.env.PATH,
    join(HOME, 'go/bin'),
    join(HOME, '.local/bin'),
    '/usr/local/go/bin',
  ].filter(Boolean).join(':'),
  HOME: process.env.HOME,
};


// Tool paths for Python tools
const LINKFINDER_PATH = config.LINKFINDER_PATH;

// ── Input Validation ──────────────────────────────────────────────────────────
const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function validateTarget(target) {
  if (!target || typeof target !== 'string') throw new Error('Target must be a non-empty string.');
  // Support full URLs: extract hostname for validation, keep original for protocol detection
  let hostname = target.trim().toLowerCase();
  let inputUrl = null;
  try {
    if (/^https?:\/\//i.test(hostname)) {
      const parsed = new URL(hostname);
      hostname = parsed.hostname;
      inputUrl = target.trim(); // preserve original URL
    } else {
      hostname = hostname.replace(/\/.*$/, '').split(':')[0];
    }
  } catch { hostname = hostname.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').split(':')[0]; }
  if (hostname.length > 253) throw new Error('Target hostname exceeds maximum length.');
  if (!HOSTNAME_RE.test(hostname)) throw new Error(`Invalid target hostname: "${hostname}".`);
  return hostname;
}

/**
 * Parse target input into { hostname, baseUrl, protocol } for the recon pipeline.
 * Supports: bare domains, http:// URLs, https:// URLs, URLs with paths.
 */
function parseTargetInput(rawTarget) {
  const trimmed = (rawTarget || '').trim();
  let hostname, protocol, baseUrl;

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      hostname = parsed.hostname;
      protocol = parsed.protocol.replace(':', ''); // 'http' or 'https'
      baseUrl = `${protocol}://${hostname}`;
    } catch {
      hostname = trimmed.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').split(':')[0];
      protocol = trimmed.toLowerCase().startsWith('http://') ? 'http' : 'https';
      baseUrl = `${protocol}://${hostname}`;
    }
  } else {
    hostname = trimmed.toLowerCase().replace(/\/.*$/, '').split(':')[0];
    protocol = 'https'; // default to https for bare domains
    baseUrl = `https://${hostname}`;
  }

  return { hostname, protocol, baseUrl };
}

// ── Phase 0: Target Intelligence ──────────────────────────────────────────────

async function collectTargetIntel(target) {
  const intel = { dns: [], asn: null, cdn: null, ip: [] };
  try {
    // DNS A/AAAA/MX
    const { stdout: dnsR } = await execAsync(`dig +short A ${target} MX ${target}`, { timeout: 10000 }).catch(() => ({ stdout: '' }));
    intel.dns = dnsR.trim().split('\n').filter(Boolean);
    intel.ip = intel.dns.filter(l => /^[0-9.]+$/.test(l));

    // ASN / Org (best effort)
    if (intel.ip.length > 0) {
      const { stdout: whoisR } = await execAsync(`whois ${intel.ip[0]} | grep -iE "origin:|organization:|netname:" | head -n 3`, { timeout: 10000 }).catch(() => ({ stdout: '' }));
      intel.asn = whoisR.trim() || 'Unknown';
    }

    // CDN Detection
    const cdnMatch = dnsR.toLowerCase().match(/cloudflare|fastly|akamai|cloudfront|sucuri|imperva|incapsula/);
    if (cdnMatch) intel.cdn = cdnMatch[0];
  } catch { /* ignore */ }
  return intel;
}

// ── Phase 1: Accessibility & Protocol Detection ─────────────────────────────

export async function negotiateTarget(target) {
  const results = {
    reachable: false,
    protocol: null,
    ports: [],
    variant: null,
    baseUrl: null,
    finalUrl: null,
    statusCode: null,
  };

  const variants = [
    `https://${target}`,
    `http://${target}`,
    `https://www.${target}`,
    `http://www.${target}`,
  ];

  // Port scan (optional)
  for (const port of [80, 443]) {
    try {
      await execAsync(`nc -zv -w 2 ${target} ${port}`, { timeout: 3000 });
      results.ports.push(port);
    } catch { }
  }

  let bestResult = null;
  for (const url of variants) {
    try {
      const { stdout } = await execAsync(
        `curl -s -I -L -k --connect-timeout 5 --max-time 12 -o /dev/null -w "%{http_code} %{url_effective}" "${url}"`,
        { timeout: 20000 }
      );

      const out = stdout.trim();
      const codeMatch = out.match(/^(\d{3})\s+(.*)$/);
      if (!codeMatch) continue;

      const code = parseInt(codeMatch[1], 10);
      const effectiveUrl = codeMatch[2]?.trim();

      // Accept redirect, forbidden, auth-required as "reachable"
      const reachableCodes = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403];
      if (!reachableCodes.includes(code)) continue;
      if (!effectiveUrl.startsWith("http")) continue;

      const parsed = new URL(effectiveUrl);

      const currentReachable = {
        reachable: true,
        protocol: parsed.protocol.replace(":", ""),
        variant: url,
        finalUrl: effectiveUrl,
        baseUrl: `${parsed.protocol}//${parsed.hostname}`,
        statusCode: code,
        ports: results.ports
      };

      const inferredPort = currentReachable.protocol === "https" ? 443 : 80;
      if (!currentReachable.ports.includes(inferredPort)) currentReachable.ports.push(inferredPort);

      // Prefer HTTPS. If we found HTTPS, break immediately. If HTTP, keep looking for HTTPS.
      if (currentReachable.protocol === "https" || !bestResult) {
        bestResult = currentReachable;
      }
      if (currentReachable.protocol === "https") {
        break;
      }
    } catch { }
  }

  if (bestResult) {
    return bestResult;
  }

  return results;
}

// ── Phase 9: Adaptive Logic ──────────────────────────────────────────────────

function createRateLimiter() {
  let errorCount = 0;
  let requestCount = 0;
  const MAX_ERROR_RATE = 0.4;

  return {
    track: (success) => {
      requestCount++;
      if (!success) errorCount++;
    },
    shouldStop: () => {
      if (requestCount < 10) return false;
      return (errorCount / requestCount) > MAX_ERROR_RATE;
    },
    getDelay: () => Math.floor(Math.random() * 1500) + 500, // 500ms - 2000ms
    stats: () => ({ errorCount, requestCount, rate: (requestCount > 0 ? errorCount / requestCount : 0).toFixed(2) })
  };
}

// ── Phase 0.5: Target Quality Assessment ──────────────────────────────────────

function assessTargetQuality(intel, liveHosts) {
  let score = 0;
  if (!intel.cdn) score += 10; // Positive for non-CDN (easier to find origin)
  if (liveHosts.length > 0) score += 30;
  if (intel.ip && intel.ip.length > 1) score += 10;
  // If no live hosts but valid DNS exists, it's still worth passive recon
  return score;
}

// ── URL Scope & Filtering Helpers ──────────────────────────────────────────

function isInScope(url, target) {
  try {
    if (!url) return false;
    // BUGFIX v3: target can be either a string hostname OR a scanContext object.
    // Always extract the hostname string before comparing.
    const hostname = (typeof target === 'object' && target !== null)
      ? (target.hostname || target.host || '')
      : String(target || '');
    if (!hostname) return true; // No scope defined → allow all
    const u = new URL(url.startsWith('http') ? url : `https://${hostname}/${url.replace(/^\//, '')}`);
    return u.hostname === hostname || u.hostname.endsWith(`.${hostname}`);
  } catch {
    return false;
  }
}

/**
 * scoreJs — scores a JS URL for exploitation value.
 * Returns a numeric score (higher = more useful).
 * NOTE: All JS files are KEPT — this score only influences analysis priority.
 * Minified/vendor JS is deprioritized but never discarded (bundles hide endpoints).
 */
function scoreJs(url) {
  const lower = url.toLowerCase();
  let score = 0;

  // High-value signals (+)
  if (/\/(app|main|index|bundle|chunk|init|config|router|routes?|api|auth|user|admin)(\.\w+)?\.(js)([?#]|$)/i.test(lower)) score += 30;
  if (lower.includes('api')) score += 20;
  if (lower.includes('config')) score += 15;
  if (lower.includes('app.js') || lower.includes('main.js')) score += 25;

  // Known low-value (penalty but NOT excluded)
  if (lower.includes('jquery')) score -= 20;
  if (lower.includes('bootstrap')) score -= 20;
  if (lower.includes('google-analytics') || lower.includes('googletagmanager')) score -= 30;

  // Minified/vendor bundles — penalise but keep (webpack bundles hide real endpoints)
  if (lower.includes('.min.js')) score -= 10;
  if (lower.includes('vendor')) score -= 10;
  if (lower.includes('webpack')) score -= 5;

  // CDN-hosted 3rd-party scripts — low priority but still parseable
  if (lower.includes('cdn')) score -= 15;

  return score;
}

// ── Phase 7: Endpoint Validation ─────────────────────────────────────────────

function isInterestingEndpoint(url) {
  const patterns = ['api', 'auth', 'login', 'admin', 'upload', 'download', 'file', 'redirect', 'callback', 'v1', 'v2', 'config', 'setup'];
  const lower = url.toLowerCase();
  let score = 0;
  if (patterns.some(p => lower.includes(p))) score += 40;
  if (lower.includes('?')) score += 30;
  return score;
}

/**
 * parseResponseHeaders — parses raw curl header dump into a structured object.
 */
function parseResponseHeaders(headerText) {
  const headers = {};
  for (const line of headerText.split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (key && val) headers[key] = val;
  }
  return headers;
}

async function validateEndpoints(endpoints, scanContext, limiter, onProgress) {
  const validated = [];
  const toCheck = endpoints.slice(0, 280);
  onProgress({ phase: 'validation', status: 'running', message: `🔍 Phase 7: Deep validation of ${toCheck.length} endpoints (GET + fingerprinting)...` });

  for (const ep of toCheck) {
    if (limiter.shouldStop()) break;

    try {
      let url = typeof ep === 'string' ? ep : ep.url;

      if (!/^https?:\/\//i.test(url)) {
        url = new URL(url.startsWith('/') ? url : `/${url}`, scanContext.baseUrl).toString();
      }

      // -D - dumps headers to stdout; body is silenced with -o /dev/null
      // -w appends status/size/type after headers
      const { stdout } = await execAsync(
        `curl -X GET -s -L -k --max-time 5 -D - -o /dev/null -w "\n__CURL_META__ %{http_code} %{size_download} %{content_type}" "${url}"`,
        { timeout: 7000 }
      );

      // Split header dump from curl write-out
      const metaMatch = stdout.match(/__CURL_META__ (\d+) (\d+) ([^\n]*)/);
      if (!metaMatch) { limiter.track(false); continue; }

      const status = parseInt(metaMatch[1], 10);
      const size = parseInt(metaMatch[2], 10) || 0;
      const type = (metaMatch[3] || 'unknown').trim();

      const headerSection = stdout.slice(0, stdout.indexOf('__CURL_META__'));
      const hdrs = parseResponseHeaders(headerSection);

      if (status >= 200 && status < 400) {
        const score = isInterestingEndpoint(url);

        // Extract cookies (name only)
        const cookieHeader = hdrs['set-cookie'] || '';
        const cookies = cookieHeader ? cookieHeader.split(';')[0].split('=')[0].trim() : null;

        validated.push({
          ...(typeof ep === 'string' ? { url: ep } : ep),
          status_code: status,
          response_size: size,
          content_type: type,
          server_header: hdrs['server'] || hdrs['x-powered-by'] || null,
          cookies,
          redirect_location: hdrs['location'] || null,
          security_headers: {
            csp: hdrs['content-security-policy'] || null,
            xfo: hdrs['x-frame-options'] || null,
            cors: hdrs['access-control-allow-origin'] || null,
          },
          priority_score: score
        });
        limiter.track(true);
      } else {
        limiter.track(false);
      }
    } catch {
      limiter.track(false);
    }
  }

  validated.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));
  return validated;
}

// ── Binary helpers ──────────────────────────────────────────────────────────

async function binaryExists(bin) {
  try {
    await execAsync(`which ${bin}`, { env: TOOL_ENV, timeout: 5000 });
    return true;
  } catch { return false; }
}

async function findBin(...candidates) {
  for (const bin of candidates) {
    if (await binaryExists(bin)) return bin;
  }
  return null;
}

// ── Generic tool runner ───────────────────────────────────────────────────────
async function runTool(command, toolName, timeoutMs = 90_000, retries = 2) {
  let lastErr = null;
  for (let i = 0; i <= retries; i++) {
    try {
      const { stdout } = await execAsync(command, {
        timeout: timeoutMs,
        maxBuffer: 8 * 1024 * 1024,
        env: TOOL_ENV,
      });
      return { tool: toolName, success: true, output: stdout.trim() || '(no output)' };
    } catch (err) {
      lastErr = err;
      // Don't retry if tool not found
      if (err.code === 127 || (err.stderr || '').includes('not found')) break;
      // Exponential backoff with jitter
      if (i < retries) {
        const delay = Math.floor(Math.random() * 1000) + (Math.pow(2, i) * 1000);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  const err = lastErr;

  // FIX: timed-out tools are NOT treated as success — return partial output only
  if (err.killed || err.signal === 'SIGTERM') {
    const partial = (err.stdout || '').trim();
    console.warn(`[RedVapt] ${toolName}: timed out after ${timeoutMs}ms${partial ? ' (partial output returned)' : ''}`);
    return {
      tool: toolName,
      success: false,
      timedOut: true,
      output: partial || '(timed out — no output)',
    };
  }
  const msg = err.stderr || err.message || '';
  if (msg.includes('not found') || msg.includes('No such file') || err.code === 127) {
    return { tool: toolName, success: false, output: `'${toolName}' not installed.` };
  }
  return { tool: toolName, success: false, output: (err.stdout || '').trim() || '(no output)' };
}

// ── PHASE 1 — ASSET DISCOVERY (DELETED AMASS)
// ══════════════════════════════════════════════════════════════════════════════


async function runSublist3r(target) {
  const bin = await findBin('sublist3r', join(HOME, '.local/bin/sublist3r'));
  if (!bin) return { tool: 'sublist3r', success: false, output: "'sublist3r' not installed." };
  const tmpOut = join(tmpdir(), `rv_sublist3r_${Date.now()}.txt`);
  try {
    await runTool(`${bin} -d ${target} -o ${tmpOut} 2>/dev/null`, 'sublist3r', TIMEOUTS.SUBLIST3R);
    const content = await readFile(tmpOut, 'utf-8').catch(() => '');
    return { tool: 'sublist3r', success: true, output: content.trim() || '(no output)' };
  } finally { await unlink(tmpOut).catch(() => { }); }
}

async function runSubfinder(target) {
  return runTool(`subfinder -d ${target} --all --recursive -silent 2>/dev/null`, 'subfinder', TIMEOUTS.SUBFINDER);
}

async function runAssetfinder(target) {
  return runTool(`assetfinder --subs-only ${target} 2>/dev/null`, 'assetfinder', TIMEOUTS.ASSETFINDER);
}

async function runCrtSh(target) {
  return runTool(
    `curl -s "https://crt.sh/?q=%.${target}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | grep -vF '*.' | sort -u`,
    'crt.sh', 60_000
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE 2 — NORMALIZATION (DNS RESOLUTION)
// ══════════════════════════════════════════════════════════════════════════════

async function resolveDns(subdomains) {
  const batch = subdomains.slice(0, 50);
  const promises = batch.map(async (host) => {
    try {
      const { stdout } = await execAsync(`dig +short ${host} 2>/dev/null`, { timeout: 5000, env: TOOL_ENV });
      const ips = stdout.trim().split('\n').filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l));
      return { subdomain: host, ip: ips[0] || null, resolves: ips.length > 0 };
    } catch { return { subdomain: host, ip: null, resolves: false }; }
  });
  return Promise.all(promises);
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE 3 — SERVICE DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════

export async function runHttpx(hostsText) {
  if (!hostsText?.trim() || hostsText === '(no output)') {
    return { tool: 'httpx', success: false, output: 'No subdomains to probe.' };
  }
  const bin = await findBin('httpx-toolkit', 'httpx');
  if (!bin) return { tool: 'httpx', success: false, output: "'httpx' not installed." };
  const tmpFile = join(tmpdir(), `rv_hosts_${Date.now()}.txt`);
  try {
    await writeFile(tmpFile, hostsText, { mode: 0o600 });
    // -json: structured output (parseable, no text fragility)
    // -follow-redirects: follow redirects
    // -insecure: ignores SSL errors — critical for labs with self-signed certs
    // -random-agent: bypass simple bot detection
    // -timeout 10, -retries 3: more robust against network noise
    // -tls-probe, -probe: extra effort to detect services
    // Fix: -insecure is not supported by installed httpx-toolkit version. Used stable flags.
    return runTool(
      `${bin} -l "${tmpFile}" -json -title -tech-detect -server -ip -cdn -follow-redirects -random-agent -timeout 10 -retries 3 -sc -location 2>/dev/null`,
      'httpx', 150_000
    );
  } finally { await unlink(tmpFile).catch(() => { }); }
}

async function runWafw00f(baseUrl) {
  if (!await binaryExists('wafw00f')) return { tool: 'wafw00f', success: false, output: 'not installed.' };
  return runTool(`wafw00f "${baseUrl}" -a 2>/dev/null`, 'wafw00f', TIMEOUTS.WAFW00F);
}

async function runWappalyzer(baseUrl) {
  return runTool(`npx -y wappalyzer "${baseUrl}" 2>/dev/null`, 'wappalyzer', TIMEOUTS.WAPPALYZER);
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE 4 — INFRASTRUCTURE MAPPING
// ══════════════════════════════════════════════════════════════════════════════

async function runNmap(target) {
  // use --top-ports 100 for speed
  return runTool(`nmap -T4 --top-ports 100 -sV -Pn --open ${target} 2>/dev/null`, 'nmap', TIMEOUTS.NMAP, 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE 5 — SURFACE EXPANSION

async function runSubjs(hostsFile) {
  const bin = await findBin(join(HOME, 'go/bin/subjs'), '/usr/local/bin/subjs', 'subjs');
  if (!bin) return { tool: 'subjs', success: false, output: "'subjs' not installed." };
  return runTool(`cat "${hostsFile}" | ${bin} 2>/dev/null | sort -u`, 'subjs', TIMEOUTS.SUBJS);
}

async function runGetjs(hostsFile) {
  const bin = await findBin(join(HOME, 'go/bin/getJS'), '/usr/local/bin/getJS', 'getJS', 'getjs');
  if (!bin) return { tool: 'getjs', success: false, output: "'getJS' not installed." };
  return runTool(`cat "${hostsFile}" | ${bin} 2>/dev/null | sort -u`, 'getjs', TIMEOUTS.GETJS);
}

async function runGauEndpoints(target) {
  const bin = await findBin(join(HOME, 'go/bin/gau'), '/usr/local/bin/gau', 'gau');
  if (!bin) return { tool: 'gau-endpoints', success: false, output: "'gau' not installed." };
  return runTool(
    `echo ${target} | ${bin} --threads 10 --blacklist png,jpg,gif,css,svg,woff,ttf,ico 2>/dev/null | sort -u`,
    'gau-endpoints', TIMEOUTS.GAU, 0
  );
}

async function runWaybackurls(target) {
  const bin = await findBin(join(HOME, 'go/bin/waybackurls'), '/usr/local/bin/waybackurls', 'waybackurls');
  if (!bin) return { tool: 'waybackurls-endpoints', success: false, output: "'waybackurls' not installed." };
  return runTool(`echo ${target} | ${bin} 2>/dev/null | sort -u`, 'waybackurls-endpoints', TIMEOUTS.WAYBACKURLS, 1);
}

async function runLinkFinder(jsUrl) {
  const paths = [LINKFINDER_PATH, '/opt/LinkFinder/linkfinder.py', join(HOME, 'Desktop/tools/LinkFinder/linkfinder.py')];
  let lf = null;
  for (const p of paths) {
    try { await execAsync(`test -f "${p}"`); lf = p; break; } catch { /* skip */ }
  }
  if (!lf) return { tool: 'linkfinder', success: false, output: "'linkfinder' not found." };
  return runTool(`python3 ${lf} -i ${jsUrl} -o cli 2>/dev/null`, 'linkfinder', TIMEOUTS.LINKFINDER);
}


// ── robots.txt + sitemap.xml extraction ──────────────────────────────────────

/**
 * fetchRobotsAndSitemap — extracts URL hints from robots.txt and sitemap.xml.
 * Handles both sitemap index files and regular sitemaps.
 * Returns: { robotsUrls: string[], sitemapUrls: string[], count: number }
 */
async function fetchRobotsAndSitemap(baseUrl) {
  const robotsUrls = [];
  const sitemapUrls = [];

  // ── robots.txt ──
  try {
    const { stdout: robotsText } = await execAsync(
      `curl -s -L -k --max-time 8 "${baseUrl}/robots.txt"`, { timeout: 10000 }
    );
    if (robotsText && !robotsText.includes('<html') && robotsText.includes('/')) {
      for (const line of robotsText.split('\n')) {
        const m = line.match(/^(?:Disallow|Allow):\s*(.+)/i);
        if (m) {
          const path = m[1].trim();
          if (path && path !== '/' && path !== '*') {
            // Convert relative paths to absolute URLs
            const absUrl = path.startsWith('http') ? path : `${baseUrl}${path.startsWith('/') ? path : '/' + path}`;
            robotsUrls.push(absUrl);
          }
        }
        // Also collect Sitemap: directives
        const sitemapDir = line.match(/^Sitemap:\s*(.+)/i);
        if (sitemapDir) sitemapUrls.push(sitemapDir[1].trim());
      }
    }
  } catch { /* ignore */ }

  // ── sitemap.xml ── (also handles sitemap index)
  const sitemapQueue = sitemapUrls.length > 0 ? [...sitemapUrls] : [`${baseUrl}/sitemap.xml`];
  const processedSitemaps = new Set();

  for (const sitemapUrl of sitemapQueue.slice(0, 5)) { // cap at 5 sitemaps
    if (processedSitemaps.has(sitemapUrl)) continue;
    processedSitemaps.add(sitemapUrl);

    try {
      const { stdout: xml } = await execAsync(
        `curl -s -L -k --max-time 8 "${sitemapUrl}"`, { timeout: 10000 }
      );
      if (!xml || xml.includes('<html')) continue;

      // Extract <loc> tags — covers both sitemapindex and urlset
      const locs = [...xml.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/gi)].map(m => m[1].trim());
      for (const loc of locs) {
        if (loc.endsWith('.xml') && !processedSitemaps.has(loc)) {
          sitemapQueue.push(loc); // nested sitemap index
        } else if (loc.startsWith('http')) {
          sitemapUrls.push(loc);
        }
      }
    } catch { /* ignore */ }
  }

  // Deduplicate and cap
  const allSitemapUrls = [...new Set(sitemapUrls)].slice(0, 200);
  const allRobotsUrls = [...new Set(robotsUrls)].slice(0, 100);

  return {
    robotsUrls: allRobotsUrls,
    sitemapUrls: allSitemapUrls,
    count: allRobotsUrls.length + allSitemapUrls.length,
  };
}

async function runParamSpider(target) {
  const bin = await findBin('paramspider', join(HOME, '.local/bin/paramspider'));
  if (!bin) return { tool: 'paramspider', success: false, output: "'paramspider' not installed." };
  const tmpOut = join(tmpdir(), `rv_params_${target}_${Date.now()}.txt`);
  try {
    await runTool(`${bin} -d ${target} --output ${tmpOut} 2>/dev/null`, 'paramspider', TIMEOUTS.PARAMSPIDER);
    const content = await readFile(tmpOut, 'utf-8').catch(() => '');
    return { tool: 'paramspider', success: true, output: content.trim() || '(no output)' };
  } finally { await unlink(tmpOut).catch(() => { }); }
}

async function runArjun(target) {
  const bin = await findBin('arjun');
  if (!bin) return { tool: 'arjun', success: false, output: "'arjun' not installed." };
  const tmpOut = join(tmpdir(), `rv_arjun_${Date.now()}.json`);
  try {
    await runTool(`${bin} -u ${target} -oT ${tmpOut} 2>/dev/null`, 'arjun', TIMEOUTS.ARJUN);
    const content = await readFile(tmpOut, 'utf-8').catch(() => '');
    return { tool: 'arjun', success: true, output: content.trim() };
  } finally { await unlink(tmpOut).catch(() => { }); }
}



async function runCariddi(hostsFile) {
  const bin = await findBin('cariddi');
  if (!bin) return { tool: 'cariddi', success: false, output: "'cariddi' not installed." };
  return runTool(`cat "${hostsFile}" | ${bin} -i -s 3 -t 10 -e -plain 2>/dev/null`, 'cariddi', 120000);
}

async function runNuclei(target) {
  const bin = await findBin('nuclei');
  if (!bin) return { tool: 'nuclei', success: false, output: "'nuclei' not installed." };
  const tmpOut = join(tmpdir(), `rv_nuclei_${Date.now()}.json`);
  try {
    await runTool(`${bin} -u ${target} -t technologies -j -o ${tmpOut} 2>/dev/null`, 'nuclei', TIMEOUTS.NUCLEI);
    const content = await readFile(tmpOut, 'utf-8').catch(() => '');
    return { tool: 'nuclei', success: true, output: content.trim() };
  } finally { await unlink(tmpOut).catch(() => { }); }
}

async function runGf(file, pattern) {
  const bin = await findBin('gf');
  if (!bin) return { tool: 'gf', success: false, output: "'gf' not installed." };
  try {
    const { stdout } = await execAsync(`cat "${file}" | ${bin} ${pattern} 2>/dev/null`, { timeout: TIMEOUTS.GF });
    return { tool: `gf-${pattern}`, success: true, output: stdout.trim() };
  } catch {
    return { tool: `gf-${pattern}`, success: false, output: "" };
  }
}


async function runFfuf(baseUrl) {
  const wordlists = [
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
  ];
  let wordlist = null;
  for (const wl of wordlists) {
    try { await execAsync(`test -f "${wl}"`); wordlist = wl; break; } catch { /* skip */ }
  }
  if (!wordlist) return { tool: 'ffuf', success: false, output: 'No wordlist found.' };

  const tmpOut = join(tmpdir(), `rv_ffuf_${Date.now()}.json`);
  try {
    const url = `${baseUrl}/FUZZ`;
    await runTool(
      `ffuf -w "${wordlist}" -u "${url}" -mc 200,201,204,301,302,303,307,401,403 -t 50 -timeout 10 -s -e .php,.html,.js,.json -o "${tmpOut}" -of json 2>/dev/null`,
      'ffuf', 180_000
    );
    const raw = await readFile(tmpOut, 'utf-8');
    const parsed = JSON.parse(raw);

    function clusterFfufResults(results) {
      const clusters = new Map();
      for (const r of results) {
        const bucket = Math.floor(r.length / 500) * 500;
        if (!clusters.has(bucket)) clusters.set(bucket, []);
        clusters.get(bucket).push(r);
      }
      return [...clusters.entries()]
        .filter(([_, urls]) => urls.length <= 3) // unique responses
        .flatMap(([_, urls]) => urls);
    }

    const clusteredResults = clusterFfufResults(parsed.results || []);
    const hits = clusteredResults.map(r => `${r.status} ${r.length}b ${r.url}`).join('\n');

    return {
      tool: 'ffuf', success: true,
      output: hits || '(no paths found)',
      metadata: `Wordlist: ${wordlist} | ${clusteredResults.length} clustered out of ${(parsed.results || []).length}`,
    };
  } catch {
    return { tool: 'ffuf', success: false, output: 'ffuf produced no parseable output.' };
  } finally { await unlink(tmpOut).catch(() => { }); }
}

async function fetchContent(url) {
  try {
    const { stdout } = await execAsync(`curl -s -L --max-time 10 "${url}"`, { timeout: 12000 });
    return stdout || '';
  } catch { return ''; }
}

function extractApiEndpoints(content, baseUrl) {
  const apiPatterns = [
    /\/api\/[a-zA-Z0-9_/.-]+/g,
    /https?:\/\/[^\s"'`]+/g,
    /["']\/[a-zA-Z0-9_\-]{2,20}\/[a-zA-Z0-9_\-\/]{2,50}["']/g
  ];
  const results = new Set();
  for (const pattern of apiPatterns) {
    const matches = content.match(pattern) || [];
    for (let m of matches) {
      m = m.replace(/["']/g, ''); // Clean quotes
      if (!m.startsWith('http') && !m.startsWith('/')) continue;
      results.add(m);
    }
  }
  return [...results];
}

function extractForms(html, url) {
  const forms = [];
  // Basic regex for form extraction
  const formBlocks = html.match(/<form[\s\S]*?<\/form>/gi) || [];
  for (const block of formBlocks) {
    const actionMatch = block.match(/action=["']([^"']+)["']/i);
    const methodMatch = block.match(/method=["']([^"']+)["']/i);
    const inputs = [...block.matchAll(/name=["']([^"']+)["']/gi)].map(m => m[1]);

    if (inputs.length > 0) {
      forms.push({
        action: actionMatch ? actionMatch[1] : url,
        method: (methodMatch ? methodMatch[1] : 'GET').toUpperCase(),
        inputs,
        is_high_value: inputs.some(i => /pass|auth|token|secret|admin/i.test(i))
      });
    }
  }
  return forms;
}

function extractParamsFromUrl(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()];
  } catch { return []; }
}

// ── Auth & Session Detection ────────────────────────────────────────────────

/**
 * detectAuthFeatures — identifies authentication-relevant indicators from
 * validated endpoints, response fingerprints, and crawled forms.
 *
 * Returns: {
 *   loginPages: string[],
 *   sessionCookies: string[],
 *   csrfTokens: string[],
 *   oauthEndpoints: string[],
 *   ssoEndpoints: string[],
 * }
 */
function detectAuthFeatures(validatedEndpoints = [], crawlForms = []) {
  const loginPages = [];
  const sessionCookies = new Set();
  const csrfTokens = new Set();
  const oauthEndpoints = [];
  const ssoEndpoints = [];

  // ── Detect from validated endpoints (URL + header fingerprint) ──
  for (const ep of validatedEndpoints) {
    const url = (ep.url || '').toLowerCase();
    const lower = url;

    // Login page detection
    if (/login|signin|sign-in\/|auth\/|account\/login/.test(lower)) {
      loginPages.push(ep.url);
    }

    // OAuth / authorize endpoints
    if (/\/oauth\/|\/authorize\b|\/token\b|client_id=|response_type=/.test(lower)) {
      oauthEndpoints.push(ep.url);
    }

    // SSO redirect patterns
    if (/\/sso\/|\/saml\/|redirect_uri=|ReturnUrl=|RelayState=/.test(url)) {
      ssoEndpoints.push(ep.url);
    }

    // Session cookie names from Set-Cookie header
    if (ep.cookies) {
      const name = ep.cookies.toLowerCase();
      if (/sess|session|auth|token|jwt|sid|phpsessid|jsessionid|asp\.net_sessionid/.test(name)) {
        sessionCookies.add(ep.cookies);
      }
    }

    // CSRF indicators in security headers or redirect targets
    const csp = (ep.security_headers?.csp || '').toLowerCase();
    if (csp && csp.includes('nonce-')) csrfTokens.add('csp-nonce');
  }

  // ── Detect from crawled forms ──
  for (const form of crawlForms) {
    const inputs = Array.isArray(form.inputs) ? form.inputs : [];
    const action = (form.action || '').toLowerCase();

    // Login form detection
    const hasPasswordField = inputs.some(i => /pass/i.test(typeof i === 'string' ? i : i.name || ''));
    if (hasPasswordField && !loginPages.includes(form.action)) {
      loginPages.push(form.action);
    }

    // CSRF token field detection
    for (const input of inputs) {
      const name = (typeof input === 'string' ? input : input.name || '').toLowerCase();
      if (/csrf|_token|authenticity_token|__requestverificationtoken|x-csrf/.test(name)) {
        csrfTokens.add(name);
      }
    }
  }

  return {
    loginPages: [...new Set(loginPages)],
    sessionCookies: [...sessionCookies],
    csrfTokens: [...csrfTokens],
    oauthEndpoints: [...new Set(oauthEndpoints)],
    ssoEndpoints: [...new Set(ssoEndpoints)],
  };
}

// ── Finalize Report ──────────────────────────────────────────────────────────

async function finalizeReport(safeTarget, scanDB, onProgress, intel = {}, limiter = null, scanContext = null) {
  const epCount = scanDB.queries.countEndpoints();
  const jsFileCount = scanDB.queries.countJsFiles();

  // ── Phase 8: Asset Intelligence & Scoring ──────────────────────────────────
  onProgress({ phase: 'scoring', status: 'running', message: `📊 **Phase 8:** Running intelligence-driven attack surface scoring...` });

  const allEndpoints = scanDB.queries.allEndpoints();
  const allParameters = scanDB.queries.allParameters();

  const highPriority = [];
  for (const ep of allEndpoints) {
    let score = 0;
    const url = ep.url?.toLowerCase() || '';
    if (url.includes('api/') || url.includes('/v1/') || url.includes('/v2/')) score += 30;
    if (url.includes('login') || url.includes('auth') || url.includes('admin')) score += 40;
    if (allParameters.some(p => p.url === url)) score += 30;

    if (score >= 60) highPriority.push({ ...ep, score });
  }

  onProgress({ phase: 'scoring', status: 'done', message: `✅ **Phase 8 done:** Identified **${highPriority.length}** high-priority attack vectors` });

  // Phase 9: Final Health Check
  const healthStats = limiter ? limiter.stats() : { rate: '0.00' };

  onProgress({ phase: 'ai_analysis', status: 'running', message: `📊 **Phase 10:** Building deterministic intelligence summary (no AI tokens used)...` });
  // Phase 11 FIX: Recon is 100% tool-driven — no LLM here.
  // AI reasoning happens LATER in the orchestrator planner step.
  const analysis = buildIntelligenceSummary({
    endpoints: allEndpoints,
    jsSecrets: scanDB.queries.allJsSecrets(),
    jsEndpoints: scanDB.queries.allJsEndpoints(),
  });
  onProgress({ phase: 'ai_analysis', status: 'done', message: `✅ **Scan complete:** 10 phases finished. [Health: ${healthStats.rate} err/req]` });

  const results = {
    protocol: scanContext?.protocol || 'https',
    baseUrl: scanContext?.baseUrl || `https://${safeTarget}`,
    finalUrl: scanContext?.finalUrl || `https://${safeTarget}`,
    subdomains: scanDB.queries.countSubdomains(),
    liveHosts: scanDB.queries.countLiveHosts(),
    services: scanDB.queries.countServices(),
    endpoints: epCount,
    jsFiles: jsFileCount,
    jsSecrets: scanDB.queries.countJsSecrets(),
    parameters: scanDB.queries.countParameters(),
    findings: scanDB.queries.allFindings(),
    intelSummary: {
      ips: intel.ip?.length || 0,
      cdn: intel.cdn || 'None',
      asn: intel.asn || 'Unknown'
    },
    errorRate: healthStats.rate
  };

  const validatedEps = scanDB._validatedEndpoints || [];
  const allForms = scanDB.queries.allForms();

  // ── Auth & Session Detection (Improvement 5) ──────────────────────────────
  const authFeatures = detectAuthFeatures(validatedEps, allForms);
  const authCount = authFeatures.loginPages.length + authFeatures.oauthEndpoints.length + authFeatures.ssoEndpoints.length;
  if (authCount > 0) {
    onProgress({
      phase: 'auth_detection', status: 'done',
      message: `🔐 **Auth Features:** ${authFeatures.loginPages.length} login page(s), ${authFeatures.sessionCookies.length} session cookie(s), ${authFeatures.csrfTokens.length} CSRF token(s), ${authFeatures.oauthEndpoints.length} OAuth endpoint(s)`
    });
  }

  const reportData = {
    target: safeTarget,
    intel,
    subdomains: scanDB.queries.allSubdomains(),
    liveHosts: scanDB.queries.allLiveHosts(),
    services: scanDB.queries.allServices(),
    endpoints: allEndpoints,
    jsFiles: scanDB.queries.allJsFiles(),
    jsSecrets: scanDB.queries.allJsSecrets(),
    jsEndpoints: scanDB.queries.allJsEndpoints(),
    parameters: allParameters,
    forms: allForms,
    findings: scanDB.queries.allFindings(),
    technologies: scanDB.queries.allTechnologies(),
    highPriority,
    validatedEndpoints: validatedEps,
    authFeatures,
    healthStats,
    scanContext
  };

  return { results, analysis, reportData, scanDB };
}

async function runWebCrawl(baseUrl) {
  try {
    return await webCrawler.execute({
      url: baseUrl,
      maxPages: RECON.CRAWLER_MAX_PAGES,
      maxDepth: RECON.CRAWLER_MAX_DEPTH,
    });
  } catch (err) {
    console.error(`[RedVapt] Web crawl error: ${err.message}`);
    return { success: false, error: err.message };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN EXPORT — runReconAgent (called by index.js)
// ══════════════════════════════════════════════════════════════════════════════

export function runReconAgent(target, onProgress = () => { }, options = {}) {
  return scanContext.run(options, async () => {
    const targetMeta = parseTargetInput(target);
    const safeTarget = validateTarget(target);
    const startTime = Date.now();

    try {
      const watchdogMs = TIMEOUTS.GLOBAL_WATCHDOG_MS || 3_600_000;
      return await Promise.race([
        _executeRecon(safeTarget, onProgress, startTime, targetMeta),
        new Promise((_, reject) => setTimeout(() => reject(new Error('GLOBAL_SCAN_TIMEOUT')), watchdogMs))
      ]);
    } catch (err) {
      if (err.message === 'GLOBAL_SCAN_TIMEOUT') {
        const mins = Math.round(TIMEOUTS.GLOBAL_WATCHDOG_MS / 60000);
        onProgress({ phase: 'watchdog', status: 'error', message: `🛑 **Global Scan Timeout (${mins}m) triggered.** Stopping recon to prevent hang/resource exhaustion.` });
      }
      throw err;
    }
  });
}

async function _executeRecon(safeTarget, onProgress, startTime, targetMeta = {}) {
  const scanDB = createScanDB();
  const limiter = createRateLimiter();

  // ── Phase 0: Target Intelligence ────────────────────────────────────────────
  onProgress({ phase: 'intelligence', status: 'running', message: `🧠 **Phase 0:** Collecting intelligence for **${safeTarget}**...` });
  const intel = await collectTargetIntel(safeTarget);
  onProgress({
    phase: 'intel', status: 'done',
    message: `✅ **Phase 0 done:** ${intel.ip.length} IPs | CDN: ${intel.cdn || 'None'} | ASN: ${intel.asn?.slice(0, 50)}...`
  });

  // ── Phase 1: Accessibility & Protocol Detection ─────────────────────────────
  onProgress({ phase: 'health_check', status: 'running', message: `🔍 **Phase 1:** Checking reachability & ports 80/443...` });
  const health = await negotiateTarget(safeTarget);

  if (!health.reachable) {
    // fallback: simple DNS-based attempt
    onProgress({ phase: 'health_check', status: 'warning', message: `⚠️ Negotiation failed. Attempting fallback HTTP probe...` });
    try {
      const { stdout } = await execAsync(`curl -s -I --max-time 8 http://${safeTarget} -o /dev/null -w "%{http_code}"`, { timeout: 12000 });
      const code = parseInt(stdout.trim(), 10);
      if (code > 0 && code < 600) {
        health.reachable = true;
        health.protocol = "http";
        health.baseUrl = `http://${safeTarget}`;
        health.finalUrl = `http://${safeTarget}`;
        health.statusCode = code;
      }
    } catch { }
  }

  if (!health.reachable) {
    onProgress({ phase: 'health_check', status: 'error', message: `🚫 **Target Unreachable** — DNS/HTTP failed. Aborting.` });
    throw new Error(`Target unreachable: ${safeTarget}`);
  }

  const scanContext = {
    hostname: safeTarget,
    protocol: health.protocol,
    baseUrl: health.baseUrl,
    finalUrl: health.finalUrl,
    ports: health.ports
  };
  const targetBaseUrl = scanContext.baseUrl;

  onProgress({ phase: 'health_check', status: 'done', message: `✅ **Phase 1 done:** Reachable via **${health.protocol.toUpperCase()}** (Ports: ${health.ports.join(', ') || 'unknown'})` });

  // ── Pre-flight check: ensure essential tools exist ──────────────────────
  const essentialTools = ['subfinder', 'httpx-toolkit', 'nmap'];
  for (const tool of essentialTools) {
    if (!await binaryExists(tool)) {
      console.warn(`[RedVapt] Warning: Essential tool '${tool}' not found in PATH.`);
    }
  }

  // ── Phase 2: Asset Discovery (Batched for speed + stability) ────────────────
  onProgress({ phase: 'asset_discovery', status: 'running', message: `🔍 **Phase 2:** Smart Asset Discovery — running 4 enumeration sources...` });

  // Batch 1: Fastest tools
  onProgress({ phase: 'asset_discovery', status: 'running', message: `🔍 **Phase 2.1:** Running subfinder & crt.sh...` });
  const [subfinderR, crtshR] = await Promise.all([
    runSubfinder(safeTarget),
    runCrtSh(safeTarget),
  ]);

  // Batch 2: Medium speed tools
  // REMOVED: assetfinder + sublist3r (slow, redundant with subfinder)
  onProgress({ phase: 'asset_discovery', status: 'running', message: `🔍 **Phase 2.2:** Consolidating subdomain data...` });
  const [assetfinderR, sublist3rR] = await Promise.all([
    Promise.resolve({ tool: 'assetfinder', success: false, output: '' }),
    Promise.resolve({ tool: 'sublist3r', success: false, output: '' }),
  ]);

  // Batch 3: (Removed Amass)

  const sublist3rRows = parseSubfinder(sublist3rR.output, 'sublist3r');
  const subfinderRows = parseSubfinder(subfinderR.output, 'subfinder');
  const assetfinderRows = parseSubfinder(assetfinderR.output, 'assetfinder');
  const crtshRows = parseSubfinder(crtshR.output, 'crt.sh');

  // Smart Merge & Wildcard Removal
  const rawSubs = [...sublist3rRows, ...subfinderRows, ...assetfinderRows, ...crtshRows];
  const cleanSubs = rawSubs.filter(s => {
    const host = typeof s === 'string' ? s : s.subdomain;
    return host && !host.startsWith('*.') && host !== safeTarget;
  });

  scanDB.insertSubdomains(cleanSubs);

  const totalSubs = scanDB.queries.countSubdomains();
  onProgress({
    phase: 'asset_discovery', status: 'done',
    message: `✅ **Phase 2 done:** **${totalSubs}** unique subdomains discovered (filtered noise)`
  });

  // ── Phase 3: Live Host Validation ──────────────────────────────────────────────
  onProgress({ phase: 'normalization', status: 'running', message: `🔄 **Phase 3:** Live Host Validation — strict probing with httpx...` });
  const allSubdomains = scanDB.queries.allSubdomains().map(r => r.subdomain);
  const probeInput = [safeTarget, ...allSubdomains].join('\n');
  const httpxR = await runHttpx(probeInput);

  // Debug httpx output for visibility into TLS or timeout issues
  if (!httpxR.output || httpxR.output.length < 10) {
    console.log(`[DEBUG httpx output]: (Empty or too short output) -> Result: "${httpxR.output}"`);
  }

  const liveRows = (() => {
    // FIX 1.2: Robust JSON detection — scan for the first line that looks like JSON
    let hasJson = false;
    const lines = (httpxR.output || '').split('\n').map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      if (line.startsWith('{')) {
        try {
          JSON.parse(line);
          hasJson = true;
          break;
        } catch { /* skip */ }
      }
    }

    const parsed = hasJson ? parseHttpxJson(httpxR.output) : parseHttpx(httpxR.output);
    console.log(`[RedVapt] httpx parser: ${hasJson ? 'JSON' : 'text fallback'} -> ${parsed.length} live hosts`);
    return parsed;
  })();

  // LOGIC FIX: Robust recovery logic — use actual URL hostname matching
  const targetFound = liveRows.some(r => {
    try { return new URL(r.url).hostname.includes(safeTarget); }
    catch { return false; }
  });

  if (health.reachable && !targetFound) {
    const recoveryUrl = health.variant || targetBaseUrl;
    console.log(`[RECOVERY] Added ${safeTarget} using curl health.variant: ${recoveryUrl}`);
    liveRows.push({
      url: recoveryUrl,
      host: safeTarget,
      status_code: 200,
      title: 'Recovered via curl Check',
      tech: [],
      ip: intel.ip[0] || 'unknown'
    });
  }

  // SECONDARY FALLBACK: Direct curl probe if still 0 (Absolute reliability)
  if (liveRows.length === 0) {
    try {
      const { stdout } = await execAsync(`curl -IsL -k --max-time 10 "${health.variant || targetBaseUrl}" -w "%{http_code}" -o /dev/null`);
      const code = parseInt(stdout.trim(), 10);
      if (code >= 200 && code < 400) {
        console.log(`[RedVapt] Secondary recovery via direct curl probe (status: ${code})`);
        liveRows.push({
          url: health.variant || targetBaseUrl,
          host: safeTarget,
          status_code: code,
          title: 'Recovered via Direct curl',
          tech: [],
          ip: intel.ip[0] || 'unknown'
        });
      }
    } catch { /* ignore */ }
  }

  // Refinement 4: Write raw httpx output for debugging if 0 hosts found
  if (liveRows.length === 0 && httpxR.output) {
    try {
      await writeFile('/tmp/redvapt_httpx_debug.txt', httpxR.output);
      console.log(`[RedVapt] Debug: httpx returned 0 hosts. Raw output saved to /tmp/redvapt_httpx_debug.txt`);
    } catch { /* ignore */ }
  }

  if (liveRows.length > 0) scanDB.insertLiveHosts(liveRows);

  onProgress({
    phase: 'normalization', status: 'done',
    message: `✅ **Phase 3 done:** **${liveRows.length}** live hosts confirmed out of ${allSubdomains.length + 1} targets`
  });

  // ── DECISION CHECKPOINT: 0 Live Hosts ───────────────────────────────────
  const qualityScore = assessTargetQuality(intel, liveRows);
  if (liveRows.length === 0) {
    onProgress({
      phase: 'intelligence', status: 'warning',
      message: `🚫 **Network Failure / Target Down** — 0 live hosts detected on **${safeTarget}**. Stopping scanner to prevent garbage testing.`
    });

    // Skip aggressive scanning (Nmap, FFUF)
    // Only run archive-based discovery (GAU, Wayback, GAU-Endpoints)
    onProgress({ phase: 'passive_recon', status: 'running', message: `🔍 **Phase 3.5:** Passive Archival Discovery (GAU + Wayback)...` });
    const [gauR, wbR] = await Promise.all([
      runGauEndpoints(safeTarget), // Using runGauEndpoints for general GAU output
      runWaybackurls(safeTarget), // Using existing runWaybackurls
    ]);

    const gauRows = parseGauEndpoints(gauR.output).filter(r => isInScope(r.url, scanContext));
    const wbRows = parseGauEndpoints(wbR.output).filter(r => isInScope(r.url, scanContext));

    scanDB.insertEndpoints([...gauRows, ...wbRows]);

    onProgress({
      phase: 'passive_recon', status: 'done',
      message: `✅ **Passive Recon complete:** Discovered resources from archives only.`
    });

    return finalizeReport(safeTarget, scanDB, onProgress, intel, limiter, scanContext);
  }

  if (qualityScore < 10) {
    onProgress({ status: 'info', message: `ℹ️ **Low-value target** detected (Score: ${qualityScore}). Scanning with careful rate-limiting.` });
  }

  // ── Phase 4: Infrastructure Mapping ────────────────────────────────────
  onProgress({ phase: 'infrastructure', status: 'running', message: `🔭 **Phase 4:** Infrastructure Mapping — Nmap port scan (top 100 ports)...` });

  const nmapR = await runNmap(safeTarget);
  const svcRows = parseNmap(nmapR.output, safeTarget);
  if (svcRows.length > 0) scanDB.insertServices(svcRows);

  // ── Tech Detection: Reuse httpx -tech-detect data from Phase 3 (instant) ──
  // httpx already ran with -tech-detect using Wappalyzer signatures.
  // This is 100x faster than Nuclei's template-based approach.
  onProgress({ phase: 'infrastructure', status: 'running', message: `🔭 **Phase 4:** Extracting technologies from httpx fingerprints...` });
  let httpxTechCount = 0;
  const techRows = [];
  for (const host of liveRows) {
    const techStr = host.technologies || '';
    if (!techStr) continue;
    const techs = techStr.split(',').map(t => t.trim()).filter(Boolean);
    for (const name of techs) {
      if (!techRows.some(r => r.name === name)) {
        techRows.push({ name, category: 'httpx-detect', version: '', confidence: 85, website: host.url || '' });
      }
    }
  }
  if (techRows.length > 0) {
    scanDB.insertTechnologies(techRows);
    httpxTechCount = techRows.length;
  }

  onProgress({
    phase: 'infrastructure', status: 'done',
    message: nmapR.success
      ? `✅ **Phase 4 done:** **${svcRows.length}** open services mapped, ${httpxTechCount} technologies detected`
      : `⚠️ Nmap: ${nmapR.output}`,
  });

  // ── Phase 5: JS Intelligence + robots.txt/sitemap ───────────────────
  onProgress({ phase: 'js_intel', status: 'running', message: `🔍 **Phase 5:** JS Intelligence + robots.txt/sitemap extraction...` });

  // robots.txt + sitemap.xml early extraction (Improvement 3)
  const baseUrl = health.variant || targetBaseUrl;
  onProgress({ phase: 'robots_sitemap', status: 'running', message: `🤖 **Phase 5.1:** Fetching robots.txt & sitemap.xml...` });
  const robotsSitemap = await fetchRobotsAndSitemap(baseUrl);
  const rsEps = [
    ...robotsSitemap.robotsUrls.map(url => ({ url, source: 'robots.txt', has_params: url.includes('?') })),
    ...robotsSitemap.sitemapUrls.map(url => ({ url, source: 'sitemap.xml', has_params: url.includes('?') })),
  ].filter(r => isInScope(r.url, scanContext));
  if (rsEps.length > 0) scanDB.insertEndpoints(rsEps);
  onProgress({
    phase: 'robots_sitemap', status: 'done',
    message: `✅ **Phase 5.1 done:** ${robotsSitemap.robotsUrls.length} robots.txt path(s), ${robotsSitemap.sitemapUrls.length} sitemap URL(s) discovered`
  });

  // Step 1: Collect JS from ALL found endpoints and tools
  // FIX: sequential execution with per-tool progress events so the UI never freezes
  const liveHostsText = liveRows.map(r => r.url).join('\n');
  const liveHostsFile = join(tmpdir(), `rv_livehosts_${Date.now()}.txt`);
  await writeFile(liveHostsFile, liveHostsText, { mode: 0o600 });

  let subjsRes, getjsRes, gauRes, wbRes, cariddiRes;
  try {
    // subjs REMOVED (redundant with getJS, slower)
    subjsRes = { tool: 'subjs', success: false, output: '' };
    onProgress({ phase: 'js_intel', status: 'running', message: `   🔗 Phase 5.2: Running getjs...` });
    getjsRes = await runGetjs(liveHostsFile);

    onProgress({ phase: 'js_intel', status: 'running', message: `   📚 Phase 5.3: Running gau...` });
    gauRes = await runGauEndpoints(baseUrl);
    onProgress({ phase: 'js_intel', status: 'running', message: `   📚 Phase 5.3: Running waybackurls...` });
    wbRes = await runWaybackurls(baseUrl);
    onProgress({ phase: 'js_intel', status: 'running', message: `   📚 Phase 5.3: Running cariddi...` });
    cariddiRes = await runCariddi(liveHostsFile);
    onProgress({
      phase: 'js_intel', status: 'running',
      message: `   ✅ Archive discovery done: ${(gauRes.output || '').split('\n').filter(Boolean).length} gau + ${(wbRes.output || '').split('\n').filter(Boolean).length} wayback URLs + ${(cariddiRes.output || '').split('\n').filter(Boolean).length} cariddi endpoints`
    });
  } finally {
    await unlink(liveHostsFile).catch(() => { });
  }

  // Step 2: Parse results
  const subjsRows = parseSubjs(subjsRes.output).map(url => ({ url, source: 'subjs' }));
  const getjsRows = parseGetjs(getjsRes.output).map(url => ({ url, source: 'getjs' }));

  // Safety Limit: Truncate massive GAU/Wayback outputs to prevent memory explosion
  const gauAll = (gauRes.output || '').split('\n').slice(0, 5000).filter(l => l.startsWith('http'));
  const wbAll = (wbRes.output || '').split('\n').slice(0, 5000).filter(l => l.startsWith('http'));

  const gauJs = gauAll.filter(l => /\.js([?#].*)?$/i.test(l)).map(u => ({ url: u, source: 'gau' }));
  const wbJs = wbAll.filter(l => /\.js([?#].*)?$/i.test(l)).map(u => ({ url: u, source: 'waybackurls' }));

  const gauEps = parseGauEndpoints(gauRes.output).filter(r => isInScope(r.url, scanContext)).slice(0, 1000).map(r => ({ ...r, source: 'gau' }));
  const wbEps = parseWaybackurlsEndpoints(wbRes.output).filter(r => isInScope(r.url, scanContext)).slice(0, 1000).map(r => ({ ...r, source: 'waybackurls' }));

  const cariddiEps = (cariddiRes?.output || '').split('\n').filter(l => l.startsWith('http') && isInScope(l, scanContext)).map(u => ({ url: u, source: 'cariddi', has_params: u.includes('?') }));

  if (gauEps.length > 0) scanDB.insertEndpoints(gauEps);
  if (wbEps.length > 0) scanDB.insertEndpoints(wbEps);
  if (cariddiEps.length > 0) scanDB.insertEndpoints(cariddiEps);

  // Cariddi often finds parameters, extract parameter-bearing URLs
  const cariddiParams = cariddiEps.filter(e => e.has_params).map(e => ({ url: e.url, params: '', param_count: 0 }));
  if (cariddiParams.length > 0) scanDB.insertParameters(cariddiParams);

  // ── Phase 5.6: GF Parameter Sorting ──
  onProgress({ phase: 'gf_sorting', status: 'running', message: `🧹 **Phase 5.6:** Sorting endpoints via gf (xss, sqli, lfi, redirect, idor)...` });
  const tmpGfFile = join(tmpdir(), `rv_gf_${Date.now()}.txt`);
  const GF_PATTERNS = ['xss', 'sqli', 'lfi', 'redirect', 'idor'];
  try {
    await writeFile(tmpGfFile, [...gauAll, ...wbAll].join('\n'));

    for (const pattern of GF_PATTERNS) {
      try {
        const gfResult = await runGf(tmpGfFile, pattern);
        if (gfResult.success && gfResult.output) {
          const gfUrls = gfResult.output
            .split('\n')
            .map(u => u.trim())
            .filter(u => u && isInScope(u, scanContext));

          if (gfUrls.length > 0) {
            // Insert as endpoints
            scanDB.insertEndpoints(gfUrls.map(url => ({ url, source: `gf_${pattern}`, has_params: url.includes('?') })));

            // Insert as high-priority parameters
            const paramRows = gfUrls
              .filter(url => url.includes('?'))
              .map(url => {
                try {
                  return { url, params: '', param_count: new URL(url).searchParams.size };
                } catch { return { url, params: '', param_count: 0 }; }
              });
            if (paramRows.length > 0) scanDB.insertParameters(paramRows);

            console.log(`[RedVapt] gf ${pattern}: ${gfUrls.length} URLs ingested`);
          }
        }
      } catch { /* gf pattern not available or no matches */ }
    }
  } catch { } finally { await unlink(tmpGfFile).catch(() => { }); }

  // ── Phase 6: Parameter Discovery ──────────────────────────────────────────
  onProgress({ phase: 'parameter_discovery', status: 'running', message: `📂 **Phase 6:** Parameter Discovery — Consolidating parameters via paramspider & arjun...` });

  const [paramRes, arjunRes] = await Promise.all([
    runParamSpider(safeTarget),
    runArjun(scanContext.baseUrl)
  ]);

  const paramRows = parseParamSpider(paramRes.output).map(r => ({ ...r, source: 'paramspider' }));
  if (paramRows.length > 0) scanDB.insertParameters(paramRows);

  if (arjunRes.success && arjunRes.output) {
    try {
      const arjunParsed = JSON.parse(arjunRes.output);
      const arjunRows = [];
      for (const [ep, params] of Object.entries(arjunParsed)) {
        if (isInScope(ep, scanContext)) {
          arjunRows.push({ url: ep, params: (params || []).join(','), param_count: (params || []).length, source: 'arjun' });
        }
      }
      if (arjunRows.length > 0) scanDB.insertParameters(arjunRows);
    } catch { }
  }

  const allEndpointsForDiscovery = [
    ...gauEps,
    ...wbEps
  ];

  const discoveredParamRows = discoverParameters(allEndpointsForDiscovery, []);
  if (discoveredParamRows.length > 0) scanDB.insertParameters(discoveredParamRows);

  // ── JS Deduplication & Deep Intelligence (Improvement 2: score-based, never discard) ──
  const allJsSources = [...subjsRows, ...getjsRows, ...gauJs, ...wbJs]
    .filter(f => isInScope(f.url, scanContext)); // Keep ALL in-scope JS, no hard exclusions

  const seenJs = new Set();
  const uniqueJs = [];
  for (const f of allJsSources) {
    if (uniqueJs.length >= 300) break; // Hard cap on JS files for stability
    const key = f.url.split('?')[0].split('#')[0].toLowerCase();
    if (!seenJs.has(key)) {
      seenJs.add(key);
      uniqueJs.push({ ...f, js_score: scoreJs(f.url) }); // attach score
    }
  }
  // Sort by score descending — top-scoring go to deep LinkFinder analysis first
  uniqueJs.sort((a, b) => (b.js_score || 0) - (a.js_score || 0));
  if (uniqueJs.length > 0) scanDB.insertJsFiles(uniqueJs);

  const topJs = uniqueJs.slice(0, RECON.MAX_JS_DEEP_ANALYSIS);
  if (topJs.length > 0) {
    onProgress({ phase: 'js_intelligence', status: 'running', message: `🧠 Phase 5.5: Deep JS Intelligence — Extracting APIs/Forms (Batch of ${topJs.length})...` });

    // Optimization: run JS analysis in a limited parallel batch (concurrency: 3)
    const CONCURRENCY = 3;
    for (let i = 0; i < topJs.length; i += CONCURRENCY) {
      if (limiter.shouldStop()) break;
      const batch = topJs.slice(i, i + CONCURRENCY);

      await Promise.all(batch.map(async (jsObj) => {
        const jsUrl = jsObj.url;
        try {
          const lfR = await runLinkFinder(jsUrl);
          const lfRows = parseLinkFinder(lfR.output);
          if (lfRows.length > 0) scanDB.insertJsEndpoints(jsUrl, lfRows);

          const content = await fetchContent(jsUrl);
          if (content) {
            const apis = extractApiEndpoints(content, jsUrl);
            if (apis.length > 0) {
              scanDB.insertJsEndpoints(jsUrl, apis.map(a => ({ url: a, is_relative: !a.startsWith('http') })));
            }
            const forms = extractForms(content, jsUrl);
            if (forms.length > 0) scanDB.insertForms(forms);
          }
        } catch (err) {
          console.warn(`[RedVapt] JS Deep Intel failed for ${jsUrl}: ${err.message}`);
        }
        limiter.track(true);
      }));
    }
  }

  // FFUF
  onProgress({ phase: 'ffuf', status: 'running', message: `   📂 FFUF directory brute-force on ${targetBaseUrl}...` });
  const ffufR = await runTool(
    `ffuf -w "/usr/share/wordlists/dirb/common.txt" -u "${targetBaseUrl}/FUZZ" -mc 200,201,204,301,302,307,401,403 -t 50 -timeout 10 -s 2>/dev/null`,
    'ffuf', TIMEOUTS.FFUF, 0
  );
  if (ffufR.success && ffufR.output && ffufR.output !== '(no output)' && ffufR.output !== '(no paths found)') {
    // FIX: FFUF `-s` outputs one bare path per line (e.g. "api", "admin").
    // Convert each to a full URL before inserting.
    const ffufLines = (ffufR.output || '').split('\n').map(l => l.trim()).filter(Boolean);
    const ffufEpRows = ffufLines
      .map(line => {
        // Already a URL? keep it. Otherwise prepend base.
        if (line.startsWith('http')) return line;
        return `${targetBaseUrl}/${line.replace(/^\//, '')}`;
      })
      .filter(url => isInScope(url, scanContext))
      .map(url => ({ url, source: 'ffuf', has_params: url.includes('?') }));
    if (ffufEpRows.length > 0) {
      scanDB.insertEndpoints(ffufEpRows);
      onProgress({ phase: 'ffuf', status: 'running', message: `   ✅ FFUF discovered ${ffufEpRows.length} paths` });
    }
  }

  // ── Phase 6.7: API Probing (SPA-aware endpoint seeding) ─────────────────────
  // SPAs (Angular, React, Vue) expose API routes that traditional crawlers miss.
  // Probe a curated set of common API paths and register any that respond.
  onProgress({ phase: 'api_probe', status: 'running', message: `🔌 **Phase 6.7:** API endpoint probing (SPA-aware discovery)...` });
  const API_PROBE_PATHS = [
    // Core API
    '/api', '/api/', '/api/Products', '/api/Challenges', '/api/Users',
    '/api/Feedbacks', '/api/Complaints', '/api/Recycles', '/api/SecurityQuestions',
    '/rest/products/search', '/rest/user/login', '/rest/user/whoami',
    '/rest/admin/application-configuration',
    '/rest/basket', '/rest/saveLoginIp', '/rest/deluxe-membership',
    '/rest/continue-code', '/rest/chatbot/status',
    '/api/Quantitys', '/api/Deliverys', '/api/Addresss', '/api/Cards',
    '/snippets', '/metrics', '/profile', '/administration',
    '/accounting', '/b2b/v2/orders', '/ftp',
    '/login', '/register', '/search', '/contact',
    '/redirect', '/promotion', '/video', '/about',
    '/api/v1', '/api/v2', '/graphql', '/swagger.json', '/openapi.json', '/api-docs',
    // Directory listing discovery (CWE-538)
    '/backup', '/uploads', '/files', '/data', '/logs',
    '/private', '/export', '/archive', '/tmp', '/dump',
    '/old', '/staging', '/dev', '/documents',
    '/.git/', '/.svn/', '/.hg/',
    // Upload & auth endpoints (CSRF, file upload bypass)
    '/file-upload', '/complaint', '/profile/image-upload',
    '/forgot-password', '/change-password',
    '/rest/user/change-password', '/rest/user/authentication-details',
    // IDOR targets
    '/api/BasketItems', '/rest/basket/1', '/rest/basket/2',
    '/api/Addresss/1', '/api/Cards/1',
  ];
  const apiProbeBase = targetBaseUrl;
  const apiProbeResults = [];
  // Batch in groups of 5 for speed
  for (let i = 0; i < API_PROBE_PATHS.length; i += 5) {
    if (limiter.shouldStop()) break;
    const batch = API_PROBE_PATHS.slice(i, i + 5);
    const results = await Promise.all(batch.map(async (path) => {
      try {
        const probeUrl = `${apiProbeBase}${path}`;
        const { stdout } = await execAsync(
          `curl -s -o /dev/null -w "%{http_code}" -L -k --max-time 4 "${probeUrl}"`,
          { timeout: 6000 }
        );
        const code = parseInt(stdout.trim(), 10);
        if (code >= 200 && code < 500 && code !== 404) {
          limiter.track(true);
          return { url: probeUrl, source: 'api_probe', has_params: probeUrl.includes('?'), status_code: code };
        }
        limiter.track(true);
      } catch { limiter.track(false); }
      return null;
    }));
    apiProbeResults.push(...results.filter(Boolean));
  }
  if (apiProbeResults.length > 0) {
    scanDB.insertEndpoints(apiProbeResults);
    onProgress({ phase: 'api_probe', status: 'done', message: `✅ **Phase 6.7 done:** ${apiProbeResults.length} API endpoints discovered via probing` });
  } else {
    onProgress({ phase: 'api_probe', status: 'done', message: `✅ **Phase 6.7 done:** 0 additional API endpoints found` });
  }

  // Deep Web Crawling
  onProgress({ phase: 'deep_crawl', status: 'running', message: `🕷️ **Phase 6.5:** Performing deep recursive web crawl (max 60s)...` });
  // FIX: wrap crawler in a top-level timeout so it can never hang the entire pipeline
  const crawlResult = await Promise.race([
    runWebCrawl(scanContext.baseUrl),
    new Promise(resolve => setTimeout(() => resolve({ success: false, error: 'Crawl timeout (60s)' }), 60_000))
  ]);
  if (crawlResult.success) {
    const { endpoints = [], forms = [], parameterizedUrls = [] } = crawlResult;
    const cleanEps = endpoints.filter(u => isInScope(u, scanContext)).map(url => ({ url, source: 'spider' }));
    if (cleanEps.length > 0) scanDB.insertEndpoints(cleanEps);
    if (forms.length > 0) scanDB.insertForms(forms);

    const cleanParams = parameterizedUrls.filter(u => isInScope(u, scanContext)).map(url => ({ url, params: '', param_count: 0 }));
    if (cleanParams.length > 0) scanDB.insertParameters(cleanParams);
  }

  // Phase 6.6 Playwright SPA Crawl
  onProgress({ phase: 'spa_crawl', status: 'running', message: `🕸️ **Phase 6.6:** Authenticated SPA tracing...` });
  try {
    const credentials = scanContext.credentials || { email: "admin@juice-sh.op", password: "admin" };

    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    const apiCalls = [];
    page.on('request', req => {
      if (req.resourceType() === 'fetch' || req.resourceType() === 'xhr') {
        apiCalls.push({ url: req.url(), method: req.method(), postData: req.postData() });
      }
    });

    await page.goto(scanContext.baseUrl);

    // Login form heuristic
    if (credentials.email && credentials.password) {
      try {
        await page.fill('input[type=email]', credentials.email, { timeout: 2000 });
        await page.fill('input[type=password]', credentials.password, { timeout: 2000 });
        await page.click('button[type=submit]', { timeout: 2000 });
      } catch { } // Soft-fail if form not found
    }

    await page.waitForTimeout(3000);
    await browser.close();

    const spaEps = apiCalls
      .filter(c => isInScope(c.url, scanContext))
      .map(c => ({ url: c.url, source: 'spa_fetch', method: c.method }));

    if (spaEps.length > 0) {
      scanDB.insertEndpoints(spaEps);
      onProgress({ phase: 'spa_crawl', status: 'done', message: `✅ SPA crawler discovered ${spaEps.length} internal API routes` });
    }
  } catch (err) {
    onProgress({ phase: 'spa_crawl', status: 'done', message: `⚠️ SPA crawler failed or captured 0 calls` });
  }

  // ── Phase 7: Endpoint Validation ───────────────────────────────────
  const allFinalEndpoints = scanDB.queries.allEndpoints();
  if (allFinalEndpoints.length > 0) {
    const validatedEps = await validateEndpoints(allFinalEndpoints.slice(0, 500), scanContext, limiter, onProgress);
    scanDB._validatedEndpoints = validatedEps;
    onProgress({ phase: 'validation', status: 'done', message: `✅ **Phase 7 complete:** **${validatedEps.length}** endpoints validated.` });
  }

  return finalizeReport(safeTarget, scanDB, onProgress, intel, limiter, scanContext);
}