/**
 * parsers.js — RedVapt Tool Output Parsers
 *
 * Each function accepts raw tool stdout text and returns a structured array.
 * All parsing is done in pure JS — no shell calls, no external I/O.
 *
 * Security: No eval(), no dynamic code execution. All regex are bounded.
 * Input is string-only; callers should ensure type safety before passing.
 */

// ── Shared constants ────────────────────────────────────────────────────────

const INTERESTING_STATUSES = new Set([200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 404, 500, 503]);

const SENSITIVE_TITLE_KEYWORDS = [
    'admin', 'login', 'dashboard', 'api', 'dev', 'test',
    'staging', 'backup', 'portal', 'console', 'manage',
    'config', 'internal', 'secret', 'debug', 'auth',
];

const SENSITIVE_PATH_KEYWORDS = [
    'admin', 'backup', 'config', 'api', 'internal', 'auth',
    'token', 'debug', 'secret', 'upload', 'manage', 'login',
    'console', 'portal', 'dashboard', 'dev', 'staging', 'test',
    '.git', '.env', 'phpinfo', 'wp-admin', 'xmlrpc',
];

// Known WAF signatures
const WAF_SIGNATURES = {
    cloudflare: /cloudflare/i,
    akamai: /akamai/i,
    imperva: /imperva|incapsula/i,
    sucuri: /sucuri/i,
    f5: /f5\s*big-?ip|x-wa-info/i,
    barracuda: /barracuda/i,
    fortiweb: /fortiweb/i,
    aws: /aws-?waf/i,
    modsecurity: /mod_security|modsecurity/i,
    wordfence: /wordfence/i,
    radware: /radware|x-rdwr/i,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function safeLines(text) {
    if (!text || typeof text !== 'string') return [];
    return text.split('\n').map(l => l.trim()).filter(Boolean);
}

function hasSensitiveTitle(title = '') {
    const lower = title.toLowerCase();
    return SENSITIVE_TITLE_KEYWORDS.some(kw => lower.includes(kw));
}

function hasSensitivePath(url = '') {
    const lower = url.toLowerCase();
    return SENSITIVE_PATH_KEYWORDS.some(kw => lower.includes(kw));
}

function getSensitivityTag(url = '') {
    const lower = url.toLowerCase();
    const matched = SENSITIVE_PATH_KEYWORDS.find(kw => lower.includes(kw));
    return matched || null;
}

function getPathDepth(url = '') {
    try {
        const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
        return parsed.pathname.split('/').filter(Boolean).length;
    } catch {
        return url.split('/').filter(Boolean).length;
    }
}

// Normalize a URL to a dedup key: strip query values, keep only param names
function urlDedupKey(url = '') {
    try {
        const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
        const paramNames = [...parsed.searchParams.keys()].sort().join('&');
        return `${parsed.hostname}${parsed.pathname}?${paramNames}`;
    } catch {
        return url.split('?')[0];
    }
}

// Validate a hostname string
const HOSTNAME_RE = /^[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,}$/;
export function isValidHostname(h) {
    return typeof h === 'string' && HOSTNAME_RE.test(h) && h.length <= 253;
}

/**
 * Escapes special characters in a string for use in a regular expression.
 */
export function escapeRegExp(str) {
    if (!str || typeof str !== 'string') return '';
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── URL Sanitization (RC5 fix: recon URL pollution) ────────────────────────
// Catches concatenated URLs, encoded unicode junk, and malformed URLs.
const EXTERNAL_NOISE_DOMAINS = /stackexchange\.com|stackoverflow\.com|github\.com|sqlmap\.org|cyberciti\.biz|fuglekos\.com|emkei\.cz|wikipedia\.org/i;
const UNICODE_JUNK_RE = /%[Ee][0-9A-Fa-f]%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}|%[Cc][0-9A-Fa-f]%[0-9A-Fa-f]{2}/;

export function cleanUrl(raw, targetDomain = null) {
    if (!raw || typeof raw !== 'string') return null;
    let url = raw.trim();

    // Reject obviously too-long URLs
    if (url.length > 500) return null;

    // Split concatenated URLs: find secondary http:// or https://
    const secondHttp = url.indexOf('http', 8);
    if (secondHttp > 0) url = url.slice(0, secondHttp);

    // Reject URLs with encoded unicode junk (markdown artefacts)
    if (UNICODE_JUNK_RE.test(url)) return null;

    // Reject URLs containing external noise domains
    if (EXTERNAL_NOISE_DOMAINS.test(url)) return null;

    // Reject URLs with suspicious patterns (concatenated paths, bad extensions)
    if (/\.aspx-$|\.aspx[A-Z]/.test(url)) return null;

    // Validate with URL parser
    try {
        const parsed = new URL(url);
        // If we have a target domain, reject off-scope URLs
        if (targetDomain) {
            const host = parsed.hostname.toLowerCase();
            const tgt = targetDomain.toLowerCase();
            if (host !== tgt && !host.endsWith('.' + tgt)) return null;
        }
        return parsed.href.slice(0, 500);
    } catch {
        return null;
    }
}

// ── Parser: Subfinder ────────────────────────────────────────────────────────

/**
 * Parses subfinder / ssl-san output.
 * Returns: [{ subdomain, source }]
 */
export function parseSubfinder(text, source = 'subfinder') {
    const seen = new Set();
    return safeLines(text)
        .filter(line => isValidHostname(line))
        .filter(line => {
            if (seen.has(line)) return false;
            seen.add(line);
            return true;
        })
        .map(subdomain => ({ subdomain, source }));
}

// ── Parser: SSL SAN ──────────────────────────────────────────────────────────

export function parseSslSan(text) {
    return parseSubfinder(text, 'ssl-san');
}

// ── Parser: GAU Subdomains ───────────────────────────────────────────────────

/**
 * Extracts hostnames from GAU URLs for subdomain enumeration.
 * Returns: [{ subdomain, source }]
 */
export function parseGauSubdomains(text) {
    const seen = new Set();
    return safeLines(text)
        .map(line => {
            try {
                return new URL(line.startsWith('http') ? line : `https://${line}`).hostname;
            } catch { return null; }
        })
        .filter(host => host && isValidHostname(host))
        .filter(host => {
            if (seen.has(host)) return false;
            seen.add(host);
            return true;
        })
        .map(subdomain => ({ subdomain, source: 'gau-subdomains' }));
}

// ── Parser: Waybackurls (subdomains) ────────────────────────────────────────

/**
 * Extracts unique hostnames/subdomains from waybackurls output.
 * Returns: [{ subdomain, source }]
 */
export function parseWaybackurlsSubdomains(text) {
    const seen = new Set();
    return safeLines(text)
        .map(line => {
            try {
                return new URL(line.trim()).hostname;
            } catch { return null; }
        })
        .filter(host => host && isValidHostname(host))
        .filter(host => {
            if (seen.has(host)) return false;
            seen.add(host);
            return true;
        })
        .map(subdomain => ({ subdomain, source: 'waybackurls' }));
}

// ── Parser: DNS Resolution ───────────────────────────────────────────────────

/**
 * Parses `dig +short` output and maps hostname → IP.
 * Returns: [{ subdomain, ip, resolves }]
 */
export function parseDnsResolve(text, hostname) {
    const ips = safeLines(text)
        .filter(line => /^\d{1,3}(\.\d{1,3}){3}$/.test(line) || /^[0-9a-f:]+$/.test(line, 'i'));
    return [{
        subdomain: hostname,
        ip: ips[0] || null,
        resolves: ips.length > 0,
    }];
}

// ── Parser: httpx ────────────────────────────────────────────────────────────

/**
 * parseHttpxJson — PRIMARY parser.
 * httpx -json outputs one JSON object per line (jsonl format).
 * Fields: url, status_code, title, tech, webserver, host, cdn, a (IPs), etc.
 *
 * Returns: [{ url, status_code, title, technologies, server, ip, cdn, waf }]
 */
export function parseHttpxJson(text) {
    const results = [];
    const seenUrls = new Set();

    for (const line of safeLines(text)) {
        // Strip any ANSI codes defensively
        const clean = line.replace(/\x1B\[[0-9;]*m/g, '').trim();
        if (!clean.startsWith('{')) continue;

        let obj;
        try {
            obj = JSON.parse(clean);
        } catch {
            continue; // skip malformed lines
        }

        const url = obj.url || obj.input || '';
        if (!url || !url.startsWith('http')) continue;
        if (seenUrls.has(url)) continue;
        seenUrls.add(url);

        const status_code = obj.status_code || 0;
        if (!INTERESTING_STATUSES.has(status_code)) continue;

        // Technologies: httpx puts them in obj.tech (array) or obj.technologies (array)
        const techArray = obj.tech || obj.technologies || [];
        const technologies = Array.isArray(techArray) ? techArray.join(', ').slice(0, 200) : String(techArray).slice(0, 200);

        const server = (obj.webserver || obj.server || '').slice(0, 80);
        const title = (obj.title || '').slice(0, 120);
        const ip = (Array.isArray(obj.a) ? obj.a[0] : obj.host || '').slice(0, 45);
        const cdn = Boolean(obj.cdn || obj.cdn_name);

        // WAF detection
        let waf = null;
        const combined = `${server} ${technologies} ${title}`.toLowerCase();
        for (const [wafName, re] of Object.entries(WAF_SIGNATURES)) {
            if (re.test(combined)) { waf = wafName; break; }
        }

        const interesting = hasSensitiveTitle(title) || hasSensitivePath(url) || status_code !== 200;

        results.push({
            url,
            status_code,
            title,
            technologies,
            server,
            ip,
            cdn,
            waf,
            _interesting: interesting,
        });
    }

    results.sort((a, b) => (b._interesting ? 1 : 0) - (a._interesting ? 1 : 0) || a.status_code - b.status_code);
    return results.slice(0, 80).map(({ _interesting, ...r }) => r);
}

/**
 * parseHttpx — TEXT fallback parser (used when -json flag is unavailable).
 * httpx text line format:
 *   https://example.com [200] [Title] [Tech1,Tech2] [Server] [IP] [CDN?]
 *
 * Returns: [{ url, status_code, title, technologies, server, ip, cdn, waf }]
 */
export function parseHttpx(text) {
    const results = [];
    const seenUrls = new Set();

    for (const line of safeLines(text)) {
        const clean = line.replace(/\x1B\[[0-9;]*m/g, '');

        const urlMatch = clean.match(/^(https?:\/\/[^\s]+)/);
        if (!urlMatch) continue;
        const url = urlMatch[1];
        if (seenUrls.has(url)) continue;
        seenUrls.add(url);

        const statusMatch = clean.match(/\[(\d{3})\]/);
        const status_code = statusMatch ? parseInt(statusMatch[1], 10) : 0;
        if (!INTERESTING_STATUSES.has(status_code)) continue;

        const brackets = [...clean.matchAll(/\[([^\]]*)\]/g)].map(m => m[1]);
        const title = brackets[1] || '';
        const technologies = brackets[2] || '';
        const server = brackets[3] || '';
        const ip = brackets[4] || '';
        const cdnField = brackets[5] || '';
        const cdn = cdnField.toLowerCase().includes('cdn') || cdnField === 'true';

        let waf = null;
        const combined = `${server} ${technologies} ${title}`.toLowerCase();
        for (const [wafName, re] of Object.entries(WAF_SIGNATURES)) {
            if (re.test(combined)) { waf = wafName; break; }
        }

        const interesting = hasSensitiveTitle(title) || hasSensitivePath(url) || status_code !== 200;

        results.push({
            url,
            status_code,
            title: title.slice(0, 120),
            technologies: technologies.slice(0, 200),
            server: server.slice(0, 80),
            ip: ip.slice(0, 45),
            cdn,
            waf,
            _interesting: interesting,
        });
    }

    results.sort((a, b) => (b._interesting ? 1 : 0) - (a._interesting ? 1 : 0) || a.status_code - b.status_code);
    return results.slice(0, 80).map(({ _interesting, ...r }) => r);
}

// ── Parser: wafw00f ──────────────────────────────────────────────────────────

/**
 * Parses wafw00f output to detect WAF type.
 * Returns: { detected: bool, waf: string|null, raw: string }
 */
export function parseWafw00f(text) {
    if (!text || typeof text !== 'string') return { detected: false, waf: null, raw: '' };

    // Common wafw00f output patterns:
    //   "The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
    //   "No WAF detected by the simple detect"
    const behindMatch = text.match(/is behind (.+?) (?:\(.+?\) )?WAF/i);
    if (behindMatch) {
        return { detected: true, waf: behindMatch[1].trim().slice(0, 60), raw: text.slice(0, 200) };
    }

    const noWaf = /no waf detected|not detected/i.test(text);
    return { detected: false, waf: null, raw: text.slice(0, 200) };
}

// ── Parser: Nmap ─────────────────────────────────────────────────────────────

/**
 * Parses nmap text output. Extracts open ports only.
 * Returns: [{ host, port, state, service, version }]
 */
export function parseNmap(text, defaultHost = '') {
    const results = [];
    let currentHost = defaultHost;

    for (const line of safeLines(text)) {
        const hostMatch = line.match(/^Nmap scan report for (.+)/);
        if (hostMatch) {
            currentHost = hostMatch[1].replace(/\s*\([^)]+\)/, '').trim();
            continue;
        }

        const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)/i);
        if (!portMatch) continue;

        const [, port, , state, service, version] = portMatch;
        results.push({
            host: currentHost,
            port: parseInt(port, 10),
            state,
            service: service.slice(0, 40),
            version: version.trim().slice(0, 100),
        });
    }

    return results;
}

// ── Parser: GAU Endpoints ────────────────────────────────────────────────────

/**
 * Filters GAU URL dump to high-value endpoints only.
 * Returns: [{ url, has_params, path_depth, sensitivity_tag }] — max 150 rows
 */
export function parseGauEndpoints(text) {
    if (!text || typeof text !== 'string') return [];

    const dedupKeys = new Set();
    const results = [];

    for (const line of safeLines(text)) {

        // RC5 fix: validate and sanitize URL before processing
        const url = cleanUrl(line);
        if (!url) continue;

        if (!url.startsWith('http')) continue;
        if (/\.(png|jpg|jpeg|gif|css|svg|woff|woff2|ttf|eot|ico|mp4|mp3|pdf|zip)(\?|$)/i.test(url)) continue;

        const has_params = url.includes('?');
        const path_depth = getPathDepth(url);
        const sensitivity = getSensitivityTag(url);

        // Relaxed Filter: Keep if it has params, sensitive keywords, OR depth >= 1 (keep almost everything that isn't root)
        if (!has_params && path_depth < 1 && !sensitivity) continue;

        const key = urlDedupKey(url);
        if (dedupKeys.has(key)) continue;
        dedupKeys.add(key);

        results.push({
            url,
            has_params,
            path_depth,
            sensitivity_tag: sensitivity,
        });

        if (results.length >= 150) break;
    }

    results.sort((a, b) => {
        if (a.sensitivity_tag && !b.sensitivity_tag) return -1;
        if (!a.sensitivity_tag && b.sensitivity_tag) return 1;
        if (a.has_params && !b.has_params) return -1;
        if (!a.has_params && b.has_params) return 1;
        return b.path_depth - a.path_depth;
    });

    return results;
}

// ── Parser: Waybackurls Endpoints ────────────────────────────────────────────

/**
 * Waybackurls outputs one URL per line. Filter and deduplicate.
 * Returns same format as parseGauEndpoints.
 */
export function parseWaybackurlsEndpoints(text) {
    return parseGauEndpoints(text); // identical filtering logic
}


// ── Parser: LinkFinder ───────────────────────────────────────────────────────

/**
 * LinkFinder -o cli outputs one discovered endpoint per line.
 * Returns: [{ url, is_relative, sensitivity_tag }]
 */
export function parseLinkFinder(text) {
    const seen = new Set();
    const results = [];

    for (const line of safeLines(text)) {
        // Skip non-URL garbage (comments, HTML tags, etc.)
        if (line.startsWith('<') || line.startsWith('#') || line.length > 500) continue;

        let rawUrl = line.trim();

        // RC5 fix: for absolute URLs, validate and sanitize
        const is_relative = !rawUrl.startsWith('http');
        if (!is_relative) {
            rawUrl = cleanUrl(rawUrl) || '';
            if (!rawUrl) continue;
        } else {
            // For relative URLs, reject obvious junk
            if (UNICODE_JUNK_RE.test(rawUrl)) continue;
            if (rawUrl.length > 400) continue;
        }

        if (seen.has(rawUrl)) continue;
        seen.add(rawUrl);

        const sensitivity = getSensitivityTag(rawUrl);

        // Skip likely-useless: root-only, no interesting signals
        if (is_relative && rawUrl === '/') continue;
        if (!is_relative && /\.(png|jpg|gif|ico|css|woff)/i.test(rawUrl)) continue;

        results.push({
            url: rawUrl.slice(0, 400),
            is_relative,
            sensitivity_tag: sensitivity,
        });

        if (results.length >= 100) break;
    }

    // Relative paths are often the most interesting (internal endpoints)
    results.sort((a, b) => {
        if (a.sensitivity_tag && !b.sensitivity_tag) return -1;
        if (!a.sensitivity_tag && b.sensitivity_tag) return 1;
        if (a.is_relative && !b.is_relative) return -1;
        if (!a.is_relative && b.is_relative) return 1;
        return 0;
    });

    return results;
}

// ── Parser: ParamSpider ──────────────────────────────────────────────────────

/**
 * ParamSpider outputs URLs with discovered parameters, one per line.
 * Returns: [{ url, params, param_count }]
 */
export function parseParamSpider(text) {
    const dedupKeys = new Set();
    const results = [];

    for (const line of safeLines(text)) {
        // Skip ParamSpider header/info lines
        if (/^\[|\bLoading\b|\bFetching\b|\bParameters\b|\bTotal\b/i.test(line)) continue;

        const url = line.trim();
        if (!url.startsWith('http')) continue;

        try {
            const parsed = new URL(url);
            const params = [...parsed.searchParams.keys()];
            if (params.length === 0) continue;

            const key = `${parsed.hostname}${parsed.pathname}?${params.sort().join('&')}`;
            if (dedupKeys.has(key)) continue;
            dedupKeys.add(key);

            results.push({
                url: url.slice(0, 500),
                params: params.join(', ').slice(0, 200),
                param_count: params.length,
            });

            if (results.length >= 100) break;
        } catch {
            continue;
        }
    }

    // Most params first = most attack surface
    results.sort((a, b) => b.param_count - a.param_count);

    return results;
}

// ── Parser: Subjs ────────────────────────────────────────────────────────────

/**
 * subjs outputs one JS URL per line from page source.
 * Returns: [{ url, source: 'subjs' }]
 */
export function parseSubjs(text) {
    const seen = new Set();
    return safeLines(text)
        .filter(line => line.startsWith('http') && /\.js([?#].*)?$/i.test(line))
        .filter(line => {
            if (seen.has(line)) return false;
            seen.add(line);
            return true;
        })
        .slice(0, 300)
        .map(url => ({ url: url.slice(0, 500), source: 'subjs' }));
}

// ── Parser: GetJS ────────────────────────────────────────────────────────────

/**
 * getJS outputs one JS URL per line.
 * Returns: [{ url, source: 'getjs' }]
 */
export function parseGetjs(text) {
    const seen = new Set();
    return safeLines(text)
        .filter(line => line.startsWith('http') && /\.js([?#].*)?$/i.test(line))
        .filter(line => {
            if (seen.has(line)) return false;
            seen.add(line);
            return true;
        })
        .slice(0, 300)
        .map(url => ({ url: url.slice(0, 500), source: 'getjs' }));
}

// ── Parser: Wappalyzer ───────────────────────────────────────────────────────

/**
 * Wappalyzer CLI outputs JSON with detected technologies.
 * Format: { "urls": {...}, "technologies": [{ "slug", "name", "versions", "categories": [{ "id", "slug", "name" }], "confidence", "website" }] }
 * Returns: [{ name, category, version, confidence, website }]
 */
export function parseWappalyzer(text) {
    if (!text || typeof text !== 'string') return [];

    try {
        // Wappalyzer can output multiple JSON objects or extra text - find the JSON
        const jsonStart = text.indexOf('{');
        const jsonEnd = text.lastIndexOf('}');
        if (jsonStart === -1 || jsonEnd === -1) return [];

        const json = JSON.parse(text.slice(jsonStart, jsonEnd + 1));
        const techs = json.technologies || [];

        return techs.map(t => ({
            name: (t.name || t.slug || 'unknown').slice(0, 80),
            category: (t.categories || []).map(c => c.name || c.slug).join(', ').slice(0, 120) || 'Unknown',
            version: (t.versions || []).join(', ').slice(0, 60) || null,
            confidence: t.confidence || 0,
            website: (t.website || '').slice(0, 200),
        })).sort((a, b) => b.confidence - a.confidence);
    } catch {
        // If JSON parsing fails, try line-by-line extraction as fallback
        return [];
    }
}

