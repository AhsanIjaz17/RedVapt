/**
 * preprocessor.js — RedVapt Deterministic Preprocessing Layer
 *
 * Layer 1 of the AI pipeline. Runs BEFORE any LLM call.
 *
 * Responsibilities:
 *  - SHA1-based fingerprint deduplication
 *  - Type classification (endpoint | live_host | secret | service | parameter)
 *  - URL normalization (protocol strip, lowercase, sort params)
 *  - Static asset filtering
 *  - Output: typed ReconItem[] — never raw strings
 *
 * Security: Pure JS, no shell calls, no dynamic eval.
 * Performance: O(n) pass over DB rows, Set-based dedup.
 */

import { createHash } from 'crypto';

// ── ReconItem Types ────────────────────────────────────────────────────────────
export const ITEM_TYPES = Object.freeze({
    SUBDOMAIN: 'subdomain',
    LIVE_HOST: 'live_host',
    SERVICE: 'service',
    ENDPOINT: 'endpoint',
    JS_FILE: 'js_file',
    JS_ENDPOINT: 'js_endpoint',
    SECRET: 'secret',
    PARAMETER: 'parameter',
});

// ── Static asset extensions to suppress ──────────────────────────────────────
const STATIC_EXT_RE = /\.(png|jpg|jpeg|gif|svg|ico|webp|css|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|tar|gz)(\?.*)?$/i;

// ── Fingerprint helpers ────────────────────────────────────────────────────────

/**
 * Deterministic SHA1 fingerprint for dedup.
 * Keeps token cost down — same logical endpoint = one item.
 */
function fingerprint(...parts) {
    return createHash('sha1').update(parts.join('|')).digest('hex');
}

/**
 * Normalize a URL to a stable dedup key.
 * Strips protocol, lowercases host, sorts query param names (not values).
 */
function normalizeUrl(url = '') {
    try {
        const u = new URL(url.startsWith('http') ? url : `https://${url}`);
        const paramNames = [...u.searchParams.keys()].sort().join(',');
        return `${u.hostname.toLowerCase()}${u.pathname.replace(/\/+$/, '')}?${paramNames}`;
    } catch {
        return url.toLowerCase().split('?')[0];
    }
}

/**
 * Extract hostname from URL safely.
 */
function extractHostname(url = '') {
    try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname; }
    catch { return url; }
}

// ── Timestamp ─────────────────────────────────────────────────────────────────
const NOW = new Date().toISOString();

// ── Item builders ─────────────────────────────────────────────────────────────

function buildItem(type, data, source) {
    return {
        type,
        data,
        fingerprint: fingerprint(type, JSON.stringify(data)),
        raw_source: source,
        discovered_at: NOW,
    };
}

// ── Main Preprocessor ─────────────────────────────────────────────────────────

/**
 * Preprocesses all scan DB data into a deduplicated, typed ReconItem[].
 *
 * @param {object} scanDB - The scan DB returned by createScanDB()
 * @returns {ReconItem[]} - Array of typed, deduplicated, normalized items
 */
export function preprocess(scanDB) {
    const { queries } = scanDB;
    const seen = new Set(); // fingerprint dedup set
    const items = [];

    function addItem(item) {
        if (seen.has(item.fingerprint)) return;
        seen.add(item.fingerprint);
        items.push(item);
    }

    // ── Subdomains ──────────────────────────────────────────────────────────
    for (const row of queries.allSubdomains()) {
        const fp = fingerprint(ITEM_TYPES.SUBDOMAIN, row.subdomain.toLowerCase());
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.SUBDOMAIN,
            data: {
                subdomain: row.subdomain.toLowerCase(),
                source: row.source,
                resolves: Boolean(row.resolves),
                ip: row.ip || null,
            },
            fingerprint: fp,
            raw_source: row.source,
            discovered_at: NOW,
        });
    }

    // ── Live Hosts ──────────────────────────────────────────────────────────
    for (const row of queries.allLiveHosts()) {
        const hostname = extractHostname(row.url);
        const fp = fingerprint(ITEM_TYPES.LIVE_HOST, hostname, String(row.status_code));
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.LIVE_HOST,
            data: {
                url: row.url,
                hostname,
                status_code: row.status_code,
                title: (row.title || '').slice(0, 100),
                technologies: (row.technologies || '').slice(0, 150),
                server: (row.server || '').slice(0, 60),
                ip: row.ip || null,
                cdn: Boolean(row.cdn),
                waf: row.waf || null,
            },
            fingerprint: fp,
            raw_source: 'httpx',
            discovered_at: NOW,
        });
    }

    // ── Services ────────────────────────────────────────────────────────────
    for (const row of queries.allServices()) {
        const fp = fingerprint(ITEM_TYPES.SERVICE, row.host, String(row.port));
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.SERVICE,
            data: {
                host: row.host,
                port: row.port,
                state: row.state,
                service: (row.service || '').slice(0, 40),
                version: (row.version || '').slice(0, 80),
            },
            fingerprint: fp,
            raw_source: 'nmap',
            discovered_at: NOW,
        });
    }

    // ── Endpoints ───────────────────────────────────────────────────────────
    for (const row of queries.allEndpoints()) {
        if (STATIC_EXT_RE.test(row.url)) continue; // skip static assets

        const normalized = normalizeUrl(row.url);
        const fp = fingerprint(ITEM_TYPES.ENDPOINT, normalized);
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.ENDPOINT,
            data: {
                url: row.url.slice(0, 400),
                normalized_key: normalized.slice(0, 300),
                has_params: Boolean(row.has_params),
                path_depth: row.path_depth || 0,
                sensitivity_tag: row.sensitivity_tag || null,
                source: row.source || 'gau',
            },
            fingerprint: fp,
            raw_source: row.source || 'gau',
            discovered_at: NOW,
        });
    }

    // ── JS Files ────────────────────────────────────────────────────────────
    for (const row of queries.allJsFiles()) {
        const fp = fingerprint(ITEM_TYPES.JS_FILE, row.url);
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.JS_FILE,
            data: {
                url: row.url.slice(0, 400),
                source: row.source || 'crawler',
            },
            fingerprint: fp,
            raw_source: row.source || 'crawler',
            discovered_at: NOW,
        });
    }

    // ── JS Endpoints (from LinkFinder) ───────────────────────────────────────
    for (const row of queries.allJsEndpoints()) {
        const fp = fingerprint(ITEM_TYPES.JS_ENDPOINT, row.js_url, row.endpoint);
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.JS_ENDPOINT,
            data: {
                js_url: row.js_url.slice(0, 300),
                endpoint: row.endpoint.slice(0, 200),
                is_relative: Boolean(row.is_relative),
                sensitivity_tag: row.sensitivity_tag || null,
            },
            fingerprint: fp,
            raw_source: 'linkfinder',
            discovered_at: NOW,
        });
    }

    // ── Parameters (from ParamSpider) ────────────────────────────────────────
    for (const row of queries.allParameters()) {
        const fp = fingerprint(ITEM_TYPES.PARAMETER, normalizeUrl(row.url));
        if (seen.has(fp)) continue;
        seen.add(fp);
        items.push({
            type: ITEM_TYPES.PARAMETER,
            data: {
                url: row.url.slice(0, 400),
                params: row.params.slice(0, 200),
                param_count: row.param_count,
            },
            fingerprint: fp,
            raw_source: 'paramspider',
            discovered_at: NOW,
        });
    }

    return items;
}

/**
 * Mask a secret value for safe storage/display.
 * Shows first 4 + last 4 chars, replaces middle with ***
 */
function maskSecret(value = '') {
    if (value.length <= 10) return '***';
    return `${value.slice(0, 4)}***${value.slice(-4)}`;
}

/**
 * Get preprocessing stats summary (for progress reporting).
 */
export function getPreprocessStats(items) {
    const counts = {};
    for (const item of items) {
        counts[item.type] = (counts[item.type] || 0) + 1;
    }
    return {
        total: items.length,
        by_type: counts,
    };
}
