/**
 * engine/verifiers/signalEngine.js — Signal Detection Engine
 *
 * The CORE of the hybrid pipeline. Performs a baseline + injected request pair
 * and produces a structured Signal object with a 0–1 confidence score.
 *
 * Signal is NOT a confirmed vulnerability — it's a ranked trigger for the
 * verifier layer (sqlmap, dalfox, nuclei).
 *
 * Confidence scoring (additive):
 *   SQL error pattern match       → +0.50
 *   SSTI math evaluation (49)     → +0.55
 *   XSS token raw reflection      → +0.60
 *   Timing delay ≥ threshold      → +0.80
 *   Status code changed           → +0.15
 *   Body size diff > 5%           → +0.10
 *   Response diff score < 0.85    → +0.10
 *   Token in attribute/event      → +0.20 (on top of reflection)
 *   DOM structure changed         → +0.10
 *   Error keyword in body         → +0.10
 *
 * Signal types:
 *   sqli_error      — SQL error pattern in body
 *   sqli_timing     — response delayed by timing payload
 *   sqli_boolean    — body diff between true/false condition
 *   xss_reflection  — token reflected in response body
 *   xss_sink        — token in executable JS sink / event handler
 *   ssti_eval       — mathematical evaluation confirmed (7*7=49)
 *   lfi_file_read   — OS file content confirmed (/etc/passwd, win.ini)
 *   lfi_partial     — path disclosure error (file not found, include warning)
 *   info_disclosure — sensitive data leaked (credentials, config, source)
 */

import axios from 'axios';
import https from 'https';
import { globalSession } from '../../utils/sessionManager.js';

const HTTP_TIMEOUT = 12_000;
const MAX_BODY = 50_000;  // RC4 fix: was 8000 — truncation made all sizes identical

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

const httpClient = axios.create({
    timeout: HTTP_TIMEOUT,
    validateStatus: () => true,
    maxRedirects: 10, // R7: Follow redirects aggressively
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RedVapt-Signal/2.0)' },
    httpsAgent: insecureAgent,
});

/**
 * Smart URL normalization for targets that serve on HTTP despite having HTTPS.
 * TestFire, Altoro Mutual, many legacy ASPX apps serve on HTTP.
 * CACHED per hostname to avoid repeating the probe on every single signal detection call.
 */
const _protocolCache = new Map();

async function resolveWorkingProtocol(baseUrl) {
    try {
        const hostname = new URL(baseUrl).hostname;
        if (_protocolCache.has(hostname)) return _protocolCache.get(hostname);

        const variants = [baseUrl, baseUrl.replace('https://', 'http://')];
        for (const url of variants) {
            try {
                const r = await httpClient.head(url, { timeout: 5000, maxRedirects: 3 });
                if (r.status >= 200 && r.status < 400) {
                    _protocolCache.set(hostname, url);
                    console.log(`[SignalEngine] Protocol resolved for ${hostname}: ${url}`);
                    return url;
                }
            } catch { }
        }
        _protocolCache.set(hostname, baseUrl);
        return baseUrl;
    } catch {
        return baseUrl; // Parse error — return as-is
    }
}

/**
 * Generate a unique SSTI probe with random operands.
 * Returns: { payload, expectedResult }
 * e.g. { payload: '{{137*193}}', expectedResult: '26441' }
 */
export function generateSSTIProbe() {
    const a = Math.floor(Math.random() * 900) + 100; // 100-999
    const b = Math.floor(Math.random() * 900) + 100; // 100-999
    const expected = String(a * b);
    return {
        // Test multiple template syntaxes in one shot
        payload: `{{${a}*${b}}}\${${a}*${b}}#{${a}*${b}}`,
        expectedResult: expected,
        a, b
    };
}

// ── SQL error patterns ───────────────────────────────────────────────────────

const SQL_ERRORS = [
    // MySQL
    /SQL syntax.*MySQL/i,
    /you have an error in your sql syntax/i,
    /mysql_fetch_array/i,
    /Warning.*mysql_/i,
    /supplied argument is not a valid MySQL/i,
    // Oracle
    /ORA-\d{5}/i,
    /oracle.*error/i,
    /quoted string not properly terminated/i,
    // MSSQL
    /Microsoft.*ODBC.*SQL Server/i,
    /Incorrect syntax near/i,
    /Unclosed quotation mark/i,
    /Syntax error.*converting/i,
    // PostgreSQL
    /PostgreSQL.*ERROR/i,
    /pg_query\(\)/i,
    /unterminated quoted string/i,
    // SQLite
    /sqlite3?\./i,
    // Generic
    /SQLSTATE\[/i,
    /Syntax error or access violation/i,
    /DB Error/i,
    /database error/i,
    /invalid query/i,
    /query failed/i,
    // ── Java / JSP (TestFire / Altoro Mutual specific) ──
    /java\.sql\.SQL/i,
    /java\.sql\.PreparedStatement/i,
    /javax\.servlet\.ServletException/i,
    /java\.lang\.\w*Exception/i,
    /org\.apache\.tomcat/i,
    /org\.springframework/i,
    /Hibernate.*Exception/i,
    /Error processing request/i,
    /JDBC.*Exception/i,
    /com\.ibm\..*Exception/i,  // WebSphere
    /weblogic\..*Exception/i,  // WebLogic
    // Stack traces (generic)
    /at\s+[a-z][\w.]+\.(java|jsp):\d+/i,
    /at\s+com\.\w+\.\w+/i,
    // HTTP 500 with SQL context
    /500 Internal Server Error.*sql/i,
];

// ── SSTI detection ────────────────────────────────────────────────────────────

const SSTI_PATTERNS = [
    /\b49\b/,      // {{7*7}} = 49
    /Jinja2|Twig|Freemarker|Smarty|Velocity|Pebble/i,
];

// ── Error keywords (generic server errors) ─────────────────────────────────

const ERROR_KEYWORDS = [
    /exception|traceback|stack trace|fatal error|parse error|syntax error/i,
    /internal server error|warning|invalid input|deprecated|unexpected error/i,
    /undefined index|undefined variable/i,
];

// ── LFI / Path Traversal patterns ────────────────────────────────────────────

const LFI_PATTERNS = [
    // Linux /etc/passwd format (the definitive LFI proof)
    /root:x:0:0:/,
    /root:.*:0:0:/,
    /daemon:x:\d+:\d+:/,
    /nobody:x:\d+:\d+:/,
    /www-data:x:\d+:\d+:/,
    /bin\/(?:bash|sh|nologin|false)/,
    // Windows win.ini / boot.ini
    /\[boot loader\]/i,
    /\[fonts\]/i,
    /\[extensions\]/i,
    /; for 16-bit app support/i,
    // /proc files
    /Linux version \d+\.\d+/,
    /DOCUMENT_ROOT=|SERVER_SOFTWARE=|PATH=\//,
];

// LFI partial signals (path errors suggesting the param touches filesystem)
const LFI_PARTIAL_PATTERNS = [
    /No such file or directory/i,
    /failed to open stream/i,
    /include_path/i,
    /Warning:.*(?:include|require|file_get_contents|fopen|readfile)/i,
    /java\.io\.FileNotFoundException/i,
    /ENOENT/i,
];

// Information Disclosure patterns
const INFO_DISCLOSURE_PATTERNS = [
    /DB_PASSWORD|DB_HOST|DATABASE_URL|MONGO_URI/i,
    /SECRET_KEY|API_KEY|AWS_SECRET|PRIVATE_KEY/i,
    /\[core\]\s*\n\s*repositoryformatversion/i,
    /ref:\s*refs\/heads\//i,
    /phpinfo\(\)/i,
    /PHP Version \d+\.\d+/i,
    /Index of \//i,
    /Directory listing for/i,
];

// ── Request builder ───────────────────────────────────────────────────────────

function buildUrl(url, paramName, paramValue, injectIn, hiddenFields = {}) {
    if (injectIn === 'json_body') {
        return {
            reqUrl: url,
            data: JSON.stringify({ ...hiddenFields, [paramName]: paramValue }),
            headers: { 'Content-Type': 'application/json' },
        };
    }
    if (injectIn === 'query' || !injectIn) {
        const sep = url.includes('?') ? '&' : '?';
        return {
            reqUrl: `${url}${sep}${encodeURIComponent(paramName)}=${encodeURIComponent(paramValue)}`,
            data: undefined,
            headers: {},
        };
    }
    if (injectIn === 'body') {
        const extra = Object.entries(hiddenFields).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
        return {
            reqUrl: url,
            data: `${encodeURIComponent(paramName)}=${encodeURIComponent(paramValue)}${extra ? '&' + extra : ''}`,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        };
    }
    if (injectIn === 'header') {
        return { reqUrl: url, data: undefined, headers: { [paramName]: paramValue } };
    }
    return { reqUrl: url, data: undefined, headers: {} };
}

async function probe(url, method, paramName, value, injectIn, timeoutMs = HTTP_TIMEOUT, hiddenFields = {}, retryCount = 1) {
    const { reqUrl, data, headers } = buildUrl(url, paramName, value, injectIn, hiddenFields);

    // R7: Attach session cookies
    const cookieHeader = globalSession.getCookieHeader();
    const finalHeaders = { ...headers };
    if (cookieHeader) finalHeaders['Cookie'] = cookieHeader;

    const start = Date.now();
    try {
        const resp = await axios({
            method: (method || 'GET').toLowerCase(),
            url: reqUrl,
            data,
            headers: finalHeaders,
            timeout: timeoutMs,
            validateStatus: () => true,
            maxRedirects: 5,
        });

        if (resp.status === 429 && retryCount > 0) {
            const delay = Math.floor(Math.random() * 5000) + 5000;
            await new Promise(r => setTimeout(r, delay));
            return probe(url, method, paramName, value, injectIn, timeoutMs, hiddenFields, retryCount - 1);
        }

        const body = (typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '')).slice(0, MAX_BODY);

        // R7: Update session with new cookies and tokens
        globalSession.updateFromHeaders(resp.headers);
        globalSession.extractTokens(body);

        // RC4 fix: use Content-Length header for accurate size comparison (not truncated body)
        const contentLength = parseInt(resp.headers['content-length'] || '0', 10) || body.length;
        return {
            ok: true,
            status: resp.status,
            body,
            elapsed: Date.now() - start,
            contentType: resp.headers['content-type'] || '',
            size: contentLength,  // use real size from header, not truncated body
            contentLength,
            headers: resp.headers,
            // R9/R10: Captured evidence for professional reports
            request: {
                method: (method || 'GET').toUpperCase(),
                url: reqUrl,
                headers: { ...headers, 'User-Agent': 'Mozilla/5.0 (compatible; RedVapt-Signal/2.0)' },
                data: data || null
            }
        };
    } catch (err) {
        return { ok: false, status: 0, body: '', elapsed: Date.now() - start, contentType: '', size: 0, contentLength: 0, error: err.message };
    }
}

/**
 * R12: Strip dynamic content to allow stable comparison.
 */
function normalizeBody(html) {
    if (!html || typeof html !== 'string') return html;
    return html
        .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g, '[TS]')
        .replace(/\d{4}\/\d{2}\/\d{2}(?: \d{2}:\d{2}:\d{2})?/g, '[TS]')
        .replace(/(?:csrf|token|nonce|auth)["']?\s*[:=]\s*["']([a-f0-9]{16,}|[a-zA-Z0-9+/]{16,}=*)["']/gi, '$1:"[TOKEN]"')
        .replace(/value=["']([a-f0-9]{16,}|[a-zA-Z0-9+/]{16,}=*)["']/gi, 'value="[TOKEN]"')
        .replace(/UA-\d+-\d+/g, '[GA]')
        .replace(/G-[A-Z0-9]+/g, '[GA]')
        .replace(/\b\d{6,}\b/g, '[NUM]')
        .replace(/\b0x[a-f0-9]{6,}\b/gi, '[HEX]');
}

async function getStableProbe(url, method, paramName, value, injectIn, timeoutMs, samples = 3, hiddenFields = {}) {
    const results = [];
    for (let i = 0; i < samples; i++) {
        results.push(await probe(url, method, paramName, value, injectIn, timeoutMs, hiddenFields));
        if (i < samples - 1) await new Promise(r => setTimeout(r, 100));
    }
    const valid = results.filter(r => r.ok);
    if (valid.length === 0) return results[0];
    const avgElapsed = valid.reduce((acc, r) => acc + r.elapsed, 0) / valid.length;
    const avgSize = valid.reduce((acc, r) => acc + r.size, 0) / valid.length;
    const variance = valid.reduce((acc, r) => acc + Math.pow(r.elapsed - avgElapsed, 2), 0) / valid.length;
    const stdDev = Math.sqrt(variance);
    return { ...valid[0], elapsed: avgElapsed, size: avgSize, stdDev, allSamples: valid };
}

// ── Body similarity (0 = identical, 1 = completely different) ─────────────────

function diffRatio(a, b) {
    if (!a && !b) return 0;
    const longer = Math.max(a.length, b.length) || 1;
    let diffs = 0;
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) { if (a[i] !== b[i]) diffs++; }
    diffs += Math.abs(a.length - b.length);
    return diffs / longer;
}

function countHtmlTags(body) {
    return (body.match(/<[a-z][a-z0-9]*/gi) || []).length;
}

// ── Snippet extractor: grab context around a match ────────────────────────────

function extractSnippet(body, match, radius = 150) {
    const idx = body.indexOf(match);
    if (idx === -1) return body.slice(0, 300);
    return body.slice(Math.max(0, idx - radius), idx + match.length + radius);
}

// ── XSS sink check ────────────────────────────────────────────────────────────

function isInSink(body, token) {
    const sinks = [
        new RegExp(`alert\\(['\"]?${token}['\"]?\\)`, 'i'),
        new RegExp(`on\\w+\\s*=\\s*[^>]*${token}`, 'i'),
        new RegExp(`<script[^>]*>[^<]*${token}`, 'i'),
    ];
    return sinks.some(p => p.test(body));
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Detect a signal by comparing baseline vs injected responses.
 *
 * @param {object} opts
 * @param {string}  opts.url
 * @param {string}  opts.method
 * @param {string}  opts.paramName
 * @param {string}  opts.injectIn      - 'query' | 'body' | 'header'
 * @param {string}  opts.payload       - injected value (with proofToken already substituted)
 * @param {string}  opts.baselineValue - safe benign value
 * @param {string}  opts.proofToken    - unique token embedded in payload (XSS)
 * @param {string}  opts.vulnType      - 'XSS' | 'SQLi' | 'SSTI'
 * @param {number}  [opts.expectedDelay=0] - for timing attacks
 * @param {object}  opts.hiddenFields  - hidden fields to inject in body
 *
 * @returns {Promise<{
 *   signal: boolean,
 *   signalType: string|null,
 *   confidence: number,
 *   proofToken: string,
 *   evidenceSnippet: string,
 *   baseline: object,
 *   injected: object,
 *   diffScore: number,
 *   isWafBlock: boolean
 * }>}
 */
export async function detectSignal({ url, method, paramName, injectIn, payload, baselineValue, proofToken, vulnType, expectedDelay = 0, hiddenFields = {} }) {
    // [S2 FIX] Always respect the target's actual protocol.
    // The old code "preferred HTTP" but Heroku/cloud targets redirect HTTP→HTTPS
    // via 301, which strips Authorization headers. This broke JWT auth for Juice Shop.
    // Now: use the protocol as-is. Only fall back if HTTPS connection is refused.
    let workingUrl = url;
    if (url.startsWith('https://')) {
        try {
            // Quick HTTPS check — if it works, use it
            await httpClient.head(url, { timeout: 4000, maxRedirects: 0, validateStatus: () => true });
            // HTTPS is fine — keep workingUrl as HTTPS
        } catch (err) {
            // HTTPS completely failed (ECONNREFUSED) → try HTTP
            if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
                const httpUrl = url.replace('https://', 'http://');
                try {
                    const r = await httpClient.head(httpUrl, { timeout: 4000, validateStatus: () => true });
                    if (r.status < 500) workingUrl = httpUrl;
                } catch {}
            }
            // For redirects (301/302): stay on HTTPS — don't downgrade
        }
    }

    // ── Pre-check WAF blocks ────────────────────────────────────────────────
    const WAF_BLOCKS = ["Mod_Security", "Not Acceptable", "Request blocked", "Access denied", "Forbidden"];
    const checkWaf = (body) => {
        if (!body) return false;
        return WAF_BLOCKS.some(waf => body.includes(waf) || (waf.toLowerCase() === 'forbidden' && body.includes('403')));
    };
    let expectedSstiResult = null;
    if (vulnType === 'SSTI') {
        const sstiProbe = generateSSTIProbe();
        payload = sstiProbe.payload;
        expectedSstiResult = sstiProbe.expectedResult;
    }

    let falsePayload = null;
    if (vulnType === 'SQLi') {
        if (payload.includes('1=1')) falsePayload = payload.replace('1=1', '1=0');
        else if (payload.includes("1'='1")) falsePayload = payload.replace("1'='1", "1'='0");
        else falsePayload = payload + " AND 1=0";
    }

    const probeTimeout = expectedDelay > 0 ? Math.max(20_000, expectedDelay * 2) : HTTP_TIMEOUT;
    let b = await probe(workingUrl, method, paramName, baselineValue || '1', injectIn, HTTP_TIMEOUT, hiddenFields);
    let i = await probe(workingUrl, method, paramName, payload, injectIn, probeTimeout, hiddenFields);
    let f = falsePayload ? await probe(workingUrl, method, paramName, falsePayload, injectIn, probeTimeout, hiddenFields) : null;

    if (!b.ok && !i.ok) return { signal: false, confidence: 0, b, i, isWafBlock: false };

    // WAF Block check on injected response
    if (i.status === 403 || i.status === 406 || checkWaf(i.body)) {
        return { signal: false, signalType: 'waf_block', confidence: 0, proofToken, evidenceSnippet: 'Blocked / Filtered (WAF inferred)', baseline: b, injected: i, diffScore: 0, isWafBlock: true };
    }

    const initialScore = calculateConfidence(b, i, f, vulnType, expectedDelay, proofToken, null, null, null, expectedSstiResult);

    // ── R11/R12: Stability Check (Repeated Sampling) ─────────────────────────
    // If we have a hint of a signal (>0.15), stabilize with 3x sampling
    if (initialScore.confidence > 0.15) {
        b = await getStableProbe(workingUrl, method, paramName, baselineValue || '1', injectIn, HTTP_TIMEOUT, 3, hiddenFields);
        i = await getStableProbe(workingUrl, method, paramName, payload, injectIn, probeTimeout, 3, hiddenFields);
        if (f) f = await getStableProbe(workingUrl, method, paramName, falsePayload, injectIn, probeTimeout, 3, hiddenFields);
    }

    // ── R12: Normalized Diffing ───────────────────────────────────────────────
    // Compare normalized bodies to ignore dynamic noise (TS, tokens, etc)
    const normB = normalizeBody(b.body);
    const normI = normalizeBody(i.body);

    const normF = f ? normalizeBody(f.body) : null;

    const { confidence, signalType, evidenceSnippet, metrics } = calculateConfidence(b, i, f, vulnType, expectedDelay, proofToken, normB, normI, normF, expectedSstiResult);

    // ── R11: Jitter Guard ────────────────────────────────────────────────────
    // If timing attack: delay must be > baseline avg + (3 * stdDev) to be real
    if (expectedDelay > 0 && signalType === 'sqli_timing') {
        const threshold = b.elapsed + (b.stdDev * 3) + 200; // 3 sigma + 200ms buffer
        if (i.elapsed < threshold) {
            return { signal: false, confidence: 0, signalType: 'jitter_noise', baseline: b, injected: i, isWafBlock: false };
        }
    }

    return {
        signal: confidence > 0,
        signalType,
        confidence,
        proofToken,
        evidenceSnippet,
        baseline: b,
        injected: i,
        diffScore: metrics.bodyDiff,
        metrics,
        isWafBlock: false
    };
}

/**
 * Isolated scoring logic to allow retry/stabilization re-scoring.
 */
function calculateConfidence(b, i, f, vulnType, expectedDelay, proofToken, normB, normI, normF, expectedSstiResult) {
    const isJson = i.contentType?.includes("application/json") || false;
    const sizeDiff = Math.abs(i.size - b.size);
    const sizeRatio = sizeDiff / (b.size || 1);

    // Use normalized bodies if provided
    const bodyA = normB || b.body;
    const bodyB = normI || i.body;

    const bodyDiff = diffRatio(bodyA, bodyB);
    const statusChanged = b.status !== i.status && i.ok;
    const tagsDiff = Math.abs(countHtmlTags(i.body) - countHtmlTags(b.body));
    const domChanged = tagsDiff > 3;
    const timingSignal = expectedDelay > 0 && i.elapsed >= expectedDelay * 0.8;

    let confidence = 0;
    let signalType = null;
    let evidenceSnippet = '';

    // [S3 FIX] Directory listing as standalone finding
    const dirResult = detectDirectoryListing(i.body, b.request?.url || '');
    if (dirResult && dirResult.signal) {
        return {
            confidence: dirResult.confidence,
            signalType: dirResult.signalType,
            evidenceSnippet: dirResult.evidenceSnippet,
            metrics: { sizeDiff: sizeDiff, sizeRatio: sizeRatio, statusChanged: statusChanged, timingSignal: false, domChanged: false, bodyDiff: bodyDiff }
        };
    }

    // SQLi signals
    if (vulnType === 'SQLi') {
        for (const p of SQL_ERRORS) {
            const m = i.body.match(p);
            if (m && !p.test(b.body)) {
                confidence += 0.80; // Only explicitly confirmed via error
                signalType = 'sqli_error';
                evidenceSnippet = extractSnippet(i.body, m[0]);
                break;
            }
        }
        if (timingSignal) {
            confidence += 0.80;
            signalType = signalType || 'sqli_timing';
            evidenceSnippet = `Response delayed ${Math.round(i.elapsed)}ms (baseline avg: ${Math.round(b.elapsed)}ms)`;
        }
        // Strict Boolean Diff logic (must only apply if no obvious generic WAF errors triggered)
        if (!signalType && f && f.ok && i.ok && b.ok) {
            const bodyA = normB || b.body;
            const diffBL_True = diffRatio(bodyA, normI || i.body);
            const diffBL_False = diffRatio(bodyA, normF || f.body);

            if (diffBL_True > 0.10 && diffBL_False < 0.05) {
                confidence += 0.70;
                signalType = 'sqli_boolean_confirmed';
                evidenceSnippet = `Boolean SQLi confirmed: diff(True)=${(diffBL_True * 100).toFixed(1)}%, diff(False)=${(diffBL_False * 100).toFixed(1)}%`;
            } else if (diffBL_False > 0.10 && diffBL_True < 0.05) {
                confidence += 0.70;
                signalType = 'sqli_boolean_confirmed';
                evidenceSnippet = `Boolean SQLi confirmed (inverted): diff(True)=${(diffBL_True * 100).toFixed(1)}%, diff(False)=${(diffBL_False * 100).toFixed(1)}%`;
            }
        } else if (!signalType && sizeRatio > 0.03 && !statusChanged) {
            // fallback generic
            confidence += 0.30;
            signalType = 'sqli_boolean';
            evidenceSnippet = `Body size changed by ${sizeDiff} bytes (${(sizeRatio * 100).toFixed(1)}%)`;
        }
    }

    // XSS signals
    if (vulnType === 'XSS' && proofToken) {
        const xssResult = detectXssSignal_PATCH(i.body, proofToken, i.status);
        if (xssResult.signal) {
            confidence += xssResult.confidence;
            
            if (isJson) {
                // [S1 FIX] Smart JSON penalty — don't kill signals from SPA data APIs.
                // A JSON response that reflects XSS payload CAN be a true positive when
                // the frontend (Angular/React/Vue) renders the data as innerHTML.
                const isSpaDataEndpoint = /\/(api|rest|graphql)\//i.test(url) ||
                    /\/(product|search|feedback|comment|review|description|content|name|title)/i.test(url);

                if (isSpaDataEndpoint) {
                    // Reduce confidence (needs browser verification) but don't kill
                    confidence -= 0.20;
                } else {
                    // Pure API with no SPA frontend — higher false-positive risk
                    confidence -= 0.45;
                }
            }
            signalType = xssResult.signalType;
            evidenceSnippet = xssResult.snippet;
        }
    }

    // SSTI signals
    if (vulnType === 'SSTI') {
        const bodyA = normB || b.body;
        if (expectedSstiResult && i.body.includes(expectedSstiResult) && !bodyA.includes(expectedSstiResult)) {
            confidence += 0.85; // Very high confidence — unique token match
            signalType = 'ssti_eval';
            evidenceSnippet = extractSnippet(i.body, expectedSstiResult);
        } else {
            for (const p of SSTI_PATTERNS) {
                if (p.toString().includes('49')) continue;
                const m = i.body.match(p);
                if (m) { confidence += 0.55; signalType = 'ssti_eval'; evidenceSnippet = extractSnippet(i.body, m[0]); break; }
            }
        }
    }

    // LFI / Path Traversal signals
    if (vulnType === 'LFI') {
        for (const p of LFI_PATTERNS) {
            const m = i.body.match(p);
            if (m && !p.test(b.body)) {
                // Definitive file read confirmed — /etc/passwd content in response
                confidence += 0.90;
                signalType = 'lfi_file_read';
                evidenceSnippet = extractSnippet(i.body, m[0]);
                break;
            }
        }
        // If no strong match, check for partial LFI signals (path errors)
        if (!signalType) {
            for (const p of LFI_PARTIAL_PATTERNS) {
                const m = i.body.match(p);
                if (m && !p.test(b.body)) {
                    confidence += 0.40;
                    signalType = 'lfi_partial';
                    evidenceSnippet = extractSnippet(i.body, m[0]);
                    break;
                }
            }
        }
    }

    // Information Disclosure signals
    if (vulnType === 'InfoDisclosure') {
        for (const p of INFO_DISCLOSURE_PATTERNS) {
            const m = i.body.match(p);
            if (m && !p.test(b.body)) {
                confidence += 0.70;
                signalType = 'info_disclosure';
                evidenceSnippet = extractSnippet(i.body, m[0]);
                break;
            }
        }
    }

    // ── Standalone Directory Listing Check ────────────────────────────────────
    // (This is now handled by the standalone detectDirectoryListing function)

    // ── NEW: IDOR signals ────────────────────────────────────────────────────
    if (vulnType === 'IDOR') {
        // Signal: different ID returns different user data (not an error or redirect)
        const IDOR_DATA_PATTERNS = [
            /"email"\s*:/i,
            /"username"\s*:/i,
            /"password"\s*:/i,
            /"address"\s*:/i,
            /"phone"\s*:/i,
            /"card"\s*:/i,
            /"basket"\s*:/i,
        ];
        if (i.status >= 200 && i.status < 300) {
            for (const p of IDOR_DATA_PATTERNS) {
                const m = i.body.match(p);
                if (m) {
                    // Compare with baseline — if different data is returned, it's IDOR
                    if (!p.test(b.body) || diffRatio(normalizeBody(b.body), normalizeBody(i.body)) > 0.15) {
                        confidence += 0.65;
                        signalType = 'idor_data_exposure';
                        evidenceSnippet = extractSnippet(i.body, m[0]);
                        break;
                    }
                }
            }
        }
    }

    // ── NEW: CSRF signals ────────────────────────────────────────────────────
    if (vulnType === 'CSRF') {
        // A state-changing endpoint that accepts a POST without any CSRF token
        // AND returns success (2xx) is vulnerable
        if (i.status >= 200 && i.status < 300) {
            const hasCSRFField = /csrf|_token|authenticity_token|__RequestVerificationToken|xsrf/i.test(b.body);
            const hasCSRFHeader = b.headers && (
                b.headers['x-csrf-token'] || b.headers['x-xsrf-token']
            );
            if (!hasCSRFField && !hasCSRFHeader) {
                confidence += 0.55;
                signalType = 'csrf_missing_token';
                evidenceSnippet = `State-changing endpoint accepts POST without anti-CSRF token (status ${i.status})`;
            }
        }
    }

    // Bonus signals
    if (statusChanged) confidence += 0.15;
    if (sizeRatio > 0.05) confidence += 0.10;
    if (bodyDiff > 0.10) confidence += 0.10;
    if (domChanged) confidence += 0.10;

    for (const p of ERROR_KEYWORDS) {
        if (p.test(i.body) && !p.test(b.body)) {
            confidence += 0.10;
            if (!evidenceSnippet) evidenceSnippet = extractSnippet(i.body, i.body.match(p)?.[0] || '');
            break;
        }
    }

    confidence = Math.min(1.0, parseFloat(confidence.toFixed(2)));
    return { confidence, signalType, evidenceSnippet, metrics: { sizeDiff, sizeRatio, statusChanged, timingSignal, domChanged, bodyDiff } };
}

// ── Shannon Patch: Enhanced XSS signal extraction ────────────────────────────
function detectXssSignal_PATCH(injBody, proofToken, injStatus) {
    if (!injBody) return { signal: false, signalType: null, confidence: 0, snippet: "" };

    const token = proofToken || "";
    const tokenLower = token.toLowerCase();

    // 1. Raw reflection (highest confidence)
    if (token && injBody.includes(token)) {
        const inSink = isInSink(injBody, token);
        return {
            signal: true,
            signalType: inSink ? "xss_sink" : "xss_reflection",
            confidence: inSink ? 0.95 : 0.75,
            snippet: extractSnippet(injBody, token),
        };
    }

    // 2. HTML-encoded reflection (TestFire / Java EE apps)
    if (token) {
        const htmlEncoded = token
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#x27;");

        if (injBody.includes(htmlEncoded)) {
            return {
                signal: true,
                signalType: "xss_encoded_reflection",
                confidence: 0.55,
                snippet: extractSnippet(injBody, htmlEncoded),
            };
        }

        // 3. URL-encoded reflection
        const urlEncoded = encodeURIComponent(token);
        if (urlEncoded !== token && injBody.includes(urlEncoded)) {
            return {
                signal: true,
                signalType: "xss_url_reflection",
                confidence: 0.50,
                snippet: extractSnippet(injBody, urlEncoded),
            };
        }

        // 4. Partial token reflection (sans brackets)
        const tokenCore = token.replace(/<\/?|>/g, "");
        if (tokenCore.length > 4 && injBody.toLowerCase().includes(tokenCore.toLowerCase())) {
            return {
                signal: true,
                signalType: "xss_partial_reflection",
                confidence: 0.40,
                snippet: extractSnippet(injBody, tokenCore),
            };
        }
    }

    // 5. XSS execution context heuristics
    const execPatterns = [
        /onerror\s*=\s*alert/i,
        /onmouseover\s*=\s*alert/i,
        /<script[^>]*>alert/i,
        /javascript:alert/i,
    ];
    if (execPatterns.some(p => p.test(injBody))) {
        return {
            signal: true,
            signalType: "xss_sink",
            confidence: 0.85,
            snippet: injBody.slice(0, 300),
        };
    }

    return { signal: false, signalType: null, confidence: 0, snippet: "" };
}

// ═══════════════════════════════════════════════════════════════════════════════
// [S3 PATCH] Directory listing detection logic
// ═══════════════════════════════════════════════════════════════════════════════

export const DIR_LISTING_PATTERNS = [
    /Index of \//i,
    /Parent Directory/i,
    /Directory listing for/i,
    /\[DIR\]/i,
    /\[TXT\]/i,
    /<title>.*directory.*listing/i,
];

/**
 * detectDirectoryListing — check if response exposes a directory listing.
 * This is a standalone Medium finding — no further exploitation needed.
 */
export function detectDirectoryListing(responseBody, url) {
    if (!responseBody || typeof responseBody !== 'string') return null;
    const matched = DIR_LISTING_PATTERNS.some(p => p.test(responseBody));
    if (!matched) return null;

    // Extract listed files from the response
    const filePattern = /href="([^"?#]+)"/g;
    const files = [];
    let m;
    while ((m = filePattern.exec(responseBody)) !== null) {
        const f = m[1];
        if (!f.startsWith('/') && !f.startsWith('http') && !f.startsWith('..')) {
            files.push(f);
        }
    }

    // Flag sensitive files in the listing
    const SENSITIVE_FILES = [
        /\.env$/i, /\.bak$/i, /\.sql$/i, /\.tar\.gz$/i, /\.zip$/i,
        /package\.json/i, /config\./i, /credentials\./i, /secret/i,
        /private/i, /backup/i, /dump/i, /\.log$/i, /\.key$/i,
    ];
    const sensitiveFound = files.filter(f => SENSITIVE_FILES.some(p => p.test(f)));

    return {
        signal: true,
        signalType: 'directory_listing',
        confidence: sensitiveFound.length > 0 ? 0.85 : 0.65,
        severity: sensitiveFound.length > 0 ? 'High' : 'Medium',
        evidenceSnippet: `Directory listing at ${url}. Files: ${files.slice(0, 10).join(', ')}`,
        sensitiveFiles: sensitiveFound,
        allFiles: files.slice(0, 50),
    };
}
