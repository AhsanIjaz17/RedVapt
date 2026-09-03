/**
 * vuln/verificationPipeline.js — Strict 4-Step Confirmation Pipeline
 *
 * FIX (Breakpoint #1 + #3):
 *   - proofToken is now PASSED IN from unifiedEngine (not regenerated here).
 *   - diffScore threshold lowered to 0.15 (was 0.7 — impossible to reach).
 *   - XSS sink confirmation uses the passed-in token.
 *   - OR-gate logic: any ONE piece of evidence is enough to confirm.
 *
 * Pipeline:
 *   Signal → Re-verify → Confirm → Attach Evidence
 */

import crypto from 'crypto';
import axios from 'axios';
import * as cheerio from 'cheerio';
import path from 'path';
import fs from 'fs';
import { captureXssProof as captureXssProofPW } from './playwrightProver.js';

function calculateCVSS3(severity, vulnType) {
    let score = 0.0;
    let vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

    switch ((severity || '').toLowerCase()) {
        case 'critical': score = 9.8; vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; break;
        case 'high': score = 8.1; vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'; break;
        case 'medium': score = 6.1; vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'; break;
        case 'low': score = 3.3; vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'; break;
        default: score = 0.0;
    }

    if (vulnType.toLowerCase().includes('sqli') && score < 9) { score = 9.8; vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'; }
    if (vulnType.toLowerCase().includes('xss') && score !== 6.1) { score = 6.1; vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'; }
    if (vulnType.toLowerCase().includes('lfi') && score < 8) { score = 8.6; vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'; }

    return { cvss3Score: score, cvss3Vector: vector };
}

const MAX_SNIPPET = 800;  // increased from 500
const HTTP_TIMEOUT = 15_000;

// Lazy https agent (node has a TLS default, but we want insecure for lab targets)
let _httpsAgent = null;
async function getInsecureAgent() {
    if (!_httpsAgent) {
        const https = await import('https');
        _httpsAgent = new https.Agent({ rejectUnauthorized: false });
    }
    return _httpsAgent;
}

export function generateProofToken() {
    return 'rvtok_' + crypto.randomBytes(4).toString('hex');
}

// ── Step 1: Signal check ─────────────────────────────────────────────────────

function checkSignal(response, matchers, proofToken) {
    const { body = '', status, timingMs } = response;

    for (const matcher of (matchers || [])) {
        if (matcher.type === 'pattern') {
            for (const pat of (matcher.patterns || [])) {
                const re = pat instanceof RegExp ? pat : new RegExp(pat, 'i');
                const m = body.match(re);
                if (m) return { signalType: 'pattern', matched: m[0]?.slice(0, 150) };
            }
        }
        if (matcher.type === 'timing' && timingMs >= matcher.minDelayMs) {
            return { signalType: 'timing', timingMs };
        }
        // token_reflection: check if raw proofToken appears anywhere in body
        if (matcher.type === 'token_reflection' && proofToken) {
            if (body.includes(proofToken)) {
                return { signalType: 'token_reflection', token: proofToken };
            }
        }
    }
    return null;
}

// ── Step 2: Re-verify with baseline comparison ────────────────────────────────

async function reVerify(url, method, paramName, injectIn, baselineValue, injectedPayload, timeoutMs = HTTP_TIMEOUT, hiddenFields = {}) {
    const agent = await getInsecureAgent();

    const sendReq = async (paramValue) => {
        const start = Date.now();
        let reqUrl = url;
        let body = undefined;
        const headers = {};

        if (injectIn === 'query' || !injectIn) {
            const sep = url.includes('?') ? '&' : '?';
            reqUrl = `${url}${sep}${encodeURIComponent(paramName)}=${encodeURIComponent(paramValue)}`;
        } else if (injectIn === 'body') {
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            const extra = Object.entries(hiddenFields).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
            body = `${encodeURIComponent(paramName)}=${encodeURIComponent(paramValue)}${extra ? '&' + extra : ''}`;
        } else if (injectIn === 'json_body') {
            headers['Content-Type'] = 'application/json';
            body = JSON.stringify({ ...hiddenFields, [paramName]: paramValue });
        } else if (injectIn === 'header') {
            headers[paramName] = paramValue;
        }

        try {
            const resp = await axios({
                method: (method || 'GET').toLowerCase(),
                url: reqUrl,
                data: body,
                headers,
                timeout: timeoutMs,
                validateStatus: () => true,
                maxRedirects: 5,
                httpsAgent: agent,
            });
            const responseBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
            return {
                body: responseBody,
                status: resp.status,
                elapsed: Date.now() - start,
                headers: resp.headers,
            };
        } catch (err) {
            return { body: '', status: 0, elapsed: Date.now() - start, headers: {}, error: err.message };
        }
    };

    const [baseline, injected] = await Promise.all([
        sendReq(baselineValue || 'test'),
        sendReq(injectedPayload),
    ]);

    const lengthDiff = Math.abs(injected.body.length - baseline.body.length);
    const baseLen = baseline.body.length || 1;
    // FIX: diffScore threshold was 0.7 (70% change) — way too strict.
    // Most SQL errors only add ~200 bytes to a 4KB page = 5%. New threshold: 0.05.
    const diffScore = lengthDiff / baseLen;
    const baselineTags = (baseline.body.match(/<[a-z]+/gi) || []).length;
    const injectedTags = (injected.body.match(/<[a-z]+/gi) || []).length;
    const domChanged = baselineTags !== injectedTags && Math.abs(baselineTags - injectedTags) > 2;

    return { baseline, injected, diffScore, lengthDiff, domChanged };
}

// ── Playwright XSS execution check ──────────────────────────────────────────
// Now delegates to the enhanced playwrightProver module with business-impact payloads

async function captureXssProof(url, method, data, headers, paramName) {
    try {
        const sep = url.includes('?') ? '&' : '?';
        const payload = '"><script>alert(1)</script>';
        const injectedUrl = `${url}${sep}${encodeURIComponent(paramName || 'q')}=${encodeURIComponent(payload)}`;

        const result = await captureXssProofPW({
            url,
            injectedUrl,
            vulnId: `RVPT-VERIFY-${Math.floor(Math.random()*1000)}`
        });
        
        return {
            executed: result.confirmed,
            screenshot: result.screenshots?.exploit || result.screenshots?.baseline,
            dialogText: result.alertText || '',
        };
    } catch (err) {
        console.error('[XSS] Playwright proof failed:', err.message);
        return { executed: false, error: err.message };
    }
}

// ── Step 3: XSS sink confirmation ─────────────────────────────────────────────

function confirmXssSink(body, token) {
    if (!token || !body) return false;

    // 1. Strict Regex matches
    const STRICT_PATTERNS = [
        // Script context survival (looks for script tags with token unescaped)
        new RegExp(`<script[^>]*>[^<]*${token}[^<]*<\/script>`, 'i'),
        // Attribute injection breakout (looks for token breaking quotes/html)
        new RegExp(`="[^"]*${token}[^"]*"`, 'i') === false ? false : undefined, // Handled by Cheerio below
    ];
    if (STRICT_PATTERNS.some(p => p?.test(body))) return true;

    // 2. DOM Parsing check using Cheerio (Unescaped in HTML context)
    try {
        const $ = cheerio.load(body);
        let confirmed = false;

        // Check if token landed cleanly in an unescaped text context
        $('*').each((_, el) => {
            if (el.type === 'text' && el.data && el.data.includes(token)) {
                // Since cheerio parsed it easily as text, it means it survived without breaking logic or
                // if it created a new tag, we will see it in DOM keys.
                // Wait, if it created a new tag, it won't be text, it will be an element.
            }
            // Check attributes
            if (el.attribs) {
                for (const [attrName, attrValue] of Object.entries(el.attribs)) {
                    if (attrName.startsWith('on') && attrValue.includes(token)) confirmed = true;
                    if (attrValue.includes(token) && ['href', 'src', 'action'].includes(attrName) && attrValue.toLowerCase().startsWith('javascript:')) confirmed = true;
                }
            }
        });

        // Check if our injection created the actual <script> tag (meaning token is either tag name or script content)
        $('script').each((_, el) => {
            if ($(el).html()?.includes(token)) confirmed = true;
            if (el.attribs?.src?.includes(token)) confirmed = true;
        });

        if (confirmed) return true;
    } catch (e) {
        // Cheerio load error
    }

    // Explicitly reject lazy 'includes' fallback
    return false;
}

// ── Step 3b: LFI file-read confirmation ────────────────────────────────────────

/**
 * Strict LFI confirmation: requires ≥2 valid /etc/passwd lines in the response.
 * Must NOT appear in baseline to guard against false positives from normal page content.
 */
function confirmLfiRead(injectedBody, baselineBody) {
    if (!injectedBody) return false;
    // Match lines in passwd format: username:x:uid:gid:...
    const PASSWD_LINE_RE = /^[a-z_][a-z0-9_-]*:\w*:\d+:\d+:/gm;
    const injectedMatches = injectedBody.match(PASSWD_LINE_RE) || [];
    const baselineMatches = (baselineBody || '').match(PASSWD_LINE_RE) || [];
    // Require at least 2 passwd lines in injected that don't exist in baseline
    if (injectedMatches.length >= 2 && baselineMatches.length === 0) return true;
    // Windows file indicators
    if (/\[boot loader\]/i.test(injectedBody) && !/\[boot loader\]/i.test(baselineBody || '')) return true;
    if (/\[fonts\]/i.test(injectedBody) && !/\[fonts\]/i.test(baselineBody || '')) return true;
    return false;
}

// ── Step 4: Build evidence ─────────────────────────────────────────────────────

function buildEvidence({ request, injectedResp, baselineResp, signal, proofToken, diffScore }) {
    const responseBody = typeof injectedResp?.body === 'string' ? injectedResp.body : '';
    // Try to find the interesting snippet near the signal
    let snippet = responseBody.slice(0, MAX_SNIPPET);
    if (proofToken && responseBody.includes(proofToken)) {
        const idx = responseBody.indexOf(proofToken);
        snippet = responseBody.slice(Math.max(0, idx - 100), idx + MAX_SNIPPET);
    }

    const evidence = {
        request: typeof request === 'string' ? request.slice(0, 800) : JSON.stringify(request).slice(0, 800),
        response_snippet: snippet,
        status_code: injectedResp?.status,
        diff_score: diffScore,
    };

    if (signal?.signalType === 'timing') {
        evidence.timing_ms = injectedResp?.elapsed || signal.timingMs;
        evidence.baseline_timing_ms = baselineResp?.elapsed || null;
    }
    if (signal?.signalType === 'pattern' || signal?.signalType === 'sqli_error') {
        evidence.matched_pattern = signal.matched || signal.evidenceSnippet;
    }
    if (proofToken) {
        evidence.proof_token = proofToken;
        // token_in_response is deprecated as useless, replaced by visual_proof
    }

    return evidence;
}

// ── Finding ID counter ───────────────────────────────────────────────────────

let _findingCounter = 0;
function nextFindingId() {
    return `RV-${String(++_findingCounter).padStart(4, '0')}`;
}

// ── Main pipeline entrypoint ──────────────────────────────────────────────────

/**
 * Run the 4-step verification on a candidate signal.
 *
 * FIX (Breakpoint #1): proofToken is now accepted as a parameter
 * instead of regenerated here. The token inside the injected payload
 * and the token checked in the response are now the SAME token.
 *
 * @param {object} candidate
 * @param {string}  candidate.url
 * @param {string}  candidate.method
 * @param {string}  candidate.paramName
 * @param {string}  candidate.injectIn
 * @param {string}  candidate.payload
 * @param {string}  candidate.baselineValue
 * @param {object}  candidate.template
 * @param {object}  candidate.rawResponse   - initial probe response
 * @param {string}  candidate.proofToken    - THE SAME token used in the payload
 * @param {Array}   candidate.runtimeMatchers - dynamically built matchers (XSS)
 * @param {number}  [candidate.expectedDelay]
 *
 * @returns {Promise<object|null>} Confirmed finding or null
 */
export async function runVerificationPipeline(candidate) {
    const {
        url, method = 'GET', paramName, injectIn = 'query',
        payload, baselineValue, template, rawResponse,
        proofToken,          // FIX: receive the token from caller
        runtimeMatchers,     // FIX: receive dynamic XSS matchers from caller
        expectedDelay = 0,
        hiddenFields = {},
    } = candidate;

    if (!rawResponse) return null;

    // Use runtime matchers if provided (XSS), else use template matchers
    const matchers = runtimeMatchers || template.matchers || [];

    // ── Step 1: Signal check on the FIRST raw response ───────────────────────
    const signal = checkSignal(
        { body: rawResponse.body, status: rawResponse.status, timingMs: rawResponse.timingMs },
        matchers,
        proofToken,
    );

    // Allow through if: signal OR raw token reflection (even without a matcher match)
    const rawTokenInBody = proofToken && rawResponse.body?.includes(proofToken);
    if (!signal && !rawTokenInBody && (rawResponse.diffScore || 0) < 0.05) return null;

    // ── Step 2: Re-verify with baseline ──────────────────────────────────────
    let verifyResult;
    try {
        const verifyTimeout = expectedDelay > 0 ? Math.max(20_000, expectedDelay * 2) : HTTP_TIMEOUT;
        verifyResult = await reVerify(url, method, paramName, injectIn, baselineValue, payload, verifyTimeout, hiddenFields);
    } catch {
        return null;
    }

    const { baseline, injected, diffScore, domChanged } = verifyResult;

    // ── Step 2.5: Stability test to eliminate false positives ─────────────────
    let matches = 0;
    for (let i = 0; i < 3; i++) {
        try {
            const verifyTimeout = expectedDelay > 0 ? Math.max(20_000, expectedDelay * 2) : HTTP_TIMEOUT;
            const r = await reVerify(url, method, paramName, injectIn, baselineValue, payload, verifyTimeout, hiddenFields);

            const sig = checkSignal({ body: r.injected.body, status: r.injected.status, timingMs: r.injected.elapsed }, matchers, proofToken);
            if (sig || (proofToken && r.injected.body?.includes(proofToken)) || r.diffScore >= 0.05 || r.domChanged) {
                matches++;
            }
        } catch { }
    }

    if (matches < 2) {
        return null; // stability fails -> downgrade confidence hard, do NOT report as confirmed
    }

    // ── Step 3: Confirm evidence — any ONE path is enough ────────────────────
    const confirmedSignal = checkSignal(
        { body: injected.body, status: injected.status, timingMs: injected.elapsed },
        matchers,
        proofToken,
    );

    // FIX (Breakpoint #3): thresholds dramatically lowered
    const hasTokenProof = !!proofToken && confirmXssSink(injected.body, proofToken);

    // Strict SQLi confirmation rules:
    // Only diff-proof if we have a real boolean switch WITHOUT generic errors or waf blocks. Diff > 0.05 alone is weak.
    // SQL error patterns OR timing delay are strong.
    const isSqli = template.type === 'SQL Injection' || template.type === 'SQLi';
    let hasDiffProof = diffScore >= 0.05 || domChanged;

    const hasTimingProof = expectedDelay > 0 && injected.elapsed >= expectedDelay * 0.8;
    const hasPatternProof = confirmedSignal?.signalType === 'pattern' || confirmedSignal?.signalType === 'sqli_error';
    const isLfi = template.type === 'LFI';
    const isInfoDisc = template.type === 'Information Disclosure';
    const hasLfiProof = isLfi && confirmLfiRead(injected.body, baseline.body);
    const hasInfoDiscProof = isInfoDisc && confirmedSignal?.signalType === 'pattern';

    if (isSqli && !hasTimingProof && !hasPatternProof) {
        // Enforce strict boolean SQLi:
        // Must have stable difference, no WAF blocks, and status shouldn't change to 403 or 500 abruptly.
        if (injected.status === 403 || injected.status === 406 || injected.body?.includes("Mod_Security") || injected.body?.includes("Forbidden")) {
            hasDiffProof = false; // It's just a WAF block diff!
        }
    }

    if (!hasTokenProof && !hasDiffProof && !hasTimingProof && !hasPatternProof && !hasLfiProof) {
        return null;
    }

    // Optional strong proof: Playwright XSS check
    let visualProof = null;
    const config = (await import('../../config/env.js')).default;

    if (config.ENABLE_BROWSER_PROOF && (hasTokenProof || template.type === 'XSS')) {
        visualProof = await captureXssProof(url, method, injectIn === 'body' || injectIn === 'query' ? payload : '', {});
        if (visualProof.executed && visualProof.screenshot) {
            // Unquestionable confirmation
        } else if (!hasTokenProof) {
            // Neither DOM regex matched nor did Playwright fire an alert
            return null;
        } else if (hasTokenProof && visualProof.error && visualProof.error.includes("Executable doesn't exist")) {
            // Playwright not installed properly, but we have strong DOM context proof for XSS (Level 2).
            console.warn(`[Verification] Falling back to static confirmation for XSS, Playwright missing.`);
        }
    }

    // ── Step 4: Build structured finding ─────────────────────────────────────
    const requestStr = `${method} ${url}\nPayload in ${injectIn}[${paramName}]: ${payload}`;

    const evidence = buildEvidence({
        request: requestStr,
        injectedResp: { ...injected, elapsed: injected.elapsed },
        baselineResp: baseline,
        signal: confirmedSignal || signal,
        proofToken: hasTokenProof || visualProof?.executed ? proofToken : undefined,
        diffScore,
    });

    if (visualProof?.screenshot) {
        evidence.visual_proof = visualProof.screenshot;
    }

    // Strict XSS offline confirmation Check
    const isOfflineXssSink = (body, tk) => {
        if (!body || !tk) return false;
        if (body.match(new RegExp(`<script[^>]*>[^<]*${tk}[^<]*<\/script>`, 'i'))) return true;
        if (body.match(new RegExp(`on[a-z]+\\s*=\\s*["'][^"']*${tk}[^"']*["']`, 'i'))) return true;
        return false;
    };

    // Fix: Redesign confidence and validation per architecture audit (Phase 5: Type-Specific Evidence)
    let finalConfidence = 'Low';
    let numericConfidence = 0.20;

    if (template.type === 'LFI') {
        const lfiHardProofPatterns = [
            /root:x:0:0:/,
            /root:.*:0:0:.*:\/bin\//,
            /daemon:x:\d+:\d+:/,
            /\[boot loader\]/i,
            /\[fonts\].*\[extensions\]/is
        ];
        if (lfiHardProofPatterns.some(p => p.test(injected.body))) {
            finalConfidence = 'Confirmed';
            numericConfidence = 0.95;
        } else if (hasLfiProof) { // soft signal
            finalConfidence = 'Potential';
            numericConfidence = 0.45;
        } else {
            return null; // Never report on size diff alone
        }
    } else if (template.type === 'XSS' || template.type === 'Cross-Site Scripting') {
        // Reject if application/json
        if (injected.contentType?.includes('application/json')) return null;

        // Check if encoded
        if (injected.body?.includes('&lt;') && injected.body?.includes('&gt;')) {
            const encoded = proofToken.replace('<', '&lt;').replace('>', '&gt;');
            if (injected.body.includes(encoded)) return null;
        }

        if (visualProof?.executed) {
            finalConfidence = 'Confirmed';
            numericConfidence = 0.99;
        } else if (hasTokenProof && isOfflineXssSink(injected.body, proofToken)) {
            finalConfidence = 'High';
            numericConfidence = 0.80;
        } else if (hasTokenProof) {
            finalConfidence = 'Medium';
            numericConfidence = 0.65;
        } else {
            return null;
        }
    } else if (isSqli) {
        if (hasPatternProof) {
            finalConfidence = 'High';
            numericConfidence = 0.85;
        } else if (hasTimingProof) {
            finalConfidence = 'Confirmed';
            numericConfidence = 0.90;
        } else if (hasDiffProof) { // Diff proof ONLY if 3-way check passed (validated by signalEngine)
            finalConfidence = 'Medium';
            numericConfidence = 0.70;
        } else {
            return null;
        }
    } else {
        // Generic
        if (hasPatternProof) { finalConfidence = 'Confirmed'; numericConfidence = 0.95; }
        else if (hasTimingProof) { finalConfidence = 'High'; numericConfidence = 0.85; }
        else if (hasDiffProof) { finalConfidence = 'Medium'; numericConfidence = 0.50; }
        else return null;
    }

    return {
        id: `RVPT-2026-${String(Math.floor(Math.random() * 9000) + 1000)}`,
        title: `${template.type} via ${injectIn} in ${paramName}`,
        type: template.type,
        subtype: template.subtype || 'Unknown',
        cwe: template.cwe || 'CWE-000',
        owasp: template.owasp || 'Unknown',
        cvss3Score: calculateCVSS3(template.severity, template.type).cvss3Score,
        cvss3Vector: calculateCVSS3(template.severity, template.type).cvss3Vector,

        endpoint: url,
        paramName: paramName,
        method: method.toUpperCase(),
        discoveredAt: new Date().toISOString(),

        evidence: {
            ...evidence,
            proofToken: proofToken || undefined,
            payload: payload,
            httpRequest: {
                method: method.toUpperCase(),
                url: `${url}`,
            },
            httpResponseSnippet: {
                status: injected.status,
                relevantLines: injected.body?.substring(0, 300) + '...' || '',
                matched: proofToken || 'Pattern Match',
            },
            confirmedBy: visualProof?.executed ? 'playwright_dialog' : 'signalEngine',
            playwrightProof: visualProof?.executed ? {
                alertFired: true,
                dialogText: visualProof.dialogText || null,
                cookieValue: visualProof.cookieValue || null,
                domainValue: visualProof.domainValue || null,
                screenshotPath: visualProof.screenshot || null,
            } : undefined,
            baselineStatus: baseline.status,
            injectedStatus: injected.status,
            sizeDiff: `${(injected.body?.length || 0) - (baseline.body?.length || 0)} bytes`,
        },

        reproductionSteps: [
            `1. Issue ${method.toUpperCase()} request to ${url}`,
            `2. Inject payload into ${injectIn}[${paramName}]: ${payload}`,
            `3. Observe response for explicit proof context.`
        ],
        curlCommand: `curl -s -X ${method.toUpperCase()} "${injectIn === 'query' || !injectIn ? url + (url.includes('?') ? '&' : '?') + encodeURIComponent(paramName) + '=' + encodeURIComponent(payload) : url}"${injectIn === 'body' ? ` -d "${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}"` : ''}`,

        confidence: numericConfidence,
        confidenceLabel: finalConfidence,
        falsePositiveRisk: finalConfidence === 'Confirmed' ? 'None - Verified' : 'Elevated',

        severity: template.severity,
        businessImpact: template.impact || 'System compromise',

        remediation: {
            short: template.remediation || 'Apply input sanitization',
            detailed: template.remediation || 'Apply input sanitization and verification.',
            references: ['https://owasp.org'],
        }
    };
}
