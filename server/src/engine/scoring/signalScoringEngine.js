/**
 * signalScoringEngine.js
 * 
 * Central nervous system for RedVapt evaluating response drift, WAF signs,
 * and vulnerability confidence scores to prioritize work.
 */

export class SignalScoringEngine {
    constructor() { }

    /**
     * @param {Array} baselines - Array of 3 baseline responses for stability check
     * @param {object} injected - Injected response HTTP info
     * @param {string} payload - Payload used
     * @returns {object} Contextual score object
     */
    evaluateSignal(baselines, injected, payload) {
        let confidence = 0.0;
        let diffScore = 0.0;
        let wafSuspected = false;
        let reasons = [];
        let signalType = 'UNKNOWN';
        let isUnstable = false;

        if (!baselines || baselines.length === 0 || !injected) return { confidence: 0, signalType, reasons, diffScore, wafSuspected, isUnstable };

        // 1. True Baseline Stability Check (R1)
        const sizes = baselines.map(b => b.body ? b.body.length : (b.size || 0));
        const avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length;
        const maxDiff = Math.max(...sizes) - Math.min(...sizes);

        let baselineSize = avgSize;
        if (maxDiff > (avgSize * 0.05)) { // 5% deviation
            isUnstable = true;
            reasons.push("High-noise endpoint: baseline size varies too much");
        }

        const injSize = injected.body ? injected.body.length : (injected.size || 0);

        if (baselineSize > 0) {
            diffScore = Math.abs(injSize - baselineSize) / baselineSize;
            if (isUnstable) diffScore = diffScore * 0.2; // reduce diff weight significantly
        }

        // 2. Strict WAF Heuristics (R2)
        const wafIndicators = [
            /cloudflare/i, /mod_security/i, /modsecurity/i,
            /imperva/i, /akamai/i, /sucuri/i, /incapsula/i, /barracuda/i
        ];

        const responseText = (injected.body || "");

        let hasWafHeader = false;
        if (injected.headers) {
            const hStr = JSON.stringify(injected.headers).toLowerCase();
            if (hStr.includes('cloudflare') || hStr.includes('x-sucuri') || hStr.includes('x-akamai')) {
                hasWafHeader = true;
            }
        }

        // HTTP 403, 406, 501 are heavy WAF signs for simple payloads
        if ([403, 406, 501].includes(injected.status) || wafIndicators.some(w => w.test(responseText)) || hasWafHeader) {
            wafSuspected = true;
            reasons.push("WAF signature, header, or block status detected");
            confidence = 0.05;
            signalType = 'WAF_BLOCK';
            return { confidence, signalType, reasons, diffScore, wafSuspected, isUnstable };
        }

        // 3. SQLi Signatures
        const sqlErrors = [
            /syntax error.*mysql/i, /PostgreSQL.*ERROR/i,
            /quoted string not properly terminated/i, /SQL syntax/i,
            /unclosed quotation mark/i
        ];

        if (sqlErrors.some(e => e.test(injected.body))) {
            confidence += 0.4;
            reasons.push("SQL syntax error detected in body");
            signalType = 'SQLi_ERROR';
        } else if (injected.status === 500 && !baselines.some(b => b.status === 500)) {
            confidence += 0.2;
            reasons.push("500 Server Error anomaly (potential blind SQLi/SSTI)");
            signalType = 'SERVER_ERROR_ANOMALY';
        }

        // 4. XSS Reflection
        if (payload && injected.body && injected.body.includes(payload)) {
            // It reflected exactly
            confidence += 0.35;
            reasons.push("Payload token reflected in response");
            signalType = 'XSS_REFLECTION';
        }

        // 5. Timing Drift
        const avgTime = baselines.reduce((a, b) => a + (b.time || 200), 0) / baselines.length;
        const injTime = injected.time || 200;
        if (injTime > avgTime + 4000) {
            confidence += 0.3;
            reasons.push("Significant timing delay detected");
            signalType = 'TIME_DELAY_ANOMALY';
        }

        // 6. Security Header Weakness
        if (injected.headers) {
            if (!injected.headers['content-security-policy']) {
                reasons.push("Missing CSP header");
            }
        }

        const finalConfidence = Math.min(confidence + Math.min(diffScore, 0.2), 1.0);

        return {
            confidence: finalConfidence,
            signalType,
            reasons,
            diffScore,
            wafSuspected,
            silent: finalConfidence < 0.3
        };
    }
}

export const signalScoringEngine = new SignalScoringEngine();
