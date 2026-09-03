/**
 * unifiedIntelligence.js — Unified Attack Surface Intelligence Engine
 * 
 * Combines general endpoint scoring (from endpointIntelligence.js) with 
 * JS reconnaissance data (secrets, LinkFinder endpoints) to guide the scanner.
 */

const SCORING_RULES = {
    DANGEROUS_PARAM: { weight: 30, pattern: /[?&](id|uid|user|q|search|query|token|redirect|url|path|file|dest|href)=/i, tag: 'injection-candidate' },
    AUTH_PATH: { weight: 20, pattern: /\/\b(login|auth|signin|signup|token|reset)\b/i, tag: 'auth-surface' },
    ADMIN_PATH: { weight: 25, pattern: /\/\b(admin|manage|internal|config|backup)\b/i, tag: 'admin-panel' },
    SSR_EXTENSION: { weight: 15, pattern: /\.(php|asp|jsp|aspx|cfm|py|rb|pl)([?#]|$)/i, tag: 'server-side-code' },
    PATH_TRAVERSAL: { weight: 10, pattern: /(\.\.\/|file=|path=|dir=|root=)/i, tag: 'lfi-candidate' },
    API_STRUCTURE: { weight: 30, pattern: /\/(api|rest)\/|\/(v[0-9]+)\/|\.json$/i, tag: 'api-layer' },
    JS_SENSITIVE: { weight: 15, pattern: /(config|setting|init|setup|bootstrap|main|app)\.js/i, tag: 'js-logic' },
    JUNK_PATH: { weight: -25, pattern: /(_vti_bin|_vti_cnf|_vti_pvt|cgi-bin|\.dll$|\.ico$|\.css$|\.woff|\.ttf|wp-includes)/i, tag: 'junk' },
};

/**
 * Scores an endpoint based on its URL/path and metadata.
 */
export function scoreEndpoint(endpoint, jsSecrets = [], jsEndpoints = []) {
    const url = typeof endpoint === 'string' ? endpoint : (endpoint.url || '');
    let score = 50; // Base score
    const tags = new Set();
    const vulnTypes = new Set(['sqli', 'xss']); // Default assume most are valid for these

    // 1. Rule-based scoring
    for (const [key, rule] of Object.entries(SCORING_RULES)) {
        if (rule.pattern.test(url)) {
            score += rule.weight;
            tags.add(rule.tag);
        }
    }

    // 2. Vulnerability type refinement
    if (/[?&](id|uid|order|sort|limit)=/i.test(url)) vulnTypes.add('sqli');
    if (/[?&](file|path|template|page|load|src)=/i.test(url)) {
        vulnTypes.add('ssti');
        tags.add('ssrf-candidate');
    }
    if (/[?&](q|s|search|query|msg|name|comment)=/i.test(url)) vulnTypes.add('xss');

    // 3. JS Intelligence Integration
    // If this endpoint was found by LinkFinder or is near a secret, boost it
    const isLinkFinder = jsEndpoints.some(jep => jep.endpoint === url || url.endsWith(jep.endpoint));
    if (isLinkFinder) {
        score += 15;
        tags.add('js-extracted');
    }

    const hasSecretProximity = jsSecrets.some(sec => url.includes(sec.source_url) || (sec.source_url && sec.source_url.includes(url)));
    if (hasSecretProximity) {
        score += 25;
        tags.add('secret-proximity');
    }

    return {
        url,
        score: Math.min(100, Math.max(0, score)),
        tags: [...tags],
        vulnTypes: [...vulnTypes],
        reason: Array.from(tags).join(', ') || 'General endpoint'
    };
}

/**
 * Scores a list of endpoints.
 * @param {Array} endpoints - Array of strings or objects with 'url'
 * @param {Array} jsSecrets - Array of secret objects from recon
 * @param {Array} jsEndpoints - Array of LinkFinder endpoint objects
 */
export function scoreEndpoints(endpoints, jsSecrets = [], jsEndpoints = []) {
    return endpoints
        .map(ep => scoreEndpoint(ep, jsSecrets, jsEndpoints))
        .sort((a, b) => b.score - a.score);
}

/**
 * Formats a concise summary of the "hottest" intelligence for the ReAct agent.
 */
export function buildIntelligenceSummary(reconData) {
    const scored = scoreEndpoints(
        reconData.endpoints || [],
        reconData.jsSecrets || [],
        reconData.jsEndpoints || []
    );

    const topTargets = scored.slice(0, 5);
    const topSecrets = (reconData.jsSecrets || []).slice(0, 3);

    let summary = "### Critical Attack Surface Intelligence\n";

    if (topTargets.length > 0) {
        summary += "**Top Priority Targets:**\n";
        topTargets.forEach(t => {
            summary += `- ${t.url} (Score: ${t.score}, Tags: ${t.reason})\n`;
        });
    }

    if (topSecrets.length > 0) {
        summary += "\n**Exposed Secrets (High Value):**\n";
        topSecrets.forEach(s => {
            const type = s.secret_type || s.type || 'Secret';
            summary += `- ${type} found in ${s.js_url || s.source_url} (Value: ${s.value?.slice(0, 10)}...)\n`;
        });
    }

    const linkfinderCount = (reconData.jsEndpoints || []).length;
    if (linkfinderCount > 0) {
        summary += `\n**JS-Extracted Endpoints:** Found ${linkfinderCount} endpoints via LinkFinder.\n`;
    }

    return summary;
}

/**
 * buildReconSnapshot — The Recon Normalizer
 * 
 * Produces a single structured JSON snapshot that is the ONLY data the LLM sees.
 * This prevents hallucination by giving the AI a clean, ranked, constrained view.
 * 
 * @param {object} reconData - Raw recon data from reconAgent
 * @returns {object} LLM-friendly snapshot
 */
export function buildReconSnapshot(reconData) {
    const target = reconData.target || 'unknown';
    const allEndpoints = (reconData.endpoints || []).map(e => typeof e === 'string' ? e : e.url || '').filter(Boolean);
    const allForms = reconData.forms || [];
    const allParams = reconData.parameters || [];
    const jsSecrets = reconData.jsSecrets || [];
    const jsEndpoints = reconData.jsEndpoints || [];
    const technologies = reconData.technologies || [];
    const validatedEndpoints = reconData.validatedEndpoints || [];

    // Score and rank all endpoints
    const scored = scoreEndpoints(allEndpoints, jsSecrets, jsEndpoints);

    // Extract auth indicators
    const loginPages = allEndpoints.filter(ep => /login|signin|auth|doLogin/i.test(ep));
    const cookiesSeen = [...new Set(
        validatedEndpoints
            .flatMap(ep => ep.cookies || [])
            .map(c => typeof c === 'string' ? c.split('=')[0] : '')
            .filter(Boolean)
    )];

    // Extract param frequency (for LLM to understand which params are common)
    const paramFreq = new Map();
    for (const ep of allEndpoints) {
        try {
            const u = new URL(ep);
            for (const key of u.searchParams.keys()) {
                paramFreq.set(key, (paramFreq.get(key) || 0) + 1);
            }
        } catch { }
    }
    for (const p of allParams) {
        const name = typeof p === 'string' ? p : p.param_name || p.name || '';
        if (name) paramFreq.set(name, (paramFreq.get(name) || 0) + 1);
    }
    const topParams = [...paramFreq.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([name, count]) => ({ name, count }));

    // Build ranked form list
    const topForms = allForms.slice(0, 15).map(f => ({
        page: f.page_url || f.url || '',
        action: f.action || f.action_url || '',
        method: (f.method || 'POST').toUpperCase(),
        inputs: (f.inputs || []).map(i => typeof i === 'string' ? i : i.name || '').filter(Boolean),
        hiddenFields: f.hiddenFields || f.hidden_fields || {},
    }));

    // Build the snapshot
    return {
        target: {
            domain: target,
            baseUrl: reconData.scanContext?.baseUrl || reconData.baseUrl || `http://${target}`,
        },
        techStack: technologies.map(t => typeof t === 'string' ? t : t.name || '').filter(Boolean),
        authIndicators: {
            loginPages,
            cookiesSeen,
        },
        stats: {
            totalEndpoints: allEndpoints.length,
            totalForms: allForms.length,
            totalParams: topParams.length,
            totalJsFiles: (reconData.jsFiles || []).length,
            totalJsEndpoints: jsEndpoints.length,
        },
        // Top 20 ranked endpoints — this is what the LLM reasons over
        topEndpoints: scored.slice(0, 20).map(s => ({
            url: s.url,
            score: s.score,
            tags: s.tags,
            vulnTypes: s.vulnTypes,
        })),
        topForms,
        topParams,
        jsEndpoints: jsEndpoints.slice(0, 20).map(e => typeof e === 'string' ? e : e.endpoint || e.url || '').filter(Boolean),
        interestingHeaders: Object.entries(reconData.observedHeaders || {}).slice(0, 10).map(([k, v]) => ({ header: k, value: v })),
    };
}
