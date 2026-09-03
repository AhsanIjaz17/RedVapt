/**
 * graph/scoringEngine.js — Endpoint Priority Scorer
 *
 * Scores endpoints from the graph against exploitation signals.
 * Higher score = higher priority for the unified vuln engine.
 *
 * Signals and weights are documented inline for easy tuning.
 */

/** @param {string} url */
function scoreEndpoint(urlStr, nodeData = {}) {
    let score = 0;
    const url = (urlStr || '').toLowerCase();
    const contentType = (nodeData.content_type || '').toLowerCase();

    // ── Parameter presence ────────────────────────────────────────────────────
    if (url.includes('?')) score += 30;
    // Count distinct params — more params = higher attack surface
    try {
        const params = [...new URL(urlStr).searchParams.keys()];
        score += Math.min(params.length * 8, 40);
    } catch { /* ignore */ }

    // ── Semantic keywords ────────────────────────────────────────────────────
    const authKeywords = /login|signin|auth|oauth|token|session|password|credential|sso|saml/;
    if (authKeywords.test(url)) score += 25;

    const uploadKeywords = /upload|import|file|attachment|document|media|image|avatar/;
    if (uploadKeywords.test(url)) score += 20;

    const adminKeywords = /admin|management|dashboard|panel|control|backoffice|backstage/;
    if (adminKeywords.test(url)) score += 20;

    const apiKeywords = /\/api\/|\/v\d+\/|\/graphql|\/rest\/|\/rpc\/|\.json(\?|$)|\.xml(\?|$)/;
    if (apiKeywords.test(url)) score += 20;

    const sensitiveKeywords = /search|query|redirect|url|next|return|target|dest|path|src|include|load/;
    if (sensitiveKeywords.test(url)) score += 15;

    // ── Content type signals ─────────────────────────────────────────────────
    if (contentType.includes('application/json')) score += 15;
    if (contentType.includes('text/html')) score += 5;
    if (contentType.includes('application/x-www-form-urlencoded')) score += 10;

    // ── HTTP status ──────────────────────────────────────────────────────────
    const status = nodeData.status_code || nodeData.status || 0;
    if (status === 200) score += 10;
    if (status === 401 || status === 403) score += 15; // protected = interesting
    if (status === 302 || status === 301) score += 5;

    // ── Forms present ───────────────────────────────────────────────────────
    if (nodeData.hasForms) score += 15;
    if (nodeData.hasPasswordField) score += 25;

    // ── JS secrets nearby ───────────────────────────────────────────────────
    if (nodeData.secretsFound && nodeData.secretsFound > 0) score += 25;

    // Active crawl > gau > waybackurls
    const source = (nodeData.discoveredBy || '').toLowerCase();
    if (source.includes('crawl')) score += 10;
    else if (source.includes('gau')) score += 5;
    else if (source.includes('wayback')) score += 3;

    // ── File extension penalties ─────────────────────────────────────────────
    if (/\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|pdf)(\?|$)/i.test(url)) score -= 30;
    if (/\.(js)(\?|$)/i.test(url)) score -= 5; // JS files have own pipeline

    return Math.max(0, score); // never negative
}

/**
 * Score all endpoints from the graph and return sorted top-N.
 *
 * @param {import('./graphStore.js').GraphStore} graph
 * @param {object} opts
 * @param {number} [opts.topN=50]    - How many to return
 * @param {number} [opts.minScore=5] - Minimum score threshold
 * @returns {Array<{ url: string, score: number, data: object }>}
 */
export function scoreGraph(graph, { topN = 50, minScore = 5 } = {}) {
    const endpoints = graph.getNodesByType('endpoint');

    const scored = endpoints.map(node => {
        const url = node.id.replace(/^endpoint:/, '');
        const s = scoreEndpoint(url, node.data || {});
        graph.setScore(node.id, s);
        return { url, score: s, data: node.data || {} };
    });

    return scored
        .filter(e => e.score >= minScore)
        .sort((a, b) => b.score - a.score)
        .slice(0, topN);
}

/**
 * Score a single endpoint object (without graph).
 * Used by orchestratorMCP for in-memory scoring.
 */
export function scoreEndpointObject(url, data = {}) {
    return { url, score: scoreEndpoint(url, data), data };
}

/**
 * Sort a plain array of endpoint URL strings or objects by score.
 *
 * @param {Array<string | object>} endpoints
 * @param {number} [topN=50]
 */
export function rankEndpoints(endpoints, topN = 50) {
    return endpoints
        .map(ep => {
            const url = typeof ep === 'string' ? ep : ep.url || ep;
            const data = typeof ep === 'object' ? ep : {};
            return scoreEndpointObject(url, data);
        })
        .filter(e => e.score >= 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, topN);
}
