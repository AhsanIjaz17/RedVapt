/**
 * utils/webCrawler.js — MCP Wrapper for Web Crawling
 *
 * Delegating to the 'web-server' MCP tool: crawl.
 */

import { mcpCall } from '../engine/mcp/mcpSessionClient.js';

/**
 * Execute a web crawl on the target URL.
 * 
 * @param {Object} params
 * @param {string} params.url
 * @param {number} [params.maxPages=30]
 * @param {number} [params.maxDepth=2]
 * @returns {Promise<Object>} Crawler results
 */

/**
 * Probe known vulnerability-rich paths for common web app frameworks.
 * This supplements crawler with hardcoded "known interesting" paths.
 */
async function probeKnownPaths(baseUrl) {
    const host = new URL(baseUrl).hostname;

    const ASPX_PATHS = [
        '/bank/login.aspx', '/bank/apply.aspx', '/bank/main.aspx',
        '/search.aspx', '/comment.aspx', '/survey_questions.aspx',
        '/bank/queryxpath.aspx', '/bank/customize.aspx',
        '/bank/transfer.aspx', '/bank/transaction.aspx',
    ];

    const PHP_PATHS = [
        '/login.php', '/search.php', '/user.php', '/admin.php',
        '/upload.php', '/include.php', '/index.php?page=',
    ];

    const API_PATHS = [
        '/api/v1/users', '/api/v1/products', '/rest/user/login',
        '/rest/products/search', '/graphql', '/api-docs', '/swagger.json',
    ];

    const allPaths = [...ASPX_PATHS, ...PHP_PATHS, ...API_PATHS];
    const discovered = { endpoints: [], forms: [] };

    const { default: axios } = await import('axios');
    const { default: https } = await import('https');

    const client = axios.create({
        timeout: 5000,
        validateStatus: () => true,
        maxRedirects: 5,
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
    });

    const results = await Promise.allSettled(
        allPaths.slice(0, 15).map(path => {
            const testUrl = `${baseUrl.replace(/\/$/, '')}${path}`;
            return client.get(testUrl).then(r => ({ url: testUrl, status: r.status, data: r.data }));
        })
    );

    for (const result of results) {
        if (result.status !== 'fulfilled') continue;
        const { url, status, data } = result.value;
        if (status >= 200 && status < 400 && typeof data === 'string' && data.length > 100) {
            discovered.endpoints.push(url);

            try {
                const { default: cheerio } = await import('cheerio');
                const $ = cheerio.load(data);
                $('form').each((_, el) => {
                    const action = $(el).attr('action') || url;
                    const method = ($(el).attr('method') || 'GET').toUpperCase();
                    const inputs = [];
                    $(el).find('input, select, textarea').each((_, inp) => {
                        const name = $(inp).attr('name');
                        if (name) inputs.push({
                            name,
                            type: $(inp).attr('type') || 'text',
                            value: $(inp).attr('value') || ''
                        });
                    });
                    if (inputs.length > 0) {
                        discovered.forms.push({ action, method, inputs });
                    }
                });
            } catch { }
        }
    }

    return discovered;
}
export async function execute({ url, maxPages = 30, maxDepth = 2 }) {
    console.log(`[webCrawler] Delegating crawl of ${url} to MCP web-server...`);

    const result = await mcpCall('web-server', 'crawl', {
        url,
        maxPages,
        maxDepth
    });

    let crawlResult;
    if (!result.success) {
        console.warn(`⚠️ [webCrawler] MCP Failed (${result.error}). Falling back to static Node crawler.`);
        crawlResult = await _fallbackCrawler(url, maxPages);
    } else {
        crawlResult = result.output;
    }

    // ✅ FIX: Also probe known interesting paths
    const knownPaths = await probeKnownPaths(url);

    // Merge discovered endpoints and forms
    const allEndpoints = [...new Set([
        ...(crawlResult?.endpoints || []),
        ...knownPaths.endpoints,
    ])];
    const allForms = [...(crawlResult?.forms || []), ...knownPaths.forms];

    console.log(`[webCrawler] Total: ${allEndpoints.length} endpoints, ${allForms.length} forms discovered`);

    // FIX: Include success flag so reconAgent can properly consume results
    return { ...crawlResult, success: true, endpoints: allEndpoints, forms: allForms };
}

// ── Fallback Crawler (Non-MCP) ────────────────────────────────────────────────
async function _fallbackCrawler(startUrl, maxPages) {
    const { default: axios } = await import('axios');
    const { default: cheerio } = await import('cheerio');
    const { default: crypto } = await import('crypto');
    const { URL } = await import('url');

    const visited = new Set();
    const endpoints = new Set();
    const forms = [];
    const parameterizedUrls = [];
    const queue = [startUrl];
    let host;
    try { host = new URL(startUrl).hostname; } catch { return { success: true, endpoints: [], forms: [], parameterizedUrls: [] }; }

    const client = axios.create({ timeout: 5000, validateStatus: () => true });

    // Pattern to extract API/route paths from JavaScript content
    const JS_API_PATTERNS = [
        /["'](\/api\/[a-zA-Z0-9_\/.{}\-?=&]+)["']/g,
        /["'](\/rest\/[a-zA-Z0-9_\/.{}\-?=&]+)["']/g,
        /["'](\/v[0-9]+\/[a-zA-Z0-9_\/.{}\-?=&]+)["']/g,
        /["'](\/graphql[a-zA-Z0-9_\/.{}\-?=&]*)["']/g,
        /["'](\/[a-zA-Z0-9_\-]{2,20}\/[a-zA-Z0-9_\-]{2,30})["']/g,
        /(?:fetch|axios|http|get|post|put|delete)\s*\(\s*["'`](\/[a-zA-Z0-9_\-\/.?=&]+)["'`]/gi,
    ];

    function extractJsEndpoints(content) {
        const found = new Set();
        for (const pattern of JS_API_PATTERNS) {
            pattern.lastIndex = 0;
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const path = match[1];
                if (path && path.length > 1 && path.length < 200 && !path.includes('\\')) {
                    found.add(path);
                }
            }
        }
        return found;
    }

    while (queue.length > 0 && visited.size < maxPages) {
        const currentUrl = queue.shift();
        if (visited.has(currentUrl)) continue;
        visited.add(currentUrl);

        try {
            const res = await client.get(currentUrl);
            const html = typeof res.data === 'string' ? res.data : '';
            const $ = cheerio.load(html);

            $('a[href]').each((_, el) => {
                const link = $(el).attr('href');
                if (!link || link.startsWith('javascript:') || link.startsWith('#')) return;
                try {
                    const resolved = new URL(link, currentUrl);
                    if (resolved.hostname === host) {
                        endpoints.add(resolved.href);
                        if (!visited.has(resolved.href)) queue.push(resolved.href);
                    }
                } catch { }
            });

            $('form').each((_, el) => {
                const action = $(el).attr('action') || currentUrl;
                const method = ($(el).attr('method') || 'GET').toUpperCase();
                const inputs = [];
                const hiddenFields = {};

                $(el).find('input, select, textarea').each((_, input) => {
                    const name = $(input).attr('name');
                    if (name) inputs.push({ name, type: input.tagName.toLowerCase() });
                });

                $(el).find('input[type="hidden"]').each((_, elHidden) => {
                    const name = $(elHidden).attr("name");
                    const value = $(elHidden).attr("value") || "";
                    if (name) hiddenFields[name] = value;
                });

                try {
                    forms.push({ url: new URL(action, currentUrl).href, method, inputs, hiddenFields });
                } catch { }
            });

            // FIX: Extract API endpoints from inline <script> tags (critical for SPAs)
            $('script').each((_, el) => {
                const scriptContent = $(el).html() || '';
                if (scriptContent.length > 10) {
                    const jsEps = extractJsEndpoints(scriptContent);
                    for (const path of jsEps) {
                        try {
                            const resolved = new URL(path, currentUrl);
                            if (resolved.hostname === host) {
                                endpoints.add(resolved.href);
                                if (resolved.search) parameterizedUrls.push(resolved.href);
                            }
                        } catch { }
                    }
                }
            });

            // Also extract from script src files (fetch and parse top JS files)
            const scriptSrcs = [];
            $('script[src]').each((_, el) => {
                const src = $(el).attr('src');
                if (src) {
                    try {
                        const resolved = new URL(src, currentUrl);
                        if (resolved.hostname === host) scriptSrcs.push(resolved.href);
                    } catch { }
                }
            });
            // Parse top 5 JS files for API endpoints
            for (const jsSrc of scriptSrcs.slice(0, 5)) {
                if (visited.has(jsSrc)) continue;
                visited.add(jsSrc);
                try {
                    const jsRes = await client.get(jsSrc);
                    const jsContent = typeof jsRes.data === 'string' ? jsRes.data : '';
                    if (jsContent.length > 10) {
                        const jsEps = extractJsEndpoints(jsContent);
                        for (const path of jsEps) {
                            try {
                                const resolved = new URL(path, currentUrl);
                                if (resolved.hostname === host) {
                                    endpoints.add(resolved.href);
                                }
                            } catch { }
                        }
                    }
                } catch { }
            }

        } catch (e) { }
    }

    return {
        success: true,
        endpoints: Array.from(endpoints).map(u => ({ url: u })),
        forms,
        parameterizedUrls,
    };
}
