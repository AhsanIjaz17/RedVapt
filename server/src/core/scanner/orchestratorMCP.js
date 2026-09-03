/**
 * core/orchestratorMCP.js — State-Machine Orchestrator (MCP-Backed)
 *
 * Drives the full scan pipeline through MCP tool servers.
 * The orchestrator NEVER calls exec() directly — only MCP clients.
 *
 * State machine:
 *   INIT → RECON → GRAPH_BUILD → CRAWL → PARAM_GRAPH → JS_INTEL → SCORE → VULN_SCAN → REPORT
 *
 * All SSE progress events follow the existing format so the UI is unaffected.
 *
 * SECURITY:
 *   - All tool calls go through McpClient (exec-safe, validated)
 *   - Hostname validated before first MCP call
 *   - Rate limiter applied between MCP calls
 */

import { McpSessionClient as McpClient } from '../../engine/mcp/mcpSessionClient.js';
import { GraphStore } from '../../engine/graph/graphStore.js';
import { rankEndpoints } from '../../engine/graph/scoringEngine.js';
import { runUnifiedScan } from '../../engine/vuln/unifiedEngine.js';
import {
    parseSubfinder,
    parseDnsResolve,
    parseHttpx,
    parseHttpxJson,
    parseWafw00f,
    parseNmap,
    parseGauEndpoints,
    parseLinkFinder,
    parseParamSpider,
} from '../../utils/parsers.js';
import { discoverParameters } from '../../utils/paramDiscovery.js';
import { validateTarget } from './reconAgent.js';

const RECON = new McpClient('recon-server');
const JSINT = new McpClient('jsintel-server');
const WEB = new McpClient('web-server');

// Security & Safety Guardrails (R14)
const GLOBAL_RATE_LIMIT_MS = 200; // 5 requests per second
const MAX_TOTAL_REQUESTS = 5000;

const sleep = (ms) => new Promise(res => setTimeout(res, ms));

async function rateLimitCall(client, method, params) {
    await sleep(GLOBAL_RATE_LIMIT_MS);
    return client.call(method, params);
}

/** Prefer httpx-reported scheme/host so HTTP-only labs are crawled correctly. */
function pickMcpCrawlUrl(safeTarget, liveHttpHosts) {
    const norm = safeTarget.toLowerCase().replace(/^www\./, '');
    for (const h of liveHttpHosts || []) {
        const raw = h.url || h.input;
        if (!raw || typeof raw !== 'string' || !raw.startsWith('http')) continue;
        try {
            const host = new URL(raw).hostname.toLowerCase().replace(/^www\./, '');
            if (host === norm || host.endsWith(`.${norm}`)) return raw;
        } catch { /* ignore */ }
    }
    return `https://${safeTarget}`;
}

// ── State machine driver ─────────────────────────────────────────────────────

export async function runMcpPipeline(target, onProgress = () => { }) {
    const safeTarget = validateTarget(target);
    const graph = new GraphStore(); // in-memory per scan

    graph.addNode({ id: `domain:${safeTarget}`, type: 'domain', data: { domain: safeTarget } });

    const p = (phase, status, message) => onProgress({ phase, status, message });

    // ── STATE: RECON ────────────────────────────────────────────────────────
    p('recon_mcp', 'running', '🔍 MCP Recon: Asset discovery starting...');

    // Parallel discovery
    const [subfinderRes, assetfinderRes, crtRes] = await Promise.allSettled([
        rateLimitCall(RECON, 'subfinder', { domain: safeTarget }),
        rateLimitCall(RECON, 'assetfinder', { domain: safeTarget }),
        rateLimitCall(RECON, 'crtsh', { domain: safeTarget }),
    ]);

    const allSubs = new Set();
    for (const res of [subfinderRes, assetfinderRes, crtRes]) {
        if (res.status === 'fulfilled' && res.value?.success) {
            (res.value.output || []).forEach(s => allSubs.add(s.toLowerCase().trim()));
        }
    }
    allSubs.add(safeTarget);

    p('recon_mcp', 'running', `✅ [MCP Recon] ${allSubs.size} subdomains discovered`);

    // DNS resolution
    const dnsRes = await rateLimitCall(RECON, 'dns_resolve', { subdomains: [...allSubs] });
    const resolved = (dnsRes?.output || []).filter(r => r.resolves);
    const liveHosts = resolved.map(r => r.subdomain);

    p('recon_mcp', 'running', `🌐 [MCP Recon] ${liveHosts.length} hosts resolve`);

    // httpx probing
    const httpxRes = await rateLimitCall(RECON, 'httpx', { hosts: liveHosts });
    const liveHttpHosts = httpxRes?.output || [];

    p('recon_mcp', 'running', `🔌 [MCP Recon] ${liveHttpHosts.length} live HTTP services`);

    // ── STATE: GRAPH_BUILD ──────────────────────────────────────────────────
    p('graph_build', 'running', '📊 Building recon graph...');

    for (const host of liveHosts) {
        graph.addSubdomain(host, safeTarget);
    }
    for (const h of liveHttpHosts) {
        const url = h.url || h.input || `https://${h}`;
        graph.addNode({ id: `host:${h.input || h}`, type: 'host', data: h });
        graph.addEndpoint(url, h.input || safeTarget, { status_code: h.status_code, content_type: h['content-type'] });
    }

    // Nmap, wafw00f, gau, waybackurls in parallel
    const [nmapRes, wafRes, gauRes, waybackRes, paramRes] = await Promise.allSettled([
        rateLimitCall(RECON, 'nmap', { domain: safeTarget }),
        rateLimitCall(RECON, 'wafw00f', { domain: safeTarget }),
        rateLimitCall(RECON, 'gau', { domain: safeTarget }),
        rateLimitCall(RECON, 'waybackurls', { domain: safeTarget }),
        rateLimitCall(RECON, 'paramspider', { domain: safeTarget }),
    ]);

    const endpoints = new Set();

    for (const res of [gauRes, waybackRes, paramRes]) {
        if (res.status === 'fulfilled' && res.value?.success) {
            (res.value.output || []).forEach(u => { if (u && u.startsWith('http')) endpoints.add(u); });
        }
    }

    // Add to graph
    for (const url of endpoints) {
        graph.addEndpoint(url, safeTarget, { discoveredBy: 'mcp-recon' });
    }

    const technologies = liveHttpHosts.flatMap(h => h.tech || []).filter(Boolean);
    const waf = wafRes.status === 'fulfilled' ? wafRes.value?.output : null;
    const services = [];

    if (nmapRes.status === 'fulfilled' && nmapRes.value?.output) {
        // Parse basic port lines
        const portLines = nmapRes.value.output.match(/(\d+)\/tcp\s+open\s+(\S+)/g) || [];
        for (const line of portLines) {
            const m = line.match(/(\d+)\/tcp\s+open\s+(\S+)/);
            if (m) services.push({ port: +m[1], service: m[2] });
        }
    }

    let forms = [];
    const crawlSeedUrl = pickMcpCrawlUrl(safeTarget, liveHttpHosts);

    // ── STATE: CRAWL (before JS intel — seeds forms, in-scope links, JS URLs) ─
    p('crawl_mcp', 'running', '🕷️ [MCP Crawl] Crawling target...');

    const crawlRes = await rateLimitCall(WEB, 'crawl', { url: crawlSeedUrl, maxPages: 55, maxDepth: 3 });
    const crawlData = crawlRes?.output || {};
    forms = crawlData.forms || [];
    (crawlData.endpoints || []).forEach(u => endpoints.add(u));

    const jsUrls = new Set();
    (crawlData.jsFiles || []).forEach(u => jsUrls.add(u));

    p('crawl_mcp', 'done', `🕷️ Crawl: ${crawlData.pagesVisited || 0} pages, ${forms.length} forms`);

    const discoveredParams = discoverParameters([...endpoints], forms);
    for (const pRow of discoveredParams) {
        const params = pRow.params.split(', ').filter(Boolean);
        for (const pa of params) {
            graph.addParameter(pa, pRow.url);
        }
    }

    p('graph_build', 'done', `✅ Graph: ${graph.stats().nodes?.endpoint || 0} endpoints, ${graph.stats().nodes?.parameter || 0} params`);

    // ── STATE: JS_INTEL ────────────────────────────────────────────────────
    p('jsintel_mcp', 'running', '🔬 [MCP JsIntel] Classifying JS files...');

    const crawlBase = (() => {
        try {
            const u = new URL(crawlSeedUrl);
            return `${u.protocol}//${u.host}`;
        } catch {
            return `https://${safeTarget}`;
        }
    })();

    const classifiedJs = await rateLimitCall(JSINT, 'classify_js', { jsFiles: [...jsUrls] });
    const topJs = (classifiedJs?.output || []).slice(0, 15);

    const secrets = [];
    await Promise.allSettled(topJs.map(async ({ url: jsUrl }) => {
        if (!jsUrl) return;
        const dl = await rateLimitCall(JSINT, 'download_js', { url: jsUrl });
        if (!dl?.output?.content) return;
        const sc = await rateLimitCall(JSINT, 'scan_secrets', { content: dl.output.content, source: jsUrl });
        if (sc?.output?.length) secrets.push(...sc.output);
        const eps = await rateLimitCall(JSINT, 'extract_endpoints', { content: dl.output.content, baseUrl: crawlBase });
        if (eps?.output?.length) eps.output.forEach(e => endpoints.add(e));
    }));

    p('jsintel_mcp', 'done', `🔑 JS Intel: ${topJs.length} files analysed, ${secrets.length} secrets found`);

    // ── STATE: SCORE ────────────────────────────────────────────────────────
    p('scoring', 'running', '📊 Scoring attack surface...');

    const allEndpointsList = [...endpoints];
    const rankedEndpoints = rankEndpoints(allEndpointsList, 95);

    p('scoring', 'done', `📊 Top ${rankedEndpoints.length} endpoints scored for scanning`);

    // ── STATE: VULN_SCAN ────────────────────────────────────────────────────
    p('vuln_scan_mcp', 'running', '🔫 [MCP VulnScan] Running unified vulnerability scan...');

    const topEndpointUrls = rankedEndpoints.map(e => e.url);
    const { findings: engineFindings, attemptedFindings, observedHeaders } = await runUnifiedScan({
        target: safeTarget,
        endpoints: topEndpointUrls,
        forms,
        technologies: [...new Set(technologies)],
        onProgress,
    });

    p('vuln_scan_mcp', 'running', `✅ Unified scan complete: ${engineFindings.length} confirmed, ${attemptedFindings.filter(a => a.hadSignal).length} signals needing deep-dive`);

    // ── STATE: DEEP_DIVE (ReAct Escalation) ──────────────────────────────────
    // R14: Shift ReAct to scoring-driven traversal. LLM only used for signals.
    let finalFindings = [...engineFindings];
    const deepDiveTargets = attemptedFindings
        .filter(a => a.hadSignal && a.confidence > 0.2)
        .sort((a, b) => b.confidence - a.confidence)
        .slice(0, 14);

    if (deepDiveTargets.length > 0) {
        p('vuln_scan_mcp', 'running', `🧠 [Deep Dive] Escalating ${deepDiveTargets.length} signals to ReAct Agent for exploitation...`);

        const deepDiveHypotheses = deepDiveTargets.map(t => ({
            type: t.vulnType,
            endpoint: t.endpoint || t.url,
            paramName: t.param,
            confidence: t.confidence > 0.6 ? 'high' : 'medium',
            reason: `Signal detected (type: ${t.signalType}) during engine scan.`,
            payloads: [t.payload]
        }));

        try {
            const { runReactLoop } = await import('./reactAgent.js');
            const { vulns: agentVulns } = await runReactLoop(safeTarget, {
                reconData: {
                    baseUrl: crawlBase,
                    endpoints: topEndpointUrls,
                    forms,
                    technologies: [...new Set(technologies)]
                },
                hypothesisQueue: deepDiveHypotheses,
                maxIterations: 48 // keep MCP runs bounded but enough for auth + XSS passes
            }, onProgress);

            if (agentVulns?.length > 0) {
                // Merge and deduplicate
                agentVulns.forEach(av => {
                    const exists = finalFindings.some(f => f.endpoint === av.endpoint && f.type === av.type);
                    if (!exists) finalFindings.push(av);
                });
            }
        } catch (err) {
            console.error('ReAct Deep Dive error:', err);
        }
    }

    p('vuln_scan_mcp', 'done', `✅ Scan complete — ${finalFindings.length} total findings`);

    // ── Build return payload (compatible with existing report schema) ─────
    const endpointCount = allEndpointsList.length;
    const liveHostCount = liveHttpHosts.length;

    // results shape matching existing recon report fields
    const reconResults = {
        liveHosts: liveHostCount || 1,
        totalSubdomains: allSubs.size,
        endpoints: endpointCount,
        forms: forms.length,
        secrets: secrets.length,
        technologies: [...new Set(technologies)],
        waf: waf || null,
        services,
    };

    const reconReportData = {
        target: safeTarget,
        subdomains: [...allSubs],
        liveHosts: liveHttpHosts,
        endpoints: allEndpointsList,
        forms,
        parameters: [...graph.getNodesByType('parameter').map(n => n.data?.name)],
        secrets,
        technologies: [...new Set(technologies)],
        services,
        highPriority: rankedEndpoints,
    };

    return {
        findings: finalFindings,
        reconResults,
        reconReportData,
        graphStats: graph.stats(),
        graph,
    };
}
