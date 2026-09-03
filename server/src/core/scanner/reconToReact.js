/**
 * reconToReact.js — Recon to ReAct Data Transformer
 *
 * Normalizes raw output from reconAgent (reportData) into a structured
 * format optimized for the ReAct agent specialists and reasoning loop.
 */

// RC1 fix: strict URL validation to prevent garbage endpoints reaching vuln engine
const UNICODE_JUNK_RE = /%[Ee][0-9A-Fa-f]%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}|%[Cc][0-9A-Fa-f]%[0-9A-Fa-f]{2}/;
const EXTERNAL_NOISE = /stackexchange\.com|stackoverflow\.com|github\.com|sqlmap\.org|cyberciti\.biz|fuglekos\.com|emkei\.cz|wikipedia\.org/i;

function isValidEndpoint(url, targetDomain) {
    if (!url || typeof url !== 'string') return false;
    if (url.length > 500) return false;

    // Reject concatenated URLs (multiple http:// in the path, not in query string)
    const qPos = url.indexOf('?');
    const checkPart = qPos > 0 ? url.slice(0, qPos) : url;
    const secondHttp = checkPart.indexOf('http', 8);
    if (secondHttp > 0) return false;

    // Reject encoded unicode junk (from markdown/LLM artefacts)
    if (UNICODE_JUNK_RE.test(url)) return false;

    // Reject noise domains
    if (EXTERNAL_NOISE.test(url)) return false;

    // Reject broken extensions from concatenation
    if (/\.aspx-$|\.aspx[A-Z]/.test(url)) return false;

    try {
        const parsed = new URL(url);
        // Must be in scope
        if (targetDomain) {
            const host = parsed.hostname.toLowerCase();
            const tgt = targetDomain.toLowerCase();
            if (host !== tgt && !host.endsWith('.' + tgt)) return false;
        }
        return true;
    } catch {
        return false;
    }
}

export function transformReconToReact(reportData, target) {
    const data = {
        target,
        baseUrl: `https://${target}`,
        endpoints: [],
        forms: [],
        apiEndpoints: [],
        services: [],
        secrets: [],
        parameters: [],
        jsFiles: [],
        technologies: [],
    };

    if (!reportData) return data;

    // 1. Normalize Base URL — recon scanContext beats default https:// (HTTP-only labs)
    if (reportData.scanContext?.baseUrl) {
        data.baseUrl = reportData.scanContext.baseUrl;
    } else if (Array.isArray(reportData.liveHosts) && reportData.liveHosts.length > 0) {
        const rootHost = reportData.liveHosts.find(h => h.url?.includes(target));
        if (rootHost) data.baseUrl = rootHost.url;
    }

    // 2. Normalize Endpoints (Prioritize Validated & High-Priority)
    const allRawEps = [];
    if (Array.isArray(reportData.validatedEndpoints)) {
        allRawEps.push(...reportData.validatedEndpoints.map(e => e.url));
    }
    if (Array.isArray(reportData.highPriority)) {
        allRawEps.push(...reportData.highPriority.map(e => e.url));
    }
    if (Array.isArray(reportData.endpoints)) {
        allRawEps.push(...reportData.endpoints.map(e => typeof e === 'string' ? e : e.url));
    }
    if (Array.isArray(reportData.liveHosts)) {
        allRawEps.push(...reportData.liveHosts.map(h => typeof h === 'string' ? h : h.url || h.host));
    }
    data.endpoints.push(...allRawEps.filter(Boolean));

    // Include the new forms from deep reconnaissance
    if (Array.isArray(reportData.forms)) {
        data.forms.push(...reportData.forms.map(f => {
            const rawInputs = Array.isArray(f.inputs) ? f.inputs : JSON.parse(f.inputs || '[]');
            // Normalize inputs: string → {name, type:'text'}, object → pass through
            const normalizedInputs = rawInputs.map(i =>
                typeof i === 'string' ? { name: i, type: /pass/i.test(i) ? 'password' : 'text' } : i
            );
            return {
                action: f.action,
                method: f.method,
                inputs: normalizedInputs,
                is_high_value: Boolean(f.is_high_value),
                source: 'deep_intelligence'
            };
        }));
    }

    // Intelligence Summary for Agent
    data.intel = reportData.intel || {};
    data.highPriority = reportData.highPriority || [];

    // 3. Extract APIs from JS Endpoints
    if (Array.isArray(reportData.jsEndpoints)) {
        const jsEps = reportData.jsEndpoints
            .map(e => typeof e === 'string' ? e : e.url || e.endpoint)
            .filter(Boolean)
            .map(u => {
                if (u.startsWith('http')) return u;
                if (u.startsWith('//')) return `https:${u}`;
                const base = data.baseUrl.replace(/\/$/, '');
                return `${base}${u.startsWith('/') ? '' : '/'}${u}`;
            });

        data.endpoints.push(...jsEps);
        data.apiEndpoints = jsEps.filter(u => /\/api\//i.test(u) || /\/v\d+\//i.test(u));
    }

    // 4. Transform Parameters into Forms
    if (Array.isArray(reportData.parameters)) {
        // FIX (Breakpoint #9): no longer filter to only '?' URLs.
        // All parameter URLs get added as endpoints; the unifiedEngine
        // will synthesize common params for clean URLs (Breakpoint #6 fix).
        const paramUrls = reportData.parameters
            .map(p => typeof p === 'string' ? p : p.url || p.endpoint)
            .filter(Boolean);

        data.endpoints.push(...paramUrls);
        data.parameters = paramUrls;

        for (const url of paramUrls) {
            try {
                let absoluteUrl = url;
                if (!url.startsWith('http')) {
                    if (url.startsWith('//')) {
                        absoluteUrl = `https:${url}`;
                    } else {
                        const base = data.baseUrl.replace(/\/$/, '');
                        absoluteUrl = `${base}${url.startsWith('/') ? '' : '/'}${url}`;
                    }
                }
                const parsed = new URL(absoluteUrl);
                const inputs = [...parsed.searchParams].map(([name, value]) => ({
                    name,
                    type: 'text',
                    value: value || ''
                }));

                if (inputs.length > 0) {
                    data.forms.push({
                        action: `${parsed.origin}${parsed.pathname}`,
                        method: 'GET',
                        inputs,
                        source: 'paramspider'
                    });
                }
            } catch (e) {
                // Skip malformed
            }
        }
    }

    // 5. Normalize Secrets — IGNORE LIBRARIES (jQuery, etc.)
    const rawSecrets = reportData.jsSecrets || reportData.secrets || [];
    const libPattern = /jquery|bootstrap|vendor|assets|plugins/i;

    if (Array.isArray(rawSecrets)) {
        data.secrets = rawSecrets
            .filter(s => {
                const src = s.js_file || s.source || '';
                return !libPattern.test(src);
            })
            .map(s => ({
                type: s.secret_type || s.type || 'unknown',
                value: s.secret || s.value || '',
                source: s.js_file || s.source || ''
            }));
    }

    // 6. Normalize Services
    if (Array.isArray(reportData.services)) {
        data.services = reportData.services.map(s => ({
            port: s.port,
            service: s.service,
            version: s.version
        }));
    }

    // 7. Normalize Technologies
    const techs = [];
    if (Array.isArray(reportData.technologies)) {
        techs.push(...reportData.technologies.map(t => t.name || t));
    }
    if (Array.isArray(reportData.liveHosts)) {
        techs.push(...reportData.liveHosts.flatMap(h => h.tech || h.technologies || []));
    }
    data.technologies = [...new Set(techs.filter(Boolean))];

    // 8. JS Files for analysis
    if (Array.isArray(reportData.jsFiles)) {
        data.jsFiles = (reportData.jsFiles || [])
            .sort((a, b) => {
                const p = { high: 3, medium: 2, low: 1 };
                return (p[b.classification] || 0) - (p[a.classification] || 0);
            })
            .slice(0, 50)
            .map(f => typeof f === "string" ? f : f.url)
            .filter(Boolean);
    }

    // Final Deduplication — RC1 fix: strict URL validation as last gate before vuln engine
    data.endpoints = [...new Set(
        data.endpoints
            .filter(Boolean)
            .map(e => e.trim())
            .filter(e => isValidEndpoint(e, target))
    )];
    data.parameters = [...new Set(data.parameters.filter(Boolean))];
    data.forms = data.forms.filter((f, i, self) =>
        i === self.findIndex(t => t.action === f.action && JSON.stringify(t.inputs) === JSON.stringify(f.inputs))
    );

    return data;
}
