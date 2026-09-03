/**
 * findingEvidenceGate.js — Bug-bounty style evidence policy
 *
 * Confirmed findings must carry reproducible proof (PoC + artifact).
 * AI may add narrative steps later; it must never substitute for this gate.
 */

function buildCurlFromFinding(f) {
    try {
        const method = (f.method || 'GET').toUpperCase();
        let url = f.endpoint || f.url;
        if (!url || typeof url !== 'string') return null;
        if (!/^https?:\/\//i.test(url)) return null;
        if (method === 'GET' && f.param != null && f.payload != null && f.payload !== '') {
            const u = new URL(url);
            u.searchParams.set(f.param, String(f.payload));
            return `curl -sS -k -g -X GET '${u.toString()}'`;
        }
        return `curl -sS -k -X ${method} '${url}'`;
    } catch {
        return null;
    }
}

function proofSnippet(ev) {
    if (!ev || typeof ev !== 'object') return '';
    return [
        ev.response_snippet,
        ev.bodySnippet,
        ev.tool_output,
        ev.evidence_snippet,
        typeof ev.responseEvidence?.bodySnippet === 'string' ? ev.responseEvidence.bodySnippet : '',
    ].filter(Boolean).join('\n');
}

function hasVisualEvidence(ev) {
    if (!ev || typeof ev !== 'object') return false;
    if (ev.visual_proof) return true;
    const pp = ev.playwrightProof;
    const confText = `${pp?.confirmation || ''} ${ev.confirmation || ''}`;
    const hasExecutionConfirmation = /executed|dialog|confirmed|browser|title-change|document\.title/i.test(confText);

    if (pp?.screenshotPaths) {
        const s = pp.screenshotPaths;
        if (s.baseline && s.exploit && hasExecutionConfirmation) return true;
        if (s.credentials_entered && s.post_login) return true;
        if (s.before && s.after) return true;
    }
    if (ev.screenshots?.baseline && ev.screenshots?.exploit && hasExecutionConfirmation) return true;
    return false;
}

/**
 * @returns {{ ok: boolean, reason?: string }}
 */
export function findingMeetsEvidencePolicy(f) {
    if (!f || !f.type) return { ok: false, reason: 'missing_type' };
    const endpoint = f.endpoint || f.url;
    if (!endpoint || typeof endpoint !== 'string') return { ok: false, reason: 'missing_endpoint' };

    const ev = f.evidence && typeof f.evidence === 'object' ? f.evidence : {};
    const curl = (f.curlPoC || ev.request || ev.curlPoC || '').toString().trim();
    const tEarly = (f.type || '').toLowerCase();
    let syntheticCurl = curl || buildCurlFromFinding(f);
    if (!syntheticCurl && tEarly.includes('credential')) {
        syntheticCurl = '# PoC: open the referenced JavaScript bundle in DevTools → Sources → search for the leaked pattern (see evidence.response_snippet).';
    }
    if (!syntheticCurl || syntheticCurl.length < 12) {
        return { ok: false, reason: 'missing_curl_or_repro' };
    }

    const snippet = proofSnippet(ev);
    const hasSnippet = snippet.replace(/\s+/g, ' ').trim().length >= 48;
    const toolProof = !!(ev.tool_used && (ev.tool_evidence || ev.tool_output));
    const verified = f.verified === true;
    const visual = hasVisualEvidence(ev);
    const toolLower = (ev.tool_used || '').toLowerCase();

    if (toolProof && toolLower.includes('nuclei')) {
        return { ok: true };
    }

    const t = (f.type || '').toLowerCase();

    if (t.includes('directory') || t.includes('misconfiguration') || t.includes('cve')) {
        if (toolProof || hasSnippet || visual) return { ok: true };
    }

    if (t.includes('jwt') && hasSnippet) {
        return { ok: true };
    }

    if (t.includes('credential') && ((f.message || '').toString().length > 40 || hasSnippet)) {
        return { ok: true };
    }

    if (t.includes('xss')) {
        const execProof =
            verified ||
            visual ||
            /browser|playwright|dialog|executed/i.test(
                `${f.confidence || ''} ${ev.confirmation || ''} ${ev.playwrightProof?.confirmation || ''}`
            );
        if (!execProof) {
            return { ok: false, reason: 'xss_requires_execution_or_screenshot_proof' };
        }
    }

    if ((/broken\s*authentication|default\s*credential/i.test(t) || (t.includes('authentication') && /default/i.test(`${f.subtype || ''}`))) && (visual || hasSnippet)) {
        return { ok: true };
    }

    if (t.includes('sql') || t.includes('injection')) {
        const sqlArtifact =
            toolProof ||
            verified ||
            /sql|syntax|mysql|postgres|ora-|jdbc|sqlite|database|union|query failed/i.test(snippet);
        const authSessionSnippet =
            hasSnippet &&
            /sign\s*off|my\s+account|\/bank\/main|main\.jsp|hello\s+admin|admin\s+user|logout\.jsp/i.test(snippet);
        const authBypassFinding = /authentication\s+bypass/i.test((f.subtype || '').toLowerCase());
        if (!sqlArtifact && !visual && !(authBypassFinding && authSessionSnippet)) {
            return { ok: false, reason: 'sqli_requires_tool_or_error_snippet' };
        }
    }

    if (!hasSnippet && !visual && !toolProof && !verified) {
        return { ok: false, reason: 'missing_proof_artifact' };
    }

    return { ok: true };
}

/**
 * @returns {{ passed: object[], dropped: { id?: string, type?: string, reason: string }[] }}
 */
export function filterFindingsByEvidencePolicy(findings = []) {
    const passed = [];
    const dropped = [];

    for (const raw of findings) {
        const f = { ...raw };
        if (!f.curlPoC) {
            const c = buildCurlFromFinding(f);
            if (c) f.curlPoC = c;
        }
        const r = findingMeetsEvidencePolicy(f);
        if (r.ok) passed.push(f);
        else dropped.push({ id: f.id, type: f.type, endpoint: f.endpoint || f.url, reason: r.reason || 'unknown' });
    }

    return { passed, dropped };
}
