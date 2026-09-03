/**
 * llmAnalyzer.js — Post-Agent LLM Final Analysis
 *
 * Runs AFTER all agent work (recon + exploitation) completes.
 * Outputs STRUCTURED JSON so reportGenerator.js can render:
 *   - Attack path chains
 *   - Risk-contextualized findings
 *   - Prioritized remediation roadmap
 *
 * MODEL: llama-3.3-70b-versatile — better reasoning and consistency
 */

import { callLLM } from '../../engine/llm/llmRouter.js';
import config from '../../utils/env.js';



const MAX_INPUT_CHARS = 8000; // ~2000 tokens input

// ── OWASP Top 10 (2021) mapping ─────────────────────────────────────────────
export const OWASP_MAP = {
    'SQL Injection': { owasp: 'A03:2021 — Injection', cwe: 'CWE-89' },
    'NoSQL Injection': { owasp: 'A03:2021 — Injection', cwe: 'CWE-943' },
    'Command Injection': { owasp: 'A03:2021 — Injection', cwe: 'CWE-78' },
    'XSS': { owasp: 'A03:2021 — Injection', cwe: 'CWE-79' },
    'SSRF': { owasp: 'A10:2021 — SSRF', cwe: 'CWE-918' },
    'Authentication Bypass': { owasp: 'A07:2021 — Auth Failures', cwe: 'CWE-287' },
    'IDOR': { owasp: 'A01:2021 — Broken Access Control', cwe: 'CWE-639' },
    'Path Traversal': { owasp: 'A01:2021 — Broken Access Control', cwe: 'CWE-22' },
    'Sensitive Data Exposure': { owasp: 'A02:2021 — Crypto Failures', cwe: 'CWE-200' },
    'Security Misconfiguration': { owasp: 'A05:2021 — Misconfiguration', cwe: 'CWE-16' },
    'Broken Access Control': { owasp: 'A01:2021 — Broken Access Control', cwe: 'CWE-284' },
    'Open Redirect': { owasp: 'A01:2021 — Broken Access Control', cwe: 'CWE-601' },
    'Header Injection': { owasp: 'A03:2021 — Injection', cwe: 'CWE-113' },
};

// ── Remediation templates with code examples ────────────────────────────────
export const REMEDIATION_MAP = {
    'SQL Injection': {
        text: '- **Use Parameterized Queries**: Ensure all SQL queries use bind variables to separate code from data.\n- **Input Validation**: Implement strict allowlists for user-supplied table or column names.\n- **Least Privilege**: Run the database service with a user that has minimal necessary permissions.',
        code: '// ❌ Vulnerable\ndb.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n\n// ✅ Fixed\ndb.query(\'SELECT * FROM users WHERE id = ?\', [req.query.id]);',
        lang: 'javascript',
    },
    'NoSQL Injection': {
        text: '- **Type Checking**: Reject objects where strings are expected to prevent operator injection.\n- **Query Builders**: Use well-vetted query builder libraries that automatically handle escaping.\n- **Input Sanitization**: Remove special characters like $ and . from user input.',
        code: '// ❌ Vulnerable\ndb.users.find({ username: req.body.username });\n\n// ✅ Fixed\nconst username = String(req.body.username).replace(/[^a-zA-Z0-9_]/g, \'\');\ndb.users.find({ username });',
        lang: 'javascript',
    },
    'Command Injection': {
        text: '- **Avoid Shell Execution**: Use built-in APIs like fs.readFile instead of system commands.\n- **Safe APIs**: Use execFile() with argument arrays instead of exec() to prevent shell interpolation.\n- **Allowlisting**: Apply strict regex-based allowlists to any required command arguments.',
        code: '// ❌ Vulnerable\nexec(`ping ${req.query.host}`, callback);\n\n// ✅ Fixed\nexecFile(\'ping\', [\'-c\', \'1\', req.query.host], callback);',
        lang: 'javascript',
    },
    'XSS': {
        text: '- **Output Encoding**: Apply context-aware encoding (HTML, Attribute, JS) to all user-supplied data.\n- **CSP**: Implement a strict Content-Security-Policy that disables unsafe-inline scripts.\n- **Secure Cookies**: Set the HttpOnly flag on session cookies to mitigate session theft.',
        code: '// ❌ Vulnerable\nelement.innerHTML = userInput;\n\n// ✅ Fixed\nelement.textContent = userInput;  // or\nelement.innerHTML = DOMPurify.sanitize(userInput);',
        lang: 'javascript',
    },
    'SSRF': {
        text: '- **DNS Allowlisting**: Restrict outbound requests to a pre-defined set of trusted domains.\n- **Internal Blocking**: Block access to RFC 1918 internal IP ranges and localhost.\n- **Network Isolation**: Isolate the app server and restrict its egress traffic.',
        code: '# ❌ Vulnerable\nrequests.get(request.args[\'url\'])\n\n# ✅ Fixed\nALLOWED = [\'https://api.example.com\']\nif request.args[\'url\'] not in ALLOWED:\n    abort(400)',
        lang: 'python',
    },
    'Authentication Bypass': {
        text: '- **Server-Side Checks**: Enforce authentication and authorization on the server-side for every request.\n- **MFA**: Implement Multi-Factor Authentication for sensitive actions.\n- **Session Management**: Use short-lived, secure tokens for session tracking.',
        code: '// ❌ Vulnerable\nif (req.cookies.isAdmin === \'true\') { ... }\n\n// ✅ Fixed\nconst user = await verifyJWT(req.headers.authorization);\nif (!user || !user.isAdmin) return res.status(403).json({ error: \'Forbidden\' });',
        lang: 'javascript',
    },
    'IDOR': {
        text: '- **Authorization Logic**: Explicitly verify user ownership or permissions for every resource access.\n- **UUIDs**: Use non-predictable, random identifiers (UUIDs) instead of sequential IDs.\n- **Indirect References**: Use reference maps to decouple internal IDs from user input.',
        code: '// ❌ Vulnerable\nconst record = await db.find(req.params.id);\n\n// ✅ Fixed\nconst record = await db.find(req.params.id);\nif (record.ownerId !== req.user.id) return res.status(403).send(\'Forbidden\');',
        lang: 'javascript',
    },
    'Path Traversal': {
        text: '- **Path Normalization**: Resolve and normalize paths (e.g. removing ../) before filesystem access.\n- **Base Directory**: Ensure all file operations are restricted to a defined base directory.',
        code: '// ❌ Vulnerable\nconst file = path.join(\'/uploads\', req.query.file);\n\n// ✅ Fixed\nconst base = path.resolve(\'/uploads\');\nconst file = path.resolve(base, req.query.file);\nif (!file.startsWith(base)) return res.status(400).send(\'Invalid path\');',
        lang: 'javascript',
    },
    'Sensitive Data Exposure': {
        text: '- **Secret Rotation**: Immediately rotate any exposed credentials or API keys.\n- **Environment Variables**: Store sensitive data in server-side environment variables, never in client code.\n- **Vault Services**: Use managed vault services for secure secret storage.',
        code: '// ❌ Vulnerable — in client JS\nconst API_KEY = \'AIza...abc123\';\n\n// ✅ Fixed — server-side proxy\napp.get(\'/api/maps\', authMiddleware, async (req, res) => {\n  const result = await maps.geocode({ key: process.env.MAPS_KEY, ... });\n  res.json(result);\n});',
        lang: 'javascript',
    },
    'Open Redirect': {
        text: '- **Destination Validation**: Use an allowlist of permitted redirect domains.\n- **Internal Redirects**: Prefer relative URLs for redirection when navigating within the app.',
        code: '# ❌ Vulnerable\nredirect(request.args.get(\'next\'))\n\n# ✅ Fixed\nALLOWED_HOSTS = [\'example.com\', \'app.example.com\']\nnext_url = request.args.get(\'next\', \'/\')\nif urlparse(next_url).netloc not in ALLOWED_HOSTS:\n    next_url = \'/\'\nreturn redirect(next_url)',
        lang: 'python',
    },
    'Security Misconfiguration': {
        text: '- **Security Headers**: Implement HSTS, Content-Security-Policy, and X-Frame-Options headers.\n- **Minimal Config**: Disable unnecessary services, features, and debug modes.\n- **Default Cleanup**: Change all default passwords and remove default accounts.',
        code: '# Nginx hardening\nserver {\n  add_header X-Content-Type-Options nosniff;\n  add_header X-Frame-Options DENY;\n  add_header Content-Security-Policy "default-src \'self\'";\n  add_header Strict-Transport-Security "max-age=31536000" always;\n  autoindex off;\n}',
        lang: 'nginx',
    },
};

// ── Secret risk context ──────────────────────────────────────────────────────
export const SECRET_RISK_MAP = {
    'google_api': { risk: 'High', exploitability: 'Easy', impact: 'Quota theft, billing attacks, Maps/Geocoding API abuse' },
    'aws_key': { risk: 'Critical', exploitability: 'Easy', impact: 'Full AWS account takeover, data exfiltration, resource abuse' },
    'stripe_key': { risk: 'Critical', exploitability: 'Easy', impact: 'Financial theft, customer PII exposure, payment fraud' },
    'github_token': { risk: 'High', exploitability: 'Easy', impact: 'Source code access, secret exfiltration, CI/CD hijack' },
    'jwt_secret': { risk: 'Critical', exploitability: 'Medium', impact: 'Authentication bypass, account takeover for all users' },
    'private_key': { risk: 'Critical', exploitability: 'Medium', impact: 'TLS decryption, identity impersonation' },
    'firebase_key': { risk: 'High', exploitability: 'Easy', impact: 'Database read/write, storage access, authentication bypass' },
    'slack_token': { risk: 'Medium', exploitability: 'Easy', impact: 'Internal message exfiltration, workspace data access' },
    'sendgrid_api_key': { risk: 'Medium', exploitability: 'Easy', impact: 'Email spoofing, phishing via trusted domain' },
    'mailchimp_api_key': { risk: 'Medium', exploitability: 'Easy', impact: 'Customer email list exfiltration' },
    'database_url': { risk: 'Critical', exploitability: 'Easy', impact: 'Full database read/write access' },
    'password': { risk: 'High', exploitability: 'Medium', impact: 'Account takeover, lateral movement' },
    'generic_secret': { risk: 'Medium', exploitability: 'Unknown', impact: 'Depends on usage context — manual review required' },
};


/**
 * Build a concise summary of all scan data for LLM input.
 */
function buildScanContext(target, reconData, agentResult) {
    const parts = [`## Scan Context: ${target}`, `Date: ${new Date().toISOString()}`];

    if (reconData) {
        parts.push('\n## Recon');
        parts.push(`Endpoints: ${reconData.endpoints?.length || 0} | Forms: ${reconData.forms?.length || 0} | Secrets: ${reconData.secrets?.length || 0} | Services: ${reconData.services?.length || 0}`);
        if (reconData.technologies?.length) parts.push(`Technologies: ${reconData.technologies.slice(0, 8).join(', ')}`);
        if (reconData.secrets?.length > 0) {
            parts.push('\nExposed secrets:');
            reconData.secrets.slice(0, 5).forEach(s => parts.push(`  - [${s.type}] ${s.value?.slice(0, 40)} (from: ${s.source?.split('/').pop() || 'JS'})`));
        }
        const topEps = (reconData.endpoints || []).filter(e => e.includes('?')).slice(0, 10);
        if (topEps.length > 0) {
            parts.push('\nParameterized endpoints (injection targets):');
            topEps.forEach(e => parts.push(`  - ${e}`));
        }
    }

    if (agentResult) {
        parts.push('\n## Exploitation');
        parts.push(`Steps: ${agentResult.trace?.totalSteps || 0} | Payloads: ${agentResult.trace?.payloadsTested || 0} | Vulns: ${agentResult.vulns?.length || 0}`);
        if (agentResult.vulns?.length > 0) {
            parts.push('\nConfirmed vulns:');
            for (const v of agentResult.vulns.slice(0, 8)) {
                parts.push(`  - [${v.severity}] ${v.type} at ${v.endpoint}${v.payload ? ` (payload: ${v.payload.slice(0, 40)})` : ''}`);
            }
        }
        if (agentResult.testedClasses?.length > 0) {
            parts.push(`\nTested: ${agentResult.testedClasses.join(', ')}`);
        }
    }

    let context = parts.join('\n');
    if (context.length > MAX_INPUT_CHARS) context = context.slice(0, MAX_INPUT_CHARS) + '\n...[truncated]';
    return context;
}

/**
 * Generate the final comprehensive LLM analysis as structured JSON.
 */
export async function generateFinalAnalysis(target, reconData = {}, agentResult = {}, onProgress = () => { }) {
    onProgress({ phase: 'final_analysis', status: 'running', message: '🧠 Running final LLM security analysis...' });

    const groq_REMOVED = null;  // Groq removed — using OpenRouter via callLLM()
    const context = buildScanContext(target, reconData, agentResult);
    const vulnCount = agentResult.vulns?.length || 0;

    const systemPrompt = `You are a senior penetration testing consultant. Analyze the scan data and return ONLY valid JSON (no markdown, no explanation) with this exact structure:

{
  "executiveSummary": "2-3 sentence risk summary referencing actual findings",
  "riskRating": "Critical|High|Medium|Low",
  "riskJustification": "One sentence explaining the rating",
  "attackPaths": [
    {
      "title": "Short attack path name",
      "steps": ["Starting asset", "Vulnerability/weakness", "Exploitation method", "Business impact"],
      "likelihood": "High|Medium|Low"
    }
  ],
  "keyRisks": ["Risk 1 sentence", "Risk 2 sentence"],
  "testedAreas": ["SQL Injection", "XSS", "SSRF"],
  "untestedAreas": ["XXE", "Business Logic"],
  "immediateActions": ["Action 1", "Action 2"],
  "securityPosture": "One paragraph conclusion",
  "hasVulns": ${vulnCount > 0}
}

Rules:
- attackPaths: max 3, based ONLY on actual findings/endpoints in the data
- steps: exactly 4 strings showing the attack chain
- testedAreas: what the AI agent actually tested based on the context
- Be specific: reference real endpoints and findings, not generic advice
- Return ONLY the JSON object, nothing else`;

    try {
        const llmResult = await callLLM({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: context },
            ],
            max_tokens: 1200,
            temperature: 0.3,
        });

        if (llmResult.success && llmResult.output) {
            let parsed;
            try { parsed = JSON.parse(llmResult.output); } catch { parsed = {}; }
            onProgress({ phase: 'final_analysis', status: 'done', message: '✅ Final LLM analysis complete' });
            return { ...parsed, _source: 'llm', _model: llmResult.modelUsed };
        }

        // LLM unavailable — use structured fallback
        console.warn('[llmAnalyzer] LLM unavailable:', llmResult.error);
        onProgress({ phase: 'final_analysis', status: 'done', message: `⚠️ LLM analysis skipped: ${llmResult.error?.slice(0, 80)}` });
        return buildFallbackAnalysisJSON(target, reconData, agentResult);

    } catch (err) {
        console.error('LLM Final Analysis error:', err.message || err);
        onProgress({ phase: 'final_analysis', status: 'done', message: `⚠️ LLM analysis skipped: ${err.message?.slice(0, 80)}` });
        return buildFallbackAnalysisJSON(target, reconData, agentResult);
    }
}

/**
 * Fallback structured analysis when LLM is unavailable.
 */
function buildFallbackAnalysisJSON(target, reconData, agentResult) {
    const vulns = agentResult.vulns || [];
    const critCount = vulns.filter(v => v.severity === 'critical').length;
    const highCount = vulns.filter(v => v.severity === 'high').length;
    const riskRating = critCount > 0 ? 'Critical' : highCount > 0 ? 'High' : vulns.length > 0 ? 'Medium' : 'Low';

    const attackPaths = vulns.slice(0, 3).map(v => ({
        title: `${v.type} at ${(v.endpoint || '').split('/').pop() || 'endpoint'}`,
        steps: [
            `${target} (public attack surface)`,
            `${v.endpoint || 'endpoint'} found during recon`,
            `${v.type} exploited${v.payload ? ` with: ${v.payload.slice(0, 50)}` : ''}`,
            v.impact || 'Data exposure / unauthorized access',
        ],
        likelihood: v.severity === 'critical' || v.severity === 'high' ? 'High' : 'Medium',
    }));

    return {
        executiveSummary: vulns.length > 0
            ? `Automated assessment of ${target} identified ${vulns.length} confirmed ${riskRating.toLowerCase()}-severity vulnerabilities. Immediate remediation is required for the issues listed below.`
            : `Automated assessment of ${target} found no confirmed exploitable vulnerabilities. ${reconData.secrets?.length > 0 ? 'However, exposed secrets in JavaScript files require immediate rotation.' : 'The target demonstrates adequate security controls against automated attacks.'}`,
        riskRating,
        riskJustification: vulns.length > 0
            ? `${vulns.length} exploitable vulnerability/vulnerabilities confirmed with working proof-of-concept.`
            : 'No exploitable vulnerabilities confirmed by automated agent.',
        attackPaths: attackPaths.length > 0 ? attackPaths : (reconData.secrets?.length > 0 ? [{
            title: 'Secret Exposure → Credential Abuse',
            steps: [
                `${target} — publicly accessible JavaScript files`,
                `${reconData.secrets[0]?.source?.split('/').pop() || 'JS file'} exposes ${reconData.secrets[0]?.type || 'API key'}`,
                'Attacker extracts and uses credential directly',
                reconData.secrets[0]?.type?.toLowerCase().includes('aws') ? 'AWS account compromise' : 'API quota theft, service abuse, or data access',
            ],
            likelihood: 'High',
        }] : []),
        keyRisks: vulns.length > 0
            ? vulns.slice(0, 3).map(v => `${v.type} at ${v.endpoint} — ${v.impact || v.severity + ' severity'}`)
            : reconData.secrets?.length > 0
                ? [`${reconData.secrets.length} secret(s) exposed in public JavaScript files`]
                : ['No high-risk findings confirmed by automated agent'],
        testedAreas: agentResult.testedClasses || ['SQL Injection', 'XSS', 'SSRF', 'Command Injection', 'IDOR', 'Path Traversal', 'Authentication Bypass'],
        untestedAreas: ['Business Logic Flaws', 'Race Conditions', 'Second-Order Injection', 'File Upload Bypass', 'GraphQL Injection'],
        immediateActions: vulns.length > 0
            ? vulns.slice(0, 3).map(v => `Patch ${v.type} in ${v.endpoint || 'affected endpoint'}`)
            : reconData.secrets?.length > 0
                ? ['Rotate all exposed credentials immediately', 'Move secrets to server-side environment variables or vault']
                : ['Conduct manual testing of business logic flows', 'Review server response headers for security misconfigurations'],
        securityPosture: `The automated assessment of ${target} has completed. ${vulns.length > 0 ? `A total of ${vulns.length} vulnerability/vulnerabilities were confirmed. Priority remediation should focus on ${vulns[0]?.type || 'the confirmed findings'}.` : 'While no exploitable vulnerabilities were automatically confirmed, manual testing by a human pentester is recommended to cover business logic, race conditions, and complex multi-step attack chains.'}`,
        hasVulns: vulns.length > 0,
        _source: 'fallback',
    };
}

/**
 * After deterministic confirmation, use the LLM only to write human-readable PoC steps.
 * Does not change severity or add findings — narrative only.
 */
export async function enrichConfirmedFindingsWithReviewerPoC(findings = [], onProgress = () => { }) {
    if (!findings?.length) return findings;

    const slice = findings.slice(0, 12).map((v, i) => ({
        i,
        type: v.type,
        severity: v.severity,
        endpoint: v.endpoint || v.url,
        param: v.param,
        method: v.method,
        curl: String(v.curlPoC || v.evidence?.request || '').slice(0, 600),
        proof: String(v.evidence?.response_snippet || v.evidence?.tool_output || '').slice(0, 400),
    }));

    try {
        const llmResult = await callLLM({
            messages: [
                {
                    role: 'system',
                    content: 'You are a senior bug bounty triager. Each item is ALREADY confirmed by automated proof (HTTP/tool/browser). Write 3–6 numbered reproduction steps per item so a developer can verify. Use only facts from the JSON. Do not claim new vulnerabilities. Return ONLY JSON: { "byIndex": { "0": "1. ...\\n2. ...", "1": "..." } } using string keys "0","1",... matching field i.',
                },
                { role: 'user', content: JSON.stringify(slice) },
            ],
            max_tokens: 1800,
            temperature: 0.15,
            jsonMode: true,
        });

        if (!llmResult.success || !llmResult.output) return findings;

        let parsed;
        const raw = llmResult.output.trim();
        try {
            parsed = JSON.parse(raw);
        } catch {
            const start = raw.indexOf('{');
            const end = raw.lastIndexOf('}');
            if (start >= 0 && end > start) parsed = JSON.parse(raw.slice(start, end + 1));
            else return findings;
        }

        const byIndex = parsed.byIndex || parsed.stepsByIndex || parsed;
        if (!byIndex || typeof byIndex !== 'object') return findings;

        onProgress({
            phase: 'final_analysis',
            status: 'running',
            message: '📝 LLM: Adding reviewer-style PoC narratives to confirmed findings…',
        });

        return findings.map((v, i) => {
            const steps = byIndex[String(i)] ?? byIndex[i];
            if (!steps || typeof steps !== 'string') return v;
            return {
                ...v,
                evidence: {
                    ...(v.evidence && typeof v.evidence === 'object' ? v.evidence : {}),
                    ai_reviewer_poc_steps: steps.trim(),
                    ai_poc_model: llmResult.modelUsed || null,
                },
            };
        });
    } catch (err) {
        console.warn('[llmAnalyzer] PoC narrative enrichment skipped:', err.message);
        return findings;
    }
}

/**
 * Get OWASP mapping for a vulnerability type.
 */
export function getOwaspMapping(vulnType) {
    return OWASP_MAP[vulnType] || { owasp: 'Unmapped', cwe: 'N/A' };
}

/**
 * Get remediation object for a vulnerability type.
 */
export function getRemediation(vulnType) {
    return REMEDIATION_MAP[vulnType] || { text: 'Review and remediate according to OWASP guidelines.', code: null };
}

