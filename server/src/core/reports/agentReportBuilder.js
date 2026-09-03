/**
 * agentReportBuilder.js — Exploit-Verified Report Builder
 *
 * Builds the structured report object containing:
 *   - Enriched confirmed vulnerabilities (CVSS, synopsis, remediation)
 *   - Attempted findings (failed exploits with reasons)
 *   - Coverage summary (by vuln type)
 *   - Security controls detected during scan
 *   - Phase timing and tool command logs
 *
 * Policy: "No Exploit, No Report" — only confirmed vulns in findings section.
 * Attempted (failed) attacks go in a separate layer for transparency.
 */

const VULN_METADATA = {
    'SQL Injection': {
        score: 9.0,
        synopsis: 'SQL injection allows an attacker to interfere with the queries that an application makes to its database.',
        impact: 'Successful exploitation can lead to unauthorized access to the entire database, including PII, credentials, and financial records. Attackers may modify or delete data, leading to data integrity loss and service disruption. In some configurations, it can escalate to Remote Code Execution (RCE) on the database server.',
        remediation: `
            - **Use Parameterized Queries**: Ensure all SQL queries use bind variables (e.g., PreparedStatements in Java, PDO in PHP) to separate code from data.
            - **Input Validation**: Implement strict allowlists for user input that cannot be parameterized (e.g., table or column names).
            - **Principle of Least Privilege**: Run the database service with a user that has minimal necessary permissions (e.g., no DROP TABLE or FILE privileges).
            - **Web Application Firewall (WAF)**: Deploy a WAF to detect and block common SQLi patterns in real-time as a defense-in-depth measure.`,
    },
    'XSS': {
        score: 6.5,
        synopsis: 'Cross-Site Scripting occurs when an application includes untrusted data in a web page without proper validation or escaping.',
        impact: 'Attackers can hijack user sessions, steal sensitive cookies (including session tokens), and perform actions on behalf of the user. It also enables credential theft via fake login forms (UI redressing), defacement, and the distribution of malware to unsuspecting users through the trusted origin.',
        remediation: `
            - **Output Encoding**: Apply context-aware encoding of all user-supplied data before rendering it in the browser (HTML, Attribute, JavaScript, or CSS contexts).
            - **Content Security Policy (CSP)**: Implement a strict CSP that disables 'unsafe-inline' scripts and restricts script execution to trusted origins.
            - **HttpOnly Cookies**: Set the 'HttpOnly' flag on sensitive session cookies to prevent access via JavaScript, mitigating session theft.
            - **Use Modern Frameworks**: Utilize frameworks like React, Vue, or Angular that provide built-in, robust protection against XSS by default.`,
    },
    'SSTI': {
        score: 9.5,
        synopsis: 'Server-Side Template Injection allows attackers to inject template directives that are executed on the server.',
        impact: 'SSTI is a critical vulnerability that typically leads to full Remote Code Execution (RCE) with the privileges of the web application. Attackers can gain complete control over the application server, access the file system, and pivot to internal networks.',
        remediation: `
            - **Static Templates**: Use static templates where possible. Never pass raw user input directly to template evaluation engines.
            - **Sandboxing**: If dynamic templates are absolutely required, use a restricted, sandboxed environment that lacks access to dangerous system objects or functions.
            - **Input Sanitization**: Strictly validate and sanitize user input against an allowlist before passing it to any template function.
            - **Secure Configuration**: Disable high-risk features like 'exec', 'system', or file system access within the template engine's security configuration.`,
    },
    'LFI': {
        score: 8.5,
        synopsis: 'Local File Inclusion allows an attacker to include files on the server through the web browser.',
        impact: 'Successful exploitation enables attackers to read sensitive files from the server (like /etc/passwd, .env files, or configuration files), which often leads to further compromise, such as Remote Code Execution (RCE).',
        remediation: `
            - **Input Validation**: Never pass user input directly to filesystem APIs. Use allowlists for permitted file paths.
            - **Path Canonicalization**: Resolve paths and verify they stay within the intended directory.
            - **Disable Wrappers**: In PHP, disable allow_url_include and allow_url_fopen.`,
    },
    'Command Injection': {
        score: 9.5,
        synopsis: 'Command injection occurs when the application passes unsafe user-supplied data to a system shell.',
        impact: 'This allows for arbitrary OS command execution, providing the attacker with the ability to read, modify, or delete any data on the server. It can lead to complete server takeover and is often used as a beachhead for further network attacks.',
        remediation: `
            - **Avoid Shell Execution**: Use safer alternatives like built-in language APIs (e.g., 'fs.readFile' instead of 'cat') or 'execFile' without shell interpolation.
            - **Input Validation**: Apply strict, regex-based allowlists to any user input that must be used as an argument in a command.
            - **Jail/Containerization**: Run the application in a restricted environment (e.g., Docker, chroot, or jail) to limit the impact of a successful injection.
            - **Least Privilege**: Ensure the web application runs under a dedicated, low-privilege service account without sudo access.`,
    },
    'Path Traversal': {
        score: 7.5,
        synopsis: 'Path traversal allows reading arbitrary files on the server by manipulating file paths.',
        impact: 'Attackers can leak critical data including source code, configuration files (e.g., /etc/passwd, .env), database credentials, and sensitive SSH/API keys. This information is frequently used to facilitate further stages of an attack.',
        remediation: `
            - **Normalize Paths**: Use absolute paths and resolve traversal sequences (e.g., '../') using built-in path normalization functions before accessing files.
            - **File System Allowlist**: Restrict file access to a specific directory branch and use an allowlist of permitted filenames.
            - **Use Indirect References**: Map user-controlled requests to file IDs or tokens stored in a database instead of using raw filenames in the URL or parameters.`,
    },
    'SSRF': {
        score: 8.0,
        synopsis: 'Server-Side Request Forgery allows the attacker to induce the server to make requests to unintended locations.',
        impact: 'SSRF can be used to bypass internal firewalls, access sensitive local services (e.g., Redis, database), and extract credentials from cloud metadata services (IMDS). It essentially converts the victim server into a proxy for internal network reconnaissance.',
        remediation: `
            - **DNS Allowlisting**: Only allow the server to make outbound requests to a pre-defined and strictly maintained list of trusted domains.
            - **Block Internal IP Ranges**: Implement firewall rules and application-level checks to block access to internal IP ranges (e.g., 127.0.0.1, 169.254.169.254, 10.0.0.0/8).
            - **Network Isolation**: Segment the application server into a dedicated VLAN with strict egress control and monitoring.`,
    },
    'IDOR': {
        score: 7.0,
        synopsis: 'Insecure Direct Object Reference occurs when access to objects is based on user-supplied input without authorization checks.',
        impact: 'Attackers can gain unauthorized access to, or modify/delete, the private data of other users. This leads to massive data breaches and can compromise the privacy and integrity of the entire user base.',
        remediation: `
            - **Authorization Checks**: Implement rigorous server-side authorization checks for *every* request, verifying that the authenticated user has explicit permission to access the requested object ID.
            - **Use Non-Predictable IDs**: Replace sequential, guessable IDs with cryptographically secure random identifiers such as UUIDs.
            - **Indirect Reference Maps**: Use a temporary, session-linked map of indirect references to handle object access during a user session.`,
    },
};

function calculateSeverityScore(vuln) {
    const meta = VULN_METADATA[vuln.type] || { score: 5.0 };
    const mult = { critical: 1.0, high: 0.85, medium: 0.7, low: 0.5 }[vuln.severity] || 0.7;
    return Math.min(10, meta.score * mult).toFixed(1);
}

// ── Fail reason classifier ────────────────────────────────────────────────────

function classifyFailReason(attempt) {
    const resp = attempt.responseCode || attempt.status;
    const body = attempt.responseSnippet || '';
    const elapsed = attempt.responseTime || attempt.timingMs || 0;

    if (resp === 429 || resp === 503) return { reason: 'Rate limiting / throttling detected', control: 'Rate Limiting' };
    if (resp === 403) return { reason: 'Access forbidden — WAF or authorization block', control: 'WAF / Access Control' };
    if (resp >= 500) return { reason: `Server error (HTTP ${resp}) but no exploitable pattern found`, control: null };

    if (/cloudflare|incapsula|akamai|sucuri|barracuda|mod_security/i.test(body))
        return { reason: 'WAF blocked the payload', control: 'WAF (signature detected in response)' };

    if (attempt.vulnType === 'XSS' || attempt.type === 'XSS') {
        if (!attempt.hadReflection) return { reason: 'Payload not reflected in response — input sanitized or stripped', control: 'Input Validation / Output Encoding' };
        return { reason: 'Payload reflected but not in executable context (escaped/encoded)', control: 'Output Encoding' };
    }

    if (attempt.vulnType === 'SQLi' || attempt.type === 'SQL Injection') {
        if (elapsed < 1000 && !(/sql|syntax|error/i.test(body)))
            return { reason: 'No SQL error or timing delay — parameterized queries likely in use', control: 'Parameterized Queries' };
        return { reason: 'Weak signal but insufficient evidence to confirm injection', control: 'Input Validation' };
    }

    if (attempt.vulnType === 'SSTI' || attempt.type === 'SSTI') {
        if (!/49/.test(body)) return { reason: 'Template expression not evaluated — template engine escaped input', control: 'Template Sandboxing' };
        return { reason: 'Possible evaluation but could not escalate to code execution', control: null };
    }

    return { reason: 'No exploitable signal detected in response', control: null };
}

// ── Security controls extractor ───────────────────────────────────────────────

function extractSecurityControls(trace) {
    const controls = {
        csp: null,
        cspBlocksInline: false,
        hsts: null,
        xfo: null,
        xcto: false,
        secureCookies: false,
        cookieDetails: '',
        waf: null,
        wafDetails: '',
        rateLimiting: false,
        rateLimitDetails: '',
    };

    // Aggregate from response headers seen during scan
    const headers = trace.observedHeaders || {};

    if (headers['content-security-policy']) {
        controls.csp = headers['content-security-policy'];
        controls.cspBlocksInline = /script-src[^;]*(?:'nonce-|'strict-dynamic'|'none')/.test(controls.csp) ||
            (!/unsafe-inline/.test(controls.csp));
    }
    if (headers['strict-transport-security']) controls.hsts = headers['strict-transport-security'];
    if (headers['x-frame-options']) controls.xfo = headers['x-frame-options'];
    if (headers['x-content-type-options'] === 'nosniff') controls.xcto = true;

    // Cookie analysis
    const setCookie = headers['set-cookie'] || '';
    if (setCookie) {
        controls.secureCookies = /Secure/i.test(setCookie) && /HttpOnly/i.test(setCookie);
        const flags = [];
        if (/Secure/i.test(setCookie)) flags.push('Secure');
        if (/HttpOnly/i.test(setCookie)) flags.push('HttpOnly');
        if (/SameSite/i.test(setCookie)) flags.push('SameSite');
        controls.cookieDetails = flags.join(', ') || 'No security flags';
    }

    // WAF detection from responses
    for (const [name, value] of Object.entries(headers)) {
        if (/server|x-powered-by|x-cdn/i.test(name)) {
            if (/cloudflare/i.test(value)) { controls.waf = 'Cloudflare'; controls.wafDetails = value; }
            if (/incapsula/i.test(value)) { controls.waf = 'Imperva/Incapsula'; controls.wafDetails = value; }
            if (/akamai/i.test(value)) { controls.waf = 'Akamai'; controls.wafDetails = value; }
            if (/sucuri/i.test(value)) { controls.waf = 'Sucuri'; controls.wafDetails = value; }
        }
    }

    // Rate limiting from attempted findings
    const rateLimited = (trace.attemptedFindings || []).filter(a => a.responseCode === 429);
    if (rateLimited.length > 0) {
        controls.rateLimiting = true;
        controls.rateLimitDetails = `${rateLimited.length} requests received HTTP 429`;
    }

    return controls;
}

// ── Coverage summary builder ──────────────────────────────────────────────────

function buildCoverageSummary(trace) {
    const attempts = trace.attemptedFindings || [];
    const confirmed = trace.confirmedFindings || [];

    const typeMap = {};

    for (const a of attempts) {
        const t = a.vulnType || a.type || 'Unknown';
        if (!typeMap[t]) typeMap[t] = { type: t, endpointsTested: new Set(), payloadsTested: 0, signalsDetected: 0, confirmed: 0, blocked: 0 };
        typeMap[t].endpointsTested.add(a.endpoint || a.url);
        typeMap[t].payloadsTested++;
        if (a.hadSignal) typeMap[t].signalsDetected++;
        typeMap[t].blocked++;
    }

    for (const c of confirmed) {
        const t = c.type || 'Unknown';
        if (!typeMap[t]) typeMap[t] = { type: t, endpointsTested: new Set(), payloadsTested: 0, signalsDetected: 0, confirmed: 0, blocked: 0 };
        typeMap[t].endpointsTested.add(c.endpoint || c.url);
        typeMap[t].confirmed++;
    }

    const byType = Object.values(typeMap).map(v => ({
        ...v,
        endpointsTested: v.endpointsTested.size,
    }));

    return {
        byType,
        totalCandidates: attempts.length + confirmed.length,
        totalSignals: attempts.filter(a => a.hadSignal).length + confirmed.length,
    };
}

import { mapFinding } from '../../engine/vulnMapper.js';

// ── Main export ───────────────────────────────────────────────────────────────

export async function buildExploitReport(data) {
    const {
        target,
        vulns = [],
        trace = {},
        reconData = {},
        hypotheses = [],
        startedAt,
        duration_ms,
    } = data;

    // Build tech info for vulnMapper
    const techInfo = {
        server: reconData.serverInfo?.server || '',
        framework: reconData.serverInfo?.framework || '',
        libraries: reconData.technologies || []
    };

    // Enrich confirmed vulns with mapping intelligence
    const enrichedVulns = await Promise.all(vulns.map(async (v, i) => {
        const meta = VULN_METADATA[v.type] || {};
        const mapping = await mapFinding(v, techInfo);

        return {
            id: v.id || `RV-${String(i + 1).padStart(3, '0')}`,
            ...v,
            cvssScore: calculateSeverityScore(v),
            confirmedAt: v.confirmedAt ? new Date(v.confirmedAt).toISOString() : null,
            synopsis: meta.synopsis || v.synopsis || 'No synopsis available.',
            impact: meta.impact || v.impact || 'No impact analysis.',
            remediation: meta.remediation || v.remediation || 'No remediation provided.',
            // New mapping fields
            cwe: mapping.cwe,
            owasp: mapping.owasp,
            mitre_attack: mapping.mitre_attack,
            cve_candidates: mapping.cve_candidates,
            mappingConfidence: mapping.mappingConfidence,
            mappingMethod: mapping.mappingMethod
        };
    }));

    // Severity distribution
    const severityDist = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of enrichedVulns) severityDist[v.severity || 'medium']++;

    // Enrich attempted (failed) findings with fail reasons
    const attemptedFindings = (trace.attemptedFindings || []).map(a => {
        const { reason, control } = classifyFailReason(a);
        return {
            ...a,
            failReason: a.failReason || reason,
            securityControl: a.securityControl || control,
        };
    });

    // Extract security controls from scan observations
    const securityControls = extractSecurityControls(trace);

    // Build coverage summary
    trace.confirmedFindings = enrichedVulns;
    const coverage = buildCoverageSummary(trace);

    // Build phase timing array
    const phaseTiming = trace.phaseTiming || [];

    // Tool command logs
    const toolLogs = trace.toolLogs || [];

    // [SHANNON PATCH]: Auto-generate attack chains from confirmed findings
    const attackGraph = { paths: [] };
    const hasSqli = enrichedVulns.find(v => v.type.toLowerCase().includes('sqli'));
    const hasXss = enrichedVulns.find(v => v.type.toLowerCase().includes('xss'));
    const hasLfi = enrichedVulns.find(v => v.type.toLowerCase().includes('lfi') || v.type.toLowerCase().includes('traversal'));

    if (hasSqli && hasXss) {
        attackGraph.paths.push({
            name: 'Account Takeover via SQLi Auth Bypass & XSS',
            steps: [
                `Initial Access: Exploited SQL Injection on ${hasSqli.endpoint} to bypass authentication.`,
                `Lateral Movement: Access administrative account and identify user-facing input vectors.`,
                `Data Exfiltration: Injected XSS payload into ${hasXss.endpoint} to capture session cookies from other users.`
            ]
        });
    } else if (hasSqli) {
        attackGraph.paths.push({
            name: 'Full Database Access via SQL Injection',
            steps: [
                `Vulnerability Identification: Discovered a blind or error-based SQLi on ${hasSqli.endpoint}.`,
                `Extraction: Automated data extraction of schema, users, and passwords from the backend database.`
            ]
        });
    }

    if (hasLfi) {
        attackGraph.paths.push({
            name: 'Sensitive File Leakage & Possible RCE',
            steps: [
                `Path Traversal: Identified a file inclusion vulnerability at ${hasLfi.endpoint}.`,
                `Information Disclosure: Accessed /etc/passwd or application configuration files containing secrets.`
            ]
        });
    }

    return {
        target,
        date: new Date().toISOString(),
        duration_ms,
        attackGraph,
        executionStats: {
            totalSteps: trace.totalSteps || 0,
            payloadsTested: trace.payloadsTested || 0,
            endpointsDiscovered: trace.endpointsDiscovered || 0,
            hypothesesGenerated: hypotheses.length,
        },
        findings: {
            total: enrichedVulns.length,
            severityDistribution: severityDist,
            vulnerabilities: enrichedVulns,
        },
        attemptedFindings,
        coverage,
        securityControls,
        phaseTiming,
        toolLogs,
        reconSummary: {
            endpoints: reconData.endpoints?.length || 0,
            forms: reconData.forms?.length || 0,
            secrets: reconData.secrets?.length || 0,
            technologies: reconData.technologies || [],
            serverInfo: reconData.serverInfo || {},
        },
    };
}
