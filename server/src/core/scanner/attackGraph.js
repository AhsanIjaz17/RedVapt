/**
 * attackGraph.js — Attack Graph Builder
 *
 * Phase 6 of the autonomous pentest pipeline.
 * Builds formal Asset → Vulnerability → Exploit → Impact chains
 * from confirmed ReCct agent results + recon findings.
 *
 * Two types of paths:
 *   - confirmedPaths: Built from proven exploits (always shown)
 *   - riskPaths:     Built from recon findings without exploitation (shown as potential)
 *
 * Architecture:
 *   Recon → Crawl → Asset Intel → Specialists → ReAct → [Attack Graph] → Report
 */

import { OWASP_MAP } from './llmAnalyzer.js';

// ── Impact Templates by Vuln Type ─────────────────────────────────────────────

const IMPACT_MAP = {
    'SQL Injection': 'Database contents accessible — credentials, PII, session tokens at risk',
    'NoSQL Injection': 'Database query bypass — unauthorized data access or authentication skip',
    'Command Injection': 'Remote Code Execution — full server compromise possible',
    'XSS': 'Victim browser hijack — session theft, phishing, keylogging',
    'SSRF': 'Internal network access — cloud metadata, internal services reachable',
    'Authentication Bypass': "Any user's account accessible without credentials",
    'IDOR': 'All user records accessible — PII, financial data, or account actions',
    'Path Traversal': 'Arbitrary file read — source code, credentials, system files accessible',
    'Sensitive Data Exposure': 'Credentials or API keys exposed — direct account/service takeover',
    'Open Redirect': 'Phishing vector — victims redirected to attacker-controlled domains',
    'Header Injection': 'Response splitting, cache poisoning, or reflected injection',
    'Security Misconfiguration': 'Information disclosure, unauthorized access, or service enumeration',
};

// ── Escalation Paths (chain steps after initial exploit) ─────────────────────

const ESCALATION_MAP = {
    'SQL Injection': [
        'Extract username/password table via UNION-based injection',
        'Crack hashed passwords (MD5/SHA1 trivially crackable)',
        'Log in as admin, pivot to full application access',
    ],
    'Command Injection': [
        'Read /etc/passwd, SSH keys, .env files',
        'Establish reverse shell for persistent access',
        'Pivot to internal network via compromised server',
    ],
    'Authentication Bypass': [
        'Access all authenticated functionality as arbitrary user',
        'Modify or delete other users\' data',
        'Escalate to admin if role check is also flawed',
    ],
    'IDOR': [
        'Enumerate all user IDs to extract full user database',
        'Access admin/privileged records if ID range includes them',
        'Modify records (if endpoint supports PUT/DELETE)',
    ],
    'SSRF': [
        'Access cloud metadata endpoint (169.254.169.254)',
        'Retrieve IAM credentials for cloud account takeover',
        'Scan and attack internal services not exposed publicly',
    ],
    'Path Traversal': [
        'Read application source code and hardcoded secrets',
        'Access /etc/shadow for local user credential cracking',
        'Read database config files for direct DB access',
    ],
};

// ── Graph Building ─────────────────────────────────────────────────────────────

/**
 * Build a confirmed attack path from a proved vulnerability.
 */
function buildConfirmedPath(vuln, index) {
    const owasp = OWASP_MAP[vuln.type] || {};
    const impact = IMPACT_MAP[vuln.type] || (vuln.impact || 'Impact under investigation');
    const escalation = ESCALATION_MAP[vuln.type] || [];

    // Determine entry point description
    const entryPoint = vuln.endpoint
        ? `${vuln.endpoint} (${vuln.paramName ? `param: ${vuln.paramName}` : 'direct endpoint'})`
        : 'Discovered endpoint';

    const chain = [
        entryPoint,
        `${vuln.type} confirmed${vuln.payload ? ` — payload: \`${vuln.payload.slice(0, 60)}\`` : ''}`,
        impact,
    ];

    // Add escalation steps if available
    if (escalation.length > 0) {
        chain.push(`Escalation: ${escalation[0]}`);
    }

    // Build nodes and edges for graph visualization
    const nodes = [
        { id: `p${index}-n1`, type: 'asset', label: entryPoint, color: '#818cf8' },
        { id: `p${index}-n2`, type: 'vuln', label: `${vuln.type} [${(vuln.severity || 'medium').toUpperCase()}]`, color: vuln.severity === 'critical' ? '#dc2626' : vuln.severity === 'high' ? '#f97316' : '#eab308' },
        { id: `p${index}-n3`, type: 'exploit', label: vuln.payload ? `Payload: ${vuln.payload.slice(0, 50)}` : 'Exploit confirmed', color: '#ef4444' },
        { id: `p${index}-n4`, type: 'impact', label: impact, color: '#f87171' },
    ];

    const edges = [
        { from: `p${index}-n1`, to: `p${index}-n2`, label: 'vulnerable' },
        { from: `p${index}-n2`, to: `p${index}-n3`, label: 'exploited via' },
        { from: `p${index}-n3`, to: `p${index}-n4`, label: 'leads to' },
    ];

    return {
        id: `confirmed-${index + 1}`,
        title: `${vuln.type} → ${impact.split('—')[0].trim()}`,
        type: 'confirmed',
        severity: vuln.severity || 'medium',
        cvss: vuln.cvss || calcBaseCvss(vuln.type, vuln.severity),
        owasp: owasp.owasp || 'Unmapped',
        cwe: owasp.cwe || 'N/A',
        chain,
        escalationSteps: escalation,
        nodes,
        edges,
        evidence: vuln.evidence || null,
        endpoint: vuln.endpoint || null,
        payload: vuln.payload || null,
    };
}

/**
 * Build a risk path from recon findings (no confirmed exploit).
 * These show potential attack chains based on the attack surface.
 */
function buildRiskPath(finding, index) {
    return {
        id: `risk-${index + 1}`,
        title: finding.title,
        type: 'risk',
        likelihood: finding.likelihood || 'Medium',
        chain: finding.chain,
        reasoning: finding.reasoning,
        recommendation: finding.recommendation,
    };
}

/**
 * Generate risk paths from recon data (without confirmed exploits).
 */
function generateRiskPaths(reconData, assetIntel) {
    const riskPaths = [];
    const secrets = reconData.secrets || [];
    const services = reconData.services || [];
    const parameters = reconData.parameters || [];
    const forms = reconData.forms || [];
    const technologies = reconData.technologies || [];
    const highPriority = assetIntel?.highPriority || [];

    // Secret exposure risk paths
    for (const secret of secrets.slice(0, 2)) {
        riskPaths.push({
            title: `${secret.type || 'API Key'} Exposed → Service Abuse`,
            likelihood: 'High',
            chain: [
                `${secret.js_url?.split('/').pop() || 'JavaScript file'} publicly accessible`,
                `${secret.type || 'Credential'} found hardcoded in client-side code`,
                `Attacker extracts key from browser developer tools`,
                `Direct API access to ${secret.type?.includes('AWS') ? 'cloud resources' : secret.type?.includes('stripe') ? 'payment processor' : 'third-party service'} — billing abuse or data theft`,
            ],
            reasoning: 'Hardcoded credentials in public JS files are trivially extractable with no authentication required.',
            recommendation: `Rotate ${secret.type || 'this credential'} immediately. Move to server-side proxy pattern.`,
        });
    }

    // Admin panel risk paths
    const adminTargets = highPriority.filter(t => t.tags?.includes('admin-panel'));
    if (adminTargets.length > 0) {
        riskPaths.push({
            title: 'Admin Panel Exposed → Brute Force Risk',
            likelihood: 'Medium',
            chain: [
                `${adminTargets[0].url} discovered (score: ${adminTargets[0].score})`,
                'Admin panel accessible without IP restriction or MFA',
                'Brute-force or credential stuffing attack on login form',
                'Full administrative access — data theft, code execution, backdoor placement',
            ],
            reasoning: 'Publicly accessible admin panels are high-value targets for automated credential attacks.',
            recommendation: 'Restrict admin access to VPN/IP allowlist. Enforce MFA. Add rate limiting.',
        });
    }

    // Parameterized URL risk paths
    const paramTargets = highPriority.filter(t => t.tags?.includes('idor-candidate') || t.tags?.includes('sqli-candidate'));
    if (paramTargets.length > 0) {
        const top = paramTargets[0];
        riskPaths.push({
            title: `Parameterized Endpoint → Injection Risk`,
            likelihood: 'Medium',
            chain: [
                `${top.url} — parameterized endpoint discovered`,
                `Parameter(s) accepted: ${top.tags.join(', ')}`,
                'Input not validated — fuzzing with SQLi/IDOR payloads pending',
                'Potential data extraction or privilege escalation',
            ],
            reasoning: `Parameterized URLs are primary injection targets. This endpoint scored ${top.score}/100 in asset intelligence.`,
            recommendation: 'Manual testing recommended. Implement parameterized queries and input validation.',
        });
    }

    // Old service exposure risk
    for (const svc of services.slice(0, 1)) {
        if (svc.port && ![80, 443, 8080, 8443].includes(Number(svc.port))) {
            riskPaths.push({
                title: `Non-standard Port ${svc.port} → ${svc.service || 'Unknown Service'} Exposure`,
                likelihood: 'Low',
                chain: [
                    `Port ${svc.port} open on ${svc.host || 'target'}`,
                    `${svc.service || 'Service'} ${svc.version ? `(${svc.version})` : ''} running without TLS`,
                    'Service may have known CVEs or weak authentication',
                    'Unauthorized access to internal service',
                ],
                reasoning: 'Non-standard ports hosting services without TLS expand the network attack surface.',
                recommendation: `Restrict port ${svc.port} access. Apply firewall rules. Ensure all services are up to date.`,
            });
        }
    }

    return riskPaths.slice(0, 5); // Cap at 5 risk paths
}

/**
 * Build the full attack graph from agent results + recon.
 */
export function buildAttackGraph(vulns = [], reconData = {}, assetIntel = null) {
    const confirmedPaths = vulns.map((v, i) => buildConfirmedPath(v, i));

    const riskFindings = generateRiskPaths(reconData, assetIntel);
    const riskPaths = riskFindings.map((f, i) => buildRiskPath(f, i));

    // Overall graph statistics
    const criticalPaths = confirmedPaths.filter(p => p.severity === 'critical');
    const highPaths = confirmedPaths.filter(p => p.severity === 'high');

    const graphSummary = {
        totalPaths: confirmedPaths.length + riskPaths.length,
        confirmedCount: confirmedPaths.length,
        riskCount: riskPaths.length,
        criticalChains: criticalPaths.length,
        highChains: highPaths.length,
        escalationAvailable: confirmedPaths.filter(p => p.escalationSteps.length > 0).length,
    };

    console.log(`[AttackGraph] Built ${confirmedPaths.length} confirmed paths, ${riskPaths.length} risk paths`);

    return {
        confirmedPaths,
        riskPaths,
        summary: graphSummary,
    };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function calcBaseCvss(type, severity) {
    const base = {
        'SQL Injection': 9.0, 'Command Injection': 9.5, 'Authentication Bypass': 8.5,
        'Path Traversal': 7.5, 'SSRF': 8.0, 'XSS': 6.5, 'IDOR': 7.0,
        'Sensitive Data Exposure': 6.0, 'NoSQL Injection': 8.5, 'Open Redirect': 5.5,
    };
    const mult = { critical: 1.0, high: 0.85, medium: 0.7, low: 0.5 };
    return ((base[type] || 5.0) * (mult[severity] || 0.7)).toFixed(1);
}
