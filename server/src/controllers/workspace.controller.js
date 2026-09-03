// src/controllers/workspace.controller.js
import * as workspaceService from '../services/workspace.service.js';
import { listReports, getReport, getWorkspaceReportStats } from '../core/reports/reportStore.js';
import { getActiveScanCountForWorkspace } from '../modules/recon/scanManager.js';

import prisma from '../utils/prisma.js';

/**
 * Filesystem fallback: reads report JSON files for a workspace
 * and extracts vulns/findings when Prisma has no Report records.
 */
async function getFilesystemFindings(workspaceId) {
    try {
        const reports = await listReports(workspaceId);
        const findings = [];
        for (const r of reports) {
            const full = await getReport(r.id);
            if (!full) continue;
            const agentVulns = full.agentVulns || [];
            for (const v of agentVulns) {
                const severity = (v.severity || 'info').toString().toUpperCase().charAt(0);
                findings.push({
                    title: v.type || v.name || 'Unknown Finding',
                    target: full.target || 'Unknown',
                    status: v.status || 'Open',
                    riskLevel: severity === 'C' ? 'C' : severity === 'H' ? 'H' : severity === 'M' ? 'M' : severity === 'L' ? 'L' : 'I',
                    description: v.description || v.impact || '',
                    evidence: v.evidence || '',
                    endpoint: v.endpoint || '',
                    remediation: v.remediation || v.fix || '',
                    payload: v.payload || '',
                    cvss: v.cvss || null,
                    scanDate: full.date,
                });
            }
        }
        return findings;
    } catch (err) {
        console.error('[Workspace] Filesystem fallback error:', err.message);
        return [];
    }
}

/** Targets that have at least one report (Prisma first, else JSON report store). */
async function collectTargetsWithReports(workspaceId) {
    const out = new Set();
    try {
        const dbReports = await prisma.report.findMany({
            where: { workspace_id: workspaceId },
            include: { scan: { select: { target_url: true } } },
        });
        for (const r of dbReports) {
            const u = r.scan?.target_url;
            if (u) out.add(String(u).trim());
        }
    } catch {
        /* noop */
    }
    if (out.size === 0) {
        try {
            const fs = await listReports(workspaceId);
            for (const x of fs || []) {
                if (x.target) out.add(String(x.target).trim());
            }
        } catch {
            /* noop */
        }
    }
    return out;
}

function countHighCriticalInReportJson(reportJson) {
    if (!reportJson || typeof reportJson !== 'object') return 0;
    const vulnList = reportJson.findings || reportJson.vulnerabilities || [];
    const agentVulns = reportJson.agentVulns || [];
    const merged = [...(Array.isArray(vulnList) ? vulnList : []), ...(Array.isArray(agentVulns) ? agentVulns : [])];
    return merged.filter((v) => ['critical', 'high'].includes(String(v.severity || '').toLowerCase())).length;
}

export const getMyWorkspaces = async (req, res) => {
    try {
        const userId = req.user.userId;
        const memberships = await workspaceService.getMyWorkspaces(userId);

        const workspaces = memberships.map(m => ({
            id: m.workspace.id,
            name: m.workspace.name,
            role: m.role
        }));

        res.json(workspaces);
    } catch (err) {
        console.error('[Workspace] Fetch error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const getWorkspaceStats = async (req, res) => {
    try {
        const { workspace_id } = req.params;

        const reportStats = await getWorkspaceReportStats(workspace_id);
        const activeScans = getActiveScanCountForWorkspace(workspace_id);

        res.json({
            runningScans: activeScans,
            waitingScans: 0,
            activeScans,
            completedScans: reportStats.totalReports,
            failedScans: 0,
            addedAssets: reportStats.targetsInScope,
            highSeverityCount: reportStats.highSeverityCount,
            totalScans: reportStats.totalReports,
            totalReports: reportStats.totalReports,
            severityBreakdown: reportStats.severityBreakdown,
            recentReports: reportStats.recentReports,
            /** @deprecated use completedScans */
            scannedAssets: reportStats.totalReports,
        });
    } catch (err) {
        console.error('[Workspace] Stats error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const createWorkspace = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { name } = req.body;

        if (!name) return res.status(400).json({ error: 'Workspace name is required' });

        const workspace = await workspaceService.createWorkspace(userId, name);
        res.status(201).json(workspace);
    } catch (err) {
        console.error('[Workspace] Create error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const getWorkspaceAssets = async (req, res) => {
    try {
        const { workspace_id } = req.params;
        const reportTargets = await collectTargetsWithReports(workspace_id);
        const scans = await prisma.scan.findMany({ where: { workspace_id }, include: { reports: true } });

        const assetsMap = {};
        const bumpRiskFromReportJson = (url, reportJson) => {
            if (!assetsMap[url]) return;
            const hi = countHighCriticalInReportJson(reportJson);
            const med =
                reportJson &&
                [...(reportJson.findings || []), ...(reportJson.vulnerabilities || []), ...(reportJson.agentVulns || [])].some(
                    (v) => String(v.severity || '').toLowerCase() === 'medium'
                );
            if (hi > 0) assetsMap[url].riskLevel = 'H';
            else if (med && assetsMap[url].riskLevel !== 'H') assetsMap[url].riskLevel = 'M';
        };

        for (const s of scans) {
            if (!reportTargets.has(s.target_url)) continue;

            if (!assetsMap[s.target_url]) {
                const domain = s.target_url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
                assetsMap[s.target_url] = {
                    target: s.target_url,
                    domain,
                    scansCount: 0,
                    riskLevel: 'L',
                };
            }
            assetsMap[s.target_url].scansCount += 1;

            for (const r of s.reports || []) {
                bumpRiskFromReportJson(s.target_url, r.report_json);
            }
        }

        for (const t of reportTargets) {
            if (assetsMap[t]) continue;
            const domain = t.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
            assetsMap[t] = { target: t, domain, scansCount: 0, riskLevel: 'L' };
        }

        try {
            const fsList = await listReports(workspace_id);
            for (const meta of fsList || []) {
                const tgt = String(meta.target || '').trim();
                if (!tgt || !reportTargets.has(tgt)) continue;
                const full = await getReport(meta.id);
                if (!full) continue;
                bumpRiskFromReportJson(tgt, {
                    findings: full.finalAnalysis?.findings,
                    vulnerabilities: full.rawData?.vulnerabilities,
                    agentVulns: full.agentVulns,
                });
            }
        } catch {
            /* noop */
        }

        const fsFindings = await getFilesystemFindings(workspace_id);
        for (const f of fsFindings) {
            if (!reportTargets.has(f.target)) continue;
            if (!assetsMap[f.target]) {
                const domain = f.target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
                assetsMap[f.target] = { target: f.target, domain, scansCount: 0, riskLevel: 'L' };
            }
            const sev = f.riskLevel;
            if (sev === 'C' || sev === 'H') assetsMap[f.target].riskLevel = 'H';
            if (sev === 'M' && assetsMap[f.target].riskLevel !== 'H') assetsMap[f.target].riskLevel = 'M';
        }

        res.json(Object.values(assetsMap));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const getWorkspaceFindings = async (req, res) => {
    try {
        const { workspace_id } = req.params;
        const reports = await prisma.report.findMany({ where: { workspace_id }, include: { scan: true } });

        let findings = [];
        for (let r of reports) {
            const vulnList = r.report_json?.findings || r.report_json?.vulnerabilities || [];
            const agentVulns = r.report_json?.agentVulns || [];
            // Merge both vulnerability sources
            const allVulns = [...(Array.isArray(vulnList) ? vulnList : []), ...(Array.isArray(agentVulns) ? agentVulns : [])];
            for (let v of allVulns) {
                const severity = (v.severity || 'info').toString().toUpperCase().charAt(0);
                findings.push({
                    title: v.title || v.name || v.type || v.category || 'Unknown Finding',
                    target: r.scan?.target_url || 'Unknown',
                    status: v.status || 'Open',
                    riskLevel: severity === 'C' ? 'C' : severity === 'H' ? 'H' : severity === 'M' ? 'M' : severity === 'L' ? 'L' : 'I',
                    description: v.description || v.impact || '',
                    evidence: v.evidence || v.proof || '',
                    endpoint: v.endpoint || v.url || v.affected_url || '',
                    remediation: v.remediation || v.fix || v.recommendation || '',
                    payload: v.payload || '',
                    cvss: v.cvss || null,
                    scanDate: r.created_at,
                });
            }
        }

        // Fallback to filesystem
        if (findings.length === 0) {
            findings = await getFilesystemFindings(workspace_id);
        }

        res.json(findings);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

/**
 * Build an attack graph from actual scan findings.
 * Returns nodes (assets, vulns, impacts) and edges (exploitation paths).
 */
export const getAttackGraph = async (req, res) => {
    try {
        const { workspace_id } = req.params;
        const reports = await prisma.report.findMany({
            where: { workspace_id },
            include: { scan: true }
        });

        const nodes = [];
        const edges = [];
        const impactMap = {};

        // Collect all unique targets
        const targets = new Set();
        const allFindings = [];

        for (const r of reports) {
            const targetUrl = r.scan?.target_url || 'unknown';
            targets.add(targetUrl);

            const vulnList = r.report_json?.findings || r.report_json?.vulnerabilities || [];
            const agentVulns = r.report_json?.agentVulns || [];
            const combined = [...(Array.isArray(vulnList) ? vulnList : []), ...(Array.isArray(agentVulns) ? agentVulns : [])];

            for (const v of combined) {
                allFindings.push({ ...v, targetUrl });
            }
        }

        // Fallback to filesystem if no Prisma reports found
        if (allFindings.length === 0) {
            const fsFindings = await getFilesystemFindings(workspace_id);
            for (const f of fsFindings) {
                targets.add(f.target);
                allFindings.push({
                    title: f.title,
                    type: f.title,
                    severity: f.riskLevel === 'H' ? 'high' : f.riskLevel === 'M' ? 'medium' : f.riskLevel === 'L' ? 'low' : 'info',
                    endpoint: f.endpoint,
                    description: f.description,
                    targetUrl: f.target,
                });
            }
        }

        // Internet entry node
        nodes.push({ id: 'internet', type: 'entry', label: 'Public Internet', severity: 'info' });

        // Target asset nodes
        for (const target of targets) {
            const nodeId = `asset:${target}`;
            nodes.push({ id: nodeId, type: 'asset', label: target, severity: 'info' });
            edges.push({ source: 'internet', target: nodeId, label: 'External Access' });
        }

        // Vulnerability nodes with exploitation chains
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        const sortedFindings = allFindings.sort((a, b) =>
            (severityOrder[(b.severity || 'info').toLowerCase()] || 0) -
            (severityOrder[(a.severity || 'info').toLowerCase()] || 0)
        );

        const vulnGroups = {};
        for (const [idx, v] of sortedFindings.entries()) {
            const vulnId = `vuln:${idx}`;
            const severity = (v.severity || 'info').toLowerCase();
            const vulnType = v.type || v.title || v.name || v.category || 'Unknown';

            nodes.push({
                id: vulnId,
                type: 'vulnerability',
                label: vulnType,
                severity,
                endpoint: v.endpoint || v.url || '',
                description: v.description || v.impact || '',
                mitigation: mitigationForFinding(v),
                ...getMitreMapping(vulnType, severity),
            });

            // Edge from asset to vulnerability
            edges.push({
                source: `asset:${v.targetUrl}`,
                target: vulnId,
                label: `Exploits: ${vulnType}`,
            });

            // Track vulnerability types for chaining
            if (!vulnGroups[severity]) vulnGroups[severity] = [];
            vulnGroups[severity].push(vulnId);

            // Map business impacts
            const impactLabel = getBusinessImpact(severity, vulnType);
            if (!impactMap[impactLabel]) {
                const impactId = `impact:${impactLabel.replace(/\s+/g, '_').toLowerCase()}`;
                impactMap[impactLabel] = impactId;
                nodes.push({ id: impactId, type: 'impact', label: impactLabel, severity });
            }
            edges.push({ source: vulnId, target: impactMap[impactLabel], label: 'Leads to' });
        }

        // Chain vulnerabilities: high/critical vulns can escalate
        const criticalVulns = [...(vulnGroups['critical'] || []), ...(vulnGroups['high'] || [])];
        for (let i = 0; i < criticalVulns.length - 1; i++) {
            edges.push({
                source: criticalVulns[i],
                target: criticalVulns[i + 1],
                label: 'Escalation Path',
            });
        }

        const { attackTree, rootDomain } = buildAttackTreePayload(allFindings, targets);

        const canonicalRoot = pickRootDomain(targets, allFindings).replace(/^www\./i, '');
        attackTree.label = canonicalRoot;
        attackTree.fullLabel = canonicalRoot;
        attackTree.subtitle = 'Domain';

        // Summary stats
        const stats = {
            totalNodes: nodes.length,
            totalEdges: edges.length,
            criticalPaths: criticalVulns.length,
            impactAreas: Object.keys(impactMap).length,
            severityBreakdown: {
                critical: allFindings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
                high: allFindings.filter(f => (f.severity || '').toLowerCase() === 'high').length,
                medium: allFindings.filter(f => (f.severity || '').toLowerCase() === 'medium').length,
                low: allFindings.filter(f => (f.severity || '').toLowerCase() === 'low').length,
                info: allFindings.filter(f => ['info', 'informational', ''].includes((f.severity || '').toLowerCase())).length,
            },
        };

        res.json({ nodes, edges, stats, attackTree, rootDomain: attackTree.label });
    } catch (err) {
        console.error('[AttackGraph] Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

function extractHostname(raw) {
    if (!raw || raw === 'unknown') return 'unknown';
    try {
        const u = /^https?:/i.test(String(raw)) ? String(raw) : `https://${raw}`;
        return new URL(u).hostname;
    } catch {
        return String(raw).replace(/^https?:\/\//i, '').split(/[/?#]/)[0] || 'unknown';
    }
}

function pickRootDomain(targetUrlSet, allFindings) {
    const set = [...(targetUrlSet || [])].filter(Boolean);
    if (set.length === 0 && allFindings.length > 0) {
        const t = new Set(allFindings.map((f) => f.targetUrl).filter(Boolean));
        set.push(...t);
    }
    if (set.length === 0) return 'Add your domain in Assets';
    const hosts = set.map(extractHostname);
    const counts = {};
    for (const h of hosts) counts[h] = (counts[h] || 0) + 1;
    let best = hosts[0];
    for (const h of hosts) {
        if ((counts[h] || 0) > (counts[best] || 0)) best = h;
    }
    return best === 'unknown' ? set[0].replace(/^https?:\/\//i, '').split(/[/?#]/)[0] : best;
}

function mitigationForFinding(v) {
    const m = v.remediation || v.fix || v.recommendation || v.mitigation;
    if (m && String(m).trim()) return String(m).trim();
    const t = `${v.type || ''} ${v.title || ''} ${v.name || ''}`.toLowerCase();
    if (/sql|sqli/.test(t)) return 'Use parameterized queries and least-privilege database accounts; add WAF rules for common SQL injection patterns.';
    if (/xss|cross-site/.test(t)) return 'Apply context-aware encoding, strict Content-Security-Policy headers, and sanitize rich text.';
    if (/csrf/.test(t)) return 'Use anti-CSRF tokens and validate Origin/Referer on state-changing requests.';
    if (/ssrf/i.test(t)) return 'Whitelist outbound hosts, block internal/metadata URLs in user-controlled fetch endpoints.';
    if (/auth|session|jwt|oauth|credential|login|bypass/.test(t)) return 'Correct authentication/session logic; add MFA where appropriate and rate-limit auth endpoints.';
    if (/idor|access control|broken access/i.test(t)) return 'Enforce per-object authorization; avoid predictable IDs without access checks.';
    if (/lfi|\bpath\b|traversal|directory/i.test(t)) return 'Restrict file paths to safe roots; sanitize filename parameters and forbid .. sequences.';
    if (/inject|command|\brce\b|remote code/i.test(t)) return 'Never pass user input to shell/OS APIs; validate input with allow-lists.';
    if (/sensitive|exposure|secret|disclosure/i.test(t)) return 'Rotate exposed secrets; remove debug data from responses; tighten access controls.';
    return 'Implement vendor patches, regression tests, and a secure SDLC for this vulnerability class.';
}

function severityOrder(s) {
    const m = { critical: 4, high: 3, medium: 2, low: 1, info: 0, informational: 0 };
    return m[String(s || '').toLowerCase()] ?? 1;
}

/** Collapse multiple findings into one attack-class bucket per target (e.g. 3× SQLi → one SQL Injection node). */
function attackClassKey(v) {
    const blob = `${v.type || ''} ${v.title || ''} ${v.name || ''} ${v.category || ''}`.toLowerCase();
    if (/default\s*password|weak\s*credential|broken\s*authentication|credential|auth\s*bypass|bypass\s*auth|password\s*issue/i.test(blob))
        return 'cls:auth-weakness';
    if (/(^|\b)sqli\b|sql\s*inj|sql\s*injection/i.test(blob)) return 'cls:sqli';
    if (/cross[-\s]?site|\bxss\b/i.test(blob)) return 'cls:xss';
    if (/\bidor\b|insecure\s*direct/i.test(blob)) return 'cls:idor';
    if (/\bssrf\b/i.test(blob)) return 'cls:ssrf';
    if (/\bcsrf\b/i.test(blob)) return 'cls:csrf';
    if (/\blfi\b|path\s*traversal|\btraversal\b|directory\s*listing/i.test(blob)) return 'cls:lfi';
    if (/\bssti\b|template\s*inj/i.test(blob)) return 'cls:ssti';
    if (/\brce\b|command\s*inj/i.test(blob)) return 'cls:rce';
    if (/jwt\b/i.test(blob)) return 'cls:jwt';
    if (/open\s*redirect/i.test(blob)) return 'cls:open-redirect';
    return `raw:${blob.replace(/\s+/g, ' ').trim().slice(0, 120)}`;
}

function displayTypeForClassKey(key, sample) {
    const map = {
        'cls:auth-weakness': 'Broken / weak authentication',
        'cls:sqli': 'SQL Injection',
        'cls:xss': 'XSS',
        'cls:idor': 'IDOR',
        'cls:ssrf': 'SSRF',
        'cls:csrf': 'CSRF',
        'cls:lfi': 'Path / LFI',
        'cls:ssti': 'SSTI',
        'cls:rce': 'RCE / Command injection',
        'cls:jwt': 'JWT weakness',
        'cls:open-redirect': 'Open redirect',
    };
    if (map[key]) return map[key];
    return sample.type || sample.title || sample.name || 'Vulnerability';
}

function dedupeFindingsByAttackClass(list) {
    if (!list?.length) return [];
    const groups = new Map();
    for (const v of list) {
        const k = attackClassKey(v);
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(v);
    }
    const out = [];
    for (const [k, g] of groups) {
        let best = g[0];
        for (const x of g) {
            if (severityOrder(x.severity) > severityOrder(best.severity)) best = x;
        }
        const merged = { ...best };
        merged._mergedCount = g.length;
        merged.type = displayTypeForClassKey(k, best);
        const eps = [...new Set(g.map((x) => x.endpoint || x.url).filter(Boolean))];
        if (eps.length) merged.endpoint = eps.join(' · ').slice(0, 1500);
        out.push(merged);
    }
    return out;
}

function trimAttackTreeLabel(text, max = 54) {
    const t = (text || '').replace(/\s+/g, ' ').trim();
    if (!t) return '(No description)';
    return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/**
 * Hierarchical attack tree for UI: Domain → optional surface hosts → vuln → impact → mitigation.
 */
function buildAttackTreePayload(allFindings, targetsSet) {
    const rootDomain = pickRootDomain(targetsSet, allFindings);
    const targetsList = [...(targetsSet || [])].filter(Boolean);
    const byTarget = {};
    for (const v of allFindings) {
        const tu = v.targetUrl || targetsList[0] || 'unknown';
        if (!byTarget[tu]) byTarget[tu] = [];
        byTarget[tu].push(v);
    }
    for (const tu of Object.keys(byTarget)) {
        byTarget[tu] = dedupeFindingsByAttackClass(byTarget[tu]);
    }

    let idx = 0;
    const makeVulnNode = (v) => {
        const vulnType = v.type || v.title || v.name || v.category || 'Vulnerability';
        const sev = (v.severity || 'medium').toString().toLowerCase();
        const impact = getBusinessImpact(sev, vulnType);
        const mit = mitigationForFinding(v);
        const idNum = idx++;
        const merged = v._mergedCount > 1 ? v._mergedCount : 0;
        return {
            id: `at-vuln-${idNum}`,
            type: 'vulnerability',
            label: trimAttackTreeLabel(vulnType, 44),
            fullLabel: vulnType,
            subtitle: merged ? `${merged}× in reports` : undefined,
            severity: sev,
            endpoint: v.endpoint || v.url || '',
            children: [
                {
                    id: `at-impact-${idNum}`,
                    type: 'impact',
                    label: trimAttackTreeLabel(impact, 52),
                    fullLabel: impact,
                    severity: sev,
                    children: [
                        {
                            id: `at-mit-${idNum}`,
                            type: 'mitigation',
                            label: trimAttackTreeLabel(mit, 76),
                            fullLabel: mit,
                            children: [],
                        },
                    ],
                },
            ],
        };
    };

    const tgtKeys = Object.keys(byTarget);
    const surfaceLayer = tgtKeys.length > 1;

    let children = [];
    if (surfaceLayer) {
        for (let t = 0; t < tgtKeys.length; t++) {
            const tu = tgtKeys[t];
            const hn = extractHostname(tu);
            children.push({
                id: `at-surf-${t}`,
                type: 'surface',
                label: trimAttackTreeLabel(hn !== 'unknown' ? hn : tu, 42),
                fullLabel: tu,
                subtitle: 'Target',
                children: (byTarget[tu] || []).map(makeVulnNode),
            });
        }
    } else if (tgtKeys.length === 1) {
        children = (byTarget[tgtKeys[0]] || []).map(makeVulnNode);
    } else {
        children = dedupeFindingsByAttackClass(allFindings).map(makeVulnNode);
    }

    if (children.length === 0) {
        children = [
            {
                id: 'at-empty-tip',
                type: 'impact',
                label: 'Run a penetration scan',
                fullLabel:
                    'No findings yet — run AI Scanner against this workspace. The tree updates with vulnerabilities and contextual mitigations.',
                severity: 'info',
                children: [
                    {
                        id: 'at-empty-mit',
                        type: 'mitigation',
                        label:
                            trimAttackTreeLabel(
                                'Ensure the target matches your Assets entry, then initiate a workspace scan.'
                            ),
                        fullLabel:
                            'Ensure the target matches your Assets entry (domain/host), run a penetration scan from the Scanner page, then refresh this diagram.',
                        children: [],
                    },
                ],
            },
        ];
    }

        const attackTree = {
        id: 'at-root',
        type: 'domain',
        label: rootDomain.replace(/^www\./i, ''),
        subtitle: 'Domain',
        severity: 'info',
        children,
    };

    return { attackTree, rootDomain };
}

/** Map severity + vuln type to business impact */
function getBusinessImpact(severity, vulnType) {
    const type = (vulnType || '').toLowerCase();
    if (type.includes('sql') || type.includes('injection')) return 'Database Compromise';
    if (type.includes('xss') || type.includes('cross-site')) return 'Session Hijacking';
    if (type.includes('rce') || type.includes('command')) return 'Remote Code Execution';
    if (type.includes('ssrf')) return 'Internal Network Access';
    if (type.includes('auth') || type.includes('bypass')) return 'Unauthorized Access';
    if (type.includes('idor') || type.includes('insecure direct')) return 'Data Exfiltration';
    if (type.includes('path') || type.includes('traversal') || type.includes('lfi')) return 'File System Access';
    if (severity === 'critical') return 'Critical Infrastructure Compromise';
    if (severity === 'high') return 'Significant Data Breach Risk';
    if (severity === 'medium') return 'Operational Disruption';
    return 'Information Disclosure';
}

/** Map vuln type to MITRE ATT&CK tactic + technique ID */
function getMitreMapping(vulnType, severity) {
    const type = (vulnType || '').toLowerCase();
    if (type.includes('sql') || type.includes('injection'))
        return { mitreTactic: 'Initial Access', mitreId: 'T1190' };
    if (type.includes('xss') || type.includes('cross-site'))
        return { mitreTactic: 'Execution', mitreId: 'T1059.007' };
    if (type.includes('rce') || type.includes('command'))
        return { mitreTactic: 'Execution', mitreId: 'T1059' };
    if (type.includes('ssti') || type.includes('template'))
        return { mitreTactic: 'Execution', mitreId: 'T1203' };
    if (type.includes('ssrf'))
        return { mitreTactic: 'Discovery', mitreId: 'T1046' };
    if (type.includes('auth') || type.includes('bypass'))
        return { mitreTactic: 'Credential Access', mitreId: 'T1110' };
    if (type.includes('idor') || type.includes('insecure direct'))
        return { mitreTactic: 'Collection', mitreId: 'T1530' };
    if (type.includes('path') || type.includes('traversal') || type.includes('lfi'))
        return { mitreTactic: 'Collection', mitreId: 'T1005' };
    if (severity === 'critical' || severity === 'high')
        return { mitreTactic: 'Impact', mitreId: 'T1499' };
    return { mitreTactic: null, mitreId: null };
}
