import { runReconAgent } from '../../core/scanner/reconAgent.js';
import { saveReport } from '../../core/reports/reportStore.js';
import { generateReportHtml } from '../../core/reports/reportGenerator.js';
import { REPORT, SECURITY } from '../../utils/constants.js';
import { transformReconToReact } from '../../core/scanner/reconToReact.js';
import prisma from '../../utils/prisma.js';
import { getScanKey, registerScan, unregisterScan, abortScan } from './scanManager.js';
import { runAgentPipeline } from '../../core/scanner/orchestrator.js';
import { generateFinalAnalysis } from '../../core/scanner/llmAnalyzer.js';
import { buildExploitReport } from '../../core/reports/agentReportBuilder.js';

/**
 * Extract hostname from a user-provided target (for DB/display).
 * Supports bare domains, http:// and https:// URLs, and URLs with paths.
 */
function sanitizeTarget(raw) {
    const t = (raw || '').trim();
    if (!t) return '';
    try {
        // If it looks like a URL, parse it properly
        if (/^https?:\/\//i.test(t)) {
            return new URL(t).hostname.toLowerCase();
        }
    } catch { }
    // Bare domain — strip path/port
    return t.toLowerCase().replace(/\/.*$/, '').split(':')[0];
}

/**
 * Get the full target URL to pass to the recon agent.
 * Preserves protocol + path if provided, otherwise returns the bare domain.
 */
function getFullTarget(raw) {
    const t = (raw || '').trim();
    if (!t) return '';
    // Already a URL with protocol
    if (/^https?:\/\//i.test(t)) return t;
    // Bare domain — just return as-is (reconAgent will detect protocol)
    return t.toLowerCase().replace(/\/.*$/, '').split(':')[0];
}

const saveScanReport = async (data, workspaceId) => {
    return await saveReport(data, workspaceId);
};

/**
 * Persist report data to Prisma Report table so workspace pages can query it.
 * This bridges the filesystem-based reportStore with the Prisma-based workspace controller.
 */
async function persistReportToPrisma(reportId, scanId, workspaceId, reportData) {
    try {
        await prisma.report.create({
            data: {
                id: reportId,
                scan_id: scanId,
                workspace_id: workspaceId,
                report_json: reportData,
            },
        });

        // ── Save Finding Mappings ──
        if (reportData.agentVulns && reportData.agentVulns.length > 0) {
            for (const v of reportData.agentVulns) {
                if (v.cwe || v.mitre_attack || v.cve_candidates) {
                    await prisma.findingMapping.create({
                        data: {
                            finding_id: v.id || 'RV-000',
                            report_id: reportId,
                            workspace_id: workspaceId,
                            cwe_id: v.cwe?.[0]?.id || null,
                            attack_id: v.mitre_attack?.[0]?.id || null,
                            cve_id: v.cve_candidates?.[0]?.cveId || null,
                            mapping_confidence: v.mappingConfidence || 1.0,
                            mapping_method: v.mappingMethod || 'static_rules',
                            details: {
                                cwe: v.cwe,
                                owasp: v.owasp,
                                mitre_attack: v.mitre_attack,
                                cve_candidates: v.cve_candidates
                            }
                        }
                    });
                }
            }
        }
    } catch (err) {
        console.error('[Persistence] Failed to save report to Prisma:', err.message);
    }
}

/**
 * Ensure a Prisma Scan record exists for this target/workspace.
 * Returns the scan ID.
 */
async function ensurePrismaScan(target, workspaceId, userId, status = 'completed') {
    try {
        const scan = await prisma.scan.create({
            data: {
                workspace: { connect: { id: workspaceId } },
                target_url: target,
                scan_type: 'full',
                status,
                creator: { connect: { id: userId } }
            },
        });
        return scan.id;
    } catch (err) {
        console.error('[Persistence] Failed to create Prisma scan:\n', err.message);
        return null;
    }
}

const handleReconStage = async (cleanTarget, send, isClosed, fullTarget = null, controller = null) => {
    send('progress', { phase: 'recon', status: 'running', message: '🔍 Phase 1: Running full reconnaissance...' });
    // Pass fullTarget (with protocol) to recon agent if available, otherwise fallback to hostname
    const { results, analysis, reportData, scanDB } = await runReconAgent(fullTarget || cleanTarget, (progress) => {
        if (!isClosed) send('progress', progress);
    }, controller ? { signal: controller.signal } : {});

    if (results?.liveHosts === 0) {
        send('progress', {
            phase: 'recon',
            status: 'done',
            message: `🚫 **Network Failure / Target Down** — 0 live hosts detected on **${cleanTarget}**. Stopping scanner to prevent garbage testing.`,
        });
        send('done', { message: '❌ Scan aborted: Target unreachable.', reportId: null });
        return { aborted: true };
    }

    return { results, analysis, reportData, scanDB };
};

const handleExploitationStage = async (cleanTarget, agentReconData, send, isClosed, prismaScanId, controller = null) => {
    send('progress', { phase: 'agent', status: 'running', message: '🧠 Phase 2: Starting ReAct exploitation agent...' });
    try {
        const agentResult = await runAgentPipeline(cleanTarget, {
            skipRecon: true,
            reconData: agentReconData,
            maxIterations: 90,
            prismaScanId,
            signal: controller ? controller.signal : undefined
        }, (progress) => {
            if (isClosed) return;
            if (['thought', 'action', 'result', 'vuln_confirmed', 'attack_surface'].includes(progress.type)) {
                return send(progress.type, progress);
            }
            send('progress', progress);
        });

        if (isClosed) return null;

        send('agent_report', {
            vulns: agentResult.vulns,
            report: agentResult.report,
            summary: agentResult.summary,
            duration_ms: agentResult.duration_ms,
        });

        send('progress', {
            phase: 'agent',
            status: 'done',
            message: `✅ Agent completed — ${agentResult.vulns.length} vulnerabilities confirmed`,
        });
        return agentResult;
    } catch (err) {
        console.error('[Exploitation] Error:', err);
        send('progress', { phase: 'agent', status: 'done', message: `⚠️ Agent phase error: ${err.message}` });
        return null;
    }
};

export const startScan = async (req, res) => {
    const { target } = req.query;
    const workspaceId = req.params.workspaceId || req.params.workspace_id;
    const userId = req.user?.id || req.user?.userId;

    if (!target || typeof target !== 'string' || target.trim() === '') {
        return res.status(400).json({ error: 'Provide a target domain.' });
    }

    const cleanTarget = sanitizeTarget(target);
    const fullTarget = getFullTarget(target);
    if (cleanTarget.length > SECURITY.MAX_TARGET_LENGTH) {
        return res.status(400).json({ error: 'Target hostname is too long.' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const send = (event, data) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        if (res.flush) res.flush();
    };

    let isClosed = false;
    req.on('close', () => { isClosed = true; });

    const scanKey = getScanKey(workspaceId, cleanTarget);
    const controller = new AbortController();
    registerScan(scanKey, controller);
    let prismaScanId = null;

    try {
        send('start', { message: `🚀 Starting RedVapt AI Security Scanner on **${cleanTarget}**` });

        // Create Prisma Scan record early so we can attach reports to it
        prismaScanId = await ensurePrismaScan(cleanTarget, workspaceId, userId, 'running');

        // ── Stage 1: Recon ──
        const recon = await handleReconStage(cleanTarget, send, isClosed, fullTarget, controller);
        if (isClosed || recon.aborted) return;
        const { results, analysis, reportData, scanDB } = recon;

        // Save interim report to filesystem
        let reportId = null;
        try {
            const saved = await saveScanReport({
                target: cleanTarget,
                scanType: REPORT.SCAN_TYPES.RECON,
                stats: results,
                rawData: reportData,
                analysis,
                htmlReport: generateReportHtml({
                    target: cleanTarget,
                    scanType: REPORT.SCAN_TYPES.RECON,
                    date: new Date().toISOString(),
                    stats: results,
                    rawData: reportData,
                    analysis: typeof analysis === 'string' ? analysis : JSON.stringify(analysis, null, 2),
                }),
            }, workspaceId);
            reportId = saved.id;
        } catch (err) {
            send('progress', { phase: 'report', status: 'done', message: `⚠️ Report save failed: ${err.message}` });
        }

        if (isClosed) return;

        // ── Stage 2: Exploitation ──
        const agentReconData = transformReconToReact(reportData, cleanTarget);
        const agentResult = await handleExploitationStage(cleanTarget, agentReconData, send, isClosed, prismaScanId, controller);
        if (isClosed) return;

        // ── Stage 3: LLM Analysis ──
        let finalAnalysis = null;
        try {
            finalAnalysis = await generateFinalAnalysis(cleanTarget, agentReconData, {
                ...(agentResult || { vulns: [], trace: { totalSteps: 0 } }),
                testedClasses: agentResult?.testedClasses || [],
            }, () => { });
        } catch (err) {
            console.error('[Analysis] Error:', err);
        }

        if (isClosed) return;

        // ── Stage 4: Unified Report ──
        try {
            let finalAnalysisStr = null;
            if (typeof finalAnalysis === 'string') {
                finalAnalysisStr = finalAnalysis;
            } else if (finalAnalysis) {
                finalAnalysisStr = JSON.stringify(finalAnalysis, null, 2);
            }

            // ── Phase 4: Unified Report (Enriched with Intel) ──
            const enrichedData = await buildExploitReport({
                target: cleanTarget,
                vulns: agentResult?.vulns || [],
                trace: {
                    ...(agentResult?.trace || {}),
                    attemptedFindings: agentResult?.attemptedFindings || agentResult?.trace?.attemptedFindings || [],
                    evidenceDropped: agentResult?.evidenceDropped || [],
                },
                reconData: {
                    ...reportData,
                    serverInfo: agentResult?.serverInfo || {},
                    technologies: agentResult?.technologies || reportData.technologies || []
                },
                duration_ms: agentResult?.duration_ms || 0
            });

            const unifiedHtml = generateReportHtml({
                target: cleanTarget,
                scanType: REPORT.SCAN_TYPES.FULL,
                date: new Date().toISOString(),
                stats: results,
                rawData: reportData,
                analysis: typeof analysis === 'string' ? analysis : JSON.stringify(analysis, null, 2),
                agentVulns: enrichedData.findings.vulnerabilities,
                agentTrace: enrichedData.executionStats,
                finalAnalysis: finalAnalysisStr,
                attemptedFindings: enrichedData.attemptedFindings,
                securityControls: enrichedData.securityControls,
                coverageData: enrichedData.coverage,
                phaseTiming: enrichedData.phaseTiming,
                toolLogs: enrichedData.toolLogs,
            });

            const unifiedSaved = await saveScanReport({
                id: reportId,
                target: cleanTarget,
                scanType: REPORT.SCAN_TYPES.FULL,
                stats: results,
                rawData: reportData,
                analysis,
                htmlReport: unifiedHtml,
                agentVulns: enrichedData.findings.vulnerabilities,
                agentTrace: enrichedData.executionStats,
                finalAnalysis: finalAnalysis || '',
                attemptedFindings: enrichedData.attemptedFindings,
                securityControls: enrichedData.securityControls,
                coverage: enrichedData.coverage,
                phaseTiming: enrichedData.phaseTiming,
                toolLogs: enrichedData.toolLogs,
            }, workspaceId);

            reportId = unifiedSaved.id;
            send('progress', { phase: 'unified_report', status: 'done', message: '✅ Comprehensive report saved' });

            // ── Bridge: Persist report to Prisma for workspace pages ──
            if (prismaScanId) {
                // Update scan status to completed
                try {
                    await prisma.scan.update({
                        where: { id: prismaScanId },
                        data: { status: 'completed' },
                    });
                } catch (e) { /* ignore */ }

                // Create Prisma Report with full vulnerability data
                const reportJson = {
                    stats: results,
                    analysis: typeof analysis === 'string' ? analysis : JSON.stringify(analysis),
                    findings: enrichedData.findings.vulnerabilities.map(v => ({
                        title: v.type || v.name || 'Unknown',
                        type: v.type || '',
                        severity: v.severity || 'info',
                        endpoint: v.endpoint || '',
                        description: v.description || v.impact || '',
                        evidence: v.evidence || '',
                        payload: v.payload || '',
                        remediation: v.remediation || v.fix || '',
                        status: 'Open',
                        // Map intel
                        cwe: v.cwe,
                        owasp: v.owasp,
                        mitre_attack: v.mitre_attack,
                        cve_candidates: v.cve_candidates
                    })) || [],
                    agentVulns: enrichedData.findings.vulnerabilities,
                    attemptedFindings: agentResult?.attemptedFindings || [],
                    highSeverityCount: (agentResult?.vulns || []).filter(v =>
                        ['critical', 'high'].includes((v.severity || '').toLowerCase())
                    ).length,
                    mediumSeverityCount: (agentResult?.vulns || []).filter(v =>
                        (v.severity || '').toLowerCase() === 'medium'
                    ).length,
                    finalAnalysis: finalAnalysisStr,
                    securityControls: agentResult?.securityControls || {},
                    coverage: agentResult?.coverage || null,
                    phaseTiming: agentResult?.phaseTiming || [],
                };

                await persistReportToPrisma(reportId, prismaScanId, workspaceId, reportJson);
                send('progress', { phase: 'persistence', status: 'done', message: '✅ Report synced to workspace database' });
            }
        } catch (err) {
            send('progress', { phase: 'unified_report', status: 'done', message: `⚠️ Report update failed: ${err.message}` });
        }

        // ── Stage 5: Legacy Persistence (Disabled) ──
        // Prisma now fully handles persistence with UUID support.
        // Legacy system bypassed to avoid postgres syntax integer errors.

        send('done', { message: '✅ Full scan complete.', reportId });
    } catch (err) {
        if (err.name === 'AbortError' || err.message?.includes('aborted')) {
            console.log(`[Scan] Aborted by user: ${cleanTarget}`);
            if (!isClosed) send('error', { message: `🛑 Scan was forcefully stopped by user.` });
        } else {
            console.error(`[Scan] Failed:`, err.message);
            if (!isClosed) send('error', { message: `❌ Scan failed: ${err.message}` });
        }
        if (prismaScanId) {
            try {
                await prisma.scan.update({
                    where: { id: prismaScanId },
                    data: { status: 'failed' },
                });
            } catch {
                /* ignore */
            }
        }
    } finally {
        unregisterScan(scanKey);
        if (!res.writableEnded) res.end();
    }
};

export const stopScan = async (req, res) => {
    const { target } = req.query;
    const workspaceId = req.params.workspaceId || req.params.workspace_id;

    if (!target) return res.status(400).json({ error: 'Target is required to stop scan.' });

    const cleanTarget = sanitizeTarget(target);
    const scanKey = getScanKey(workspaceId, cleanTarget);

    const stopped = abortScan(scanKey);
    if (stopped) {
        return res.json({ message: `Scan for ${cleanTarget} stopped successfully.` });
    } else {
        return res.status(404).json({ error: `No active scan found for ${cleanTarget}.` });
    }
};

