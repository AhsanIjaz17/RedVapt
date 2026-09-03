/**
 * core/reports/reportStore.js — File-Based Report Store
 *
 * Stores reports as JSON files + HTML files in data/reports/.
 * Exports: saveReport, listReports, getReport, getReportHtmlPath
 */

import { writeFile, readFile, readdir, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = join(__dirname, '..', '..', '..', 'data', 'reports');

// Ensure reports directory exists
async function ensureDir() {
    if (!existsSync(REPORTS_DIR)) {
        await mkdir(REPORTS_DIR, { recursive: true });
    }
}

/**
 * Save a report (JSON metadata + HTML file).
 * @returns {{ id: string }} The saved report ID
 */
export async function saveReport(reportData, workspaceId) {
    await ensureDir();

    const id = reportData.id || crypto.randomUUID();
    const now = new Date().toISOString();

    const record = {
        id,
        workspaceId,
        target: reportData.target,
        scanType: reportData.scanType || 'Recon Scan',
        date: now,
        stats: reportData.stats || {},
        rawData: reportData.rawData || {},
        analysis: reportData.analysis || '',
        agentVulns: reportData.agentVulns || [],
        agentTrace: reportData.agentTrace || {},
        finalAnalysis: reportData.finalAnalysis || null,
        attemptedFindings: reportData.attemptedFindings || [],
        securityControls: reportData.securityControls || {},
        coverage: reportData.coverage || null,
        phaseTiming: reportData.phaseTiming || [],
        toolLogs: reportData.toolLogs || [],
    };

    // Save JSON metadata
    const jsonPath = join(REPORTS_DIR, `${id}.json`);
    await writeFile(jsonPath, JSON.stringify(record, null, 2), 'utf-8');

    // Save HTML report if provided
    if (reportData.htmlReport) {
        const htmlPath = join(REPORTS_DIR, `${id}.html`);
        await writeFile(htmlPath, reportData.htmlReport, 'utf-8');
    }

    return { id };
}

/** Count vulnerabilities in a stored report JSON by severity bucket. */
export function countVulnerabilitiesBySeverity(reportData) {
    const buckets = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (!reportData) return buckets;

    const vulns = Array.isArray(reportData.agentVulns) ? reportData.agentVulns : [];
    for (const v of vulns) {
        const s = String(v.severity || 'info').toLowerCase();
        if (s === 'critical') buckets.critical += 1;
        else if (s === 'high') buckets.high += 1;
        else if (s === 'medium') buckets.medium += 1;
        else if (s === 'low') buckets.low += 1;
        else buckets.info += 1;
    }
    return buckets;
}

/**
 * List all reports (summary only — no rawData or heavy fields).
 */
export async function listReports(workspaceId) {
    await ensureDir();

    const files = await readdir(REPORTS_DIR);
    const jsonFiles = files.filter(f => f.endsWith('.json')).sort().reverse();

    const reports = [];
    for (const file of jsonFiles) {
        try {
            const raw = await readFile(join(REPORTS_DIR, file), 'utf-8');
            const data = JSON.parse(raw);
            if (workspaceId && data.workspaceId !== workspaceId) continue;
            const buckets = countVulnerabilitiesBySeverity(data);
            const highSev = buckets.critical + buckets.high;
            reports.push({
                id: data.id,
                target: data.target,
                scanType: data.scanType,
                date: data.date,
                stats: data.stats || {
                    subdomains: 0,
                    liveHosts: 0,
                    services: 0,
                    endpoints: 0,
                    jsFiles: 0,
                    jsSecrets: 0,
                    parameters: 0,
                },
                highSeverityCount: highSev,
            });
        } catch {
            // Skip corrupted files
        }
    }

    return reports.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()).slice(0, 100);
}

/**
 * Workspace KPIs from on-disk reports only (same source as the Reports page).
 */
export async function getWorkspaceReportStats(workspaceId) {
    await ensureDir();
    const files = await readdir(REPORTS_DIR);
    const jsonFiles = files.filter((f) => f.endsWith('.json'));

    const reports = [];
    const targets = new Set();
    const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let highSeverityCount = 0;

    for (const file of jsonFiles) {
        try {
            const raw = await readFile(join(REPORTS_DIR, file), 'utf-8');
            const data = JSON.parse(raw);
            if (workspaceId && data.workspaceId !== workspaceId) continue;

            const buckets = countVulnerabilitiesBySeverity(data);
            severityBreakdown.critical += buckets.critical;
            severityBreakdown.high += buckets.high;
            severityBreakdown.medium += buckets.medium;
            severityBreakdown.low += buckets.low;
            severityBreakdown.info += buckets.info;
            highSeverityCount += buckets.critical + buckets.high;

            if (data.target) targets.add(String(data.target).trim());

            reports.push({
                id: data.id,
                target: data.target,
                scanType: data.scanType,
                date: data.date,
                highSeverityCount: buckets.critical + buckets.high,
                totalVulnerabilities: Object.values(buckets).reduce((a, b) => a + b, 0),
            });
        } catch {
            /* skip corrupted */
        }
    }

    reports.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

    return {
        totalReports: reports.length,
        highSeverityCount,
        targetsInScope: targets.size,
        severityBreakdown,
        recentReports: reports.slice(0, 5),
    };
}

/**
 * Get a single report by ID (full JSON data).
 */
export async function getReport(id) {
    await ensureDir();
    const jsonPath = join(REPORTS_DIR, `${id}.json`);
    if (!existsSync(jsonPath)) return null;

    try {
        const raw = await readFile(jsonPath, 'utf-8');
        return JSON.parse(raw);
    } catch {
        return null;
    }
}

/**
 * Get the absolute path to the HTML report file.
 */
export function getReportHtmlPath(id) {
    return join(REPORTS_DIR, `${id}.html`);
}

/**
 * Delete a report from the filesystem.
 * @param {string} id - The report ID
 * @returns {Promise<boolean>} - Success status
 */
export async function removeReport(id) {
    await ensureDir();
    const jsonPath = join(REPORTS_DIR, `${id}.json`);
    const htmlPath = join(REPORTS_DIR, `${id}.html`);

    let deletedAny = false;
    try {
        if (existsSync(jsonPath)) {
            const { unlink } = await import('fs/promises');
            await unlink(jsonPath);
            deletedAny = true;
        }
        if (existsSync(htmlPath)) {
            const { unlink } = await import('fs/promises');
            await unlink(htmlPath);
            deletedAny = true;
        }
    } catch (err) {
        console.error(`[ReportStore] Error deleting report ${id}:`, err.message);
    }
    return deletedAny;
}
