/**
 * evidenceStore.js — Professional Evidence Storage System
 *
 * Persists exploit evidence per finding:
 *   - Raw HTTP request / response
 *   - Screenshots (headless browser, base64)
 *   - DOM proof / extracted tokens
 *   - HAR file data
 *   - Timeline logs
 *   - Proof-of-Concept reproduction steps
 */

import prisma from '../../utils/prisma.js';

/**
 * Save evidence for a specific finding in a report.
 */
export async function saveEvidence(reportId, workspaceId, findingIndex, data) {
    return prisma.evidenceItem.create({
        data: {
            report_id: reportId,
            workspace_id: workspaceId,
            finding_index: findingIndex,
            raw_request: data.rawRequest || null,
            raw_response: data.rawResponse || null,
            screenshot_b64: data.screenshot || null,
            dom_proof: data.domProof || null,
            extracted_tokens: data.extractedTokens || null,
            har_data: data.harData || null,
            timeline_logs: data.timelineLogs || null,
            poc_steps: data.pocSteps || null,
        },
    });
}

/**
 * Save evidence for all findings in a report at once.
 */
export async function saveAllEvidence(reportId, workspaceId, evidenceArray) {
    if (!Array.isArray(evidenceArray) || evidenceArray.length === 0) return [];

    const creates = evidenceArray.map((data, idx) =>
        saveEvidence(reportId, workspaceId, data.findingIndex ?? idx, data)
    );
    return Promise.all(creates);
}

/**
 * Get all evidence items for a report.
 */
export async function getEvidenceByReport(reportId) {
    return prisma.evidenceItem.findMany({
        where: { report_id: reportId },
        orderBy: { finding_index: 'asc' },
    });
}

/**
 * Get a single evidence item by ID.
 */
export async function getEvidenceItem(evidenceId) {
    return prisma.evidenceItem.findUnique({
        where: { id: evidenceId },
    });
}

/**
 * Get all evidence for a workspace (for dashboard stats).
 */
export async function getWorkspaceEvidenceCount(workspaceId) {
    return prisma.evidenceItem.count({
        where: { workspace_id: workspaceId },
    });
}
