import { existsSync } from 'node:fs';
import { listReports, getReport, getReportHtmlPath } from '../../core/reports/reportStore.js';

export const getReports = async (req, res) => {
    try {
        const { workspace_id } = req.params;
        const reports = await listReports(workspace_id);
        res.json({ reports });
    } catch (err) {
        console.error('List reports error:', err);
        res.status(500).json({ error: 'Failed to list reports.' });
    }
};

export const getReportById = async (req, res) => {
    try {
        const report = await getReport(req.params.report_id);
        if (!report) return res.status(404).json({ error: 'Report not found.' });
        // Verify report belongs to this workspace
        if (report.workspaceId !== req.params.workspace_id) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        res.json(report);
    } catch (err) {
        console.error('Get report error:', err);
        res.status(500).json({ error: 'Failed to get report.' });
    }
};

export const downloadReport = async (req, res) => {
    try {
        const htmlPath = getReportHtmlPath(req.params.report_id);
        if (!existsSync(htmlPath)) {
            return res.status(404).json({ error: 'Report HTML not found.' });
        }
        const report = await getReport(req.params.report_id);
        const filename = `RedVapt_Report_${(report?.target || 'unknown').replaceAll(/[^a-zA-Z0-9.-]/g, '_')}_${new Date(report?.date || Date.now()).toISOString().slice(0, 10)}.html`;
        res.download(htmlPath, filename);
    } catch (err) {
        console.error('Download report error:', err);
        res.status(500).json({ error: 'Failed to download report.' });
    }
};

export const viewReport = async (req, res) => {
    try {
        const htmlPath = getReportHtmlPath(req.params.report_id);
        if (!existsSync(htmlPath)) {
            return res.status(404).json({ error: 'Report HTML not found.' });
        }
        res.sendFile(htmlPath);
    } catch (err) {
        console.error('View report error:', err);
        res.status(500).json({ error: 'Failed to view report.' });
    }
};
export const deleteReport = async (req, res) => {
    try {
        const { report_id, workspace_id } = req.params;

        // 1. Get report from filesystem to verify ownership
        const report = await getReport(report_id);
        if (!report) {
            // Check if it exists in Prisma even if not in filesystem
            const prismaReport = await import('../../utils/prisma.js').then(m => m.default.report.findUnique({
                where: { id: report_id }
            }));
            if (!prismaReport) return res.status(404).json({ error: 'Report not found.' });
            if (prismaReport.workspace_id !== workspace_id) return res.status(403).json({ error: 'Forbidden' });
        } else {
            if (report.workspaceId !== workspace_id) return res.status(403).json({ error: 'Forbidden' });
        }

        // 2. Delete from filesystem
        const fsDeleted = await import('../../core/reports/reportStore.js').then(m => m.removeReport(report_id));

        // 3. Delete from Prisma (Cascades to EvidenceItems if configured, otherwise manual)
        const prisma = await import('../../utils/prisma.js').then(m => m.default);
        
        // Manual cleanup of evidence items as schema doesn't show cascade
        await prisma.evidenceItem.deleteMany({
            where: { report_id: report_id }
        });

        const prismaDeleted = await prisma.report.delete({
            where: { id: report_id }
        }).catch(() => null);

        if (!fsDeleted && !prismaDeleted) {
            return res.status(404).json({ error: 'Report not found in any storage.' });
        }

        res.json({ success: true, message: 'Report deleted successfully.' });
    } catch (err) {
        console.error('Delete report error:', err);
        res.status(500).json({ error: 'Failed to delete report.' });
    }
};
