// src/routes/reports.routes.js
import { Router } from 'express';
import * as reportsController from '../modules/reports/reports.controller.js';
import { requireAuth, requireWorkspaceMember } from '../middleware/auth.middleware.js';
import { getEvidenceByReport, getEvidenceItem } from '../core/reports/evidenceStore.js';

const router = Router();

router.use(requireAuth);

router.get('/workspaces/:workspace_id/reports', requireWorkspaceMember, (req, res) => {
    reportsController.getReports(req, res);
});

router.get('/workspaces/:workspace_id/reports/:report_id', requireWorkspaceMember, (req, res) => {
    reportsController.getReportById(req, res);
});

router.get('/workspaces/:workspace_id/reports/:report_id/view', requireWorkspaceMember, (req, res) => {
    reportsController.viewReport(req, res);
});

router.get('/workspaces/:workspace_id/reports/:report_id/download', requireWorkspaceMember, (req, res) => {
    reportsController.downloadReport(req, res);
});

router.delete('/workspaces/:workspace_id/reports/:report_id', requireWorkspaceMember, (req, res) => {
    reportsController.deleteReport(req, res);
});

// ── Evidence Vault Routes ─────────────────────────────────────────────────────
router.get('/workspaces/:workspace_id/reports/:report_id/evidence', requireWorkspaceMember, async (req, res) => {
    try {
        const evidence = await getEvidenceByReport(req.params.report_id);
        res.json(evidence);
    } catch (err) {
        console.error('[Evidence] Fetch error:', err.message);
        res.status(500).json({ error: 'Failed to fetch evidence' });
    }
});

router.get('/workspaces/:workspace_id/evidence/:evidence_id', requireWorkspaceMember, async (req, res) => {
    try {
        const item = await getEvidenceItem(req.params.evidence_id);
        if (!item || item.workspace_id !== req.params.workspace_id) {
            return res.status(404).json({ error: 'Evidence item not found' });
        }
        res.json(item);
    } catch (err) {
        console.error('[Evidence] Item fetch error:', err.message);
        res.status(500).json({ error: 'Failed to fetch evidence item' });
    }
});

export default router;
