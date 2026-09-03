// src/routes/recon.routes.js
import { Router } from 'express';
import * as reconController from '../modules/recon/recon.controller.js';
import { requireAuth, requireWorkspaceMember } from '../middleware/auth.middleware.js';

const router = Router();

// SSE fallback for query tokens
router.use((req, res, next) => {
    if (req.query.token && !req.headers.authorization) {
        req.headers.authorization = `Bearer ${req.query.token}`;
    }
    next();
});

router.use(requireAuth);

router.post('/workspaces/:workspace_id/scans/start', requireWorkspaceMember, (req, res) => {
    // Adapter to bridge old controller to new route params if needed
    // In actual implementation, we'd refactor the controller to use req.params.workspace_id
    reconController.startScan(req, res);
});

router.post('/workspaces/:workspace_id/scan/stop', requireWorkspaceMember, reconController.stopScan);

router.get('/workspaces/:workspace_id/scans', requireWorkspaceMember, (req, res) => {
    // Logic to list scans from Prisma Scan model
    res.json({ message: 'List scans placeholder' });
});

router.get('/workspaces/:workspace_id/scan', requireWorkspaceMember, reconController.startScan);

export default router;
