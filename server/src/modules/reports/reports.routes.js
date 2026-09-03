import { Router } from 'express';
import { authenticate, authorizeWorkspace } from '../../middleware/auth.middleware.js';
import * as reportsController from './reports.controller.js';

const router = Router();

router.use(authenticate);

router.get('/workspaces/:workspaceId/reports', authorizeWorkspace, reportsController.getReports);
router.get('/workspaces/:workspaceId/reports/:id', authorizeWorkspace, reportsController.getReportById);
router.get('/workspaces/:workspaceId/reports/:id/download', authorizeWorkspace, reportsController.downloadReport);
router.get('/workspaces/:workspaceId/reports/:id/view', authorizeWorkspace, reportsController.viewReport);

export default router;
