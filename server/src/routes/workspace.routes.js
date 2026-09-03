// src/routes/workspace.routes.js
import { Router } from 'express';
import * as workspaceController from '../controllers/workspace.controller.js';
import { requireAuth, requireWorkspaceMember } from '../middleware/auth.middleware.js';

const router = Router();

router.use(requireAuth);

router.get('/my', workspaceController.getMyWorkspaces);
router.post('/create', workspaceController.createWorkspace);
router.get('/:workspace_id/stats', requireWorkspaceMember, workspaceController.getWorkspaceStats);
router.get('/:workspace_id/assets', requireWorkspaceMember, workspaceController.getWorkspaceAssets);
router.get('/:workspace_id/findings', requireWorkspaceMember, workspaceController.getWorkspaceFindings);
router.get('/:workspace_id/attack-graph', requireWorkspaceMember, workspaceController.getAttackGraph);

export default router;
