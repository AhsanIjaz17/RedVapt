import { Router } from 'express';
import { reconLimiter } from '../../middleware/limiters.js';
import { authenticate, authorizeWorkspace } from '../../middleware/auth.middleware.js';
import * as reconController from './recon.controller.js';

const router = Router();

router.get('/workspaces/:workspaceId/recon', authenticate, authorizeWorkspace, reconLimiter, reconController.startScan);

export default router;
