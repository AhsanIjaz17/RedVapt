import express from 'express';
import * as workspaceController from './workspace.controller.js';
import { authenticate } from '../../middleware/auth.middleware.js';

const router = express.Router();

router.use(authenticate);

router.get('/my', workspaceController.getMyWorkspaces);
router.post('/create', workspaceController.createWorkspace);

export default router;
