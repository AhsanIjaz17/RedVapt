/**
 * health.route.js — Health Check Endpoint
 */

import { Router } from 'express';

const router = Router();

router.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'RedVapt Recon Server is running.' });
});

export default router;
