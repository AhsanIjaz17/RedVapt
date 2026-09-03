import express from 'express';
import * as authController from './auth.controller.js';
import { rateLimit } from 'express-rate-limit';

const router = express.Router();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10, // Limit each IP to 10 requests per windowMs
    message: { error: 'Too many requests, please try again later' }
});

router.post('/register', authLimiter, authController.register);
router.post('/login', authLimiter, authController.login);
router.get('/verify', authController.verifyEmail);

export default router;
