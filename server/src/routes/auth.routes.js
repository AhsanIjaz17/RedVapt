// src/routes/auth.routes.js
import { Router } from 'express';
import passport from 'passport';
import * as authController from '../controllers/auth.controller.js';
import * as authService from '../services/auth.service.js';
import config from '../config/env.js';

const router = Router();

// Local Auth
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);

export default router;
