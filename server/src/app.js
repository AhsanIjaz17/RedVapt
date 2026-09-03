/**
 * app.js — Express Application Setup
 *
 * Registers middleware (security, CORS, rate-limiting) and mounts route handlers.
 * This module only configures the app — HTTP server is started in server.js.
 *
 * Security layers (in order):
 *   1. helmet        — 15 security response headers (XSS, clickjacking, MIME, etc.)
 *   2. cors          — strict origin allow-list from config
 *   3. rate-limit    — three tiers: general / recon (heavy) / chat
 *   4. body-limit    — 1 MB JSON cap to prevent payload attacks
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import passport from './config/passport.js';

import config from './config/env.js';
import { SECURITY } from './utils/constants.js';
import { generalLimiter, authLimiter, demoLimiter } from './middleware/limiters.js';

// Route Imports
import authRoutes from './routes/auth.routes.js';
import workspaceRoutes from './routes/workspace.routes.js';
import demoRoutes from './routes/demo.routes.js';
import reconRoutes from './routes/recon.routes.js';
import reportsRoutes from './routes/reports.routes.js';
import chatRoutes from './modules/chat/chat.routes.js';
import healthRoutes from './modules/health/health.routes.js';

const app = express();

// Request logger
app.use((req, res, next) => {
    console.log(`[App] ${req.method} ${req.url} - ${req.ip} - Origin: ${req.headers.origin}`);
    next();
});

// ── 1. Security Headers (helmet) ───────────────────────────────────────────
app.use(helmet({
    // Allow SSE streams (no content-length, keep-alive)
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
}));

// ── 2. CORS — strict origin allow-list ────────────────────────────────────
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (curl, Postman, same-origin)
        if (!origin) return callback(null, true);
        if (config.CORS_ORIGINS.includes(origin)) return callback(null, true);
        callback(new Error(`CORS: origin "${origin}" is not allowed`));
    },
    credentials: true
}));

// Rate Limiting (configured in middleware/limiters.js)

app.use('/api/auth', authLimiter);
app.use('/api/demo', demoLimiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── Routes ─────────────────────────────────────────────────────────────────
app.use(express.static('public'));
app.use('/api/evidence', express.static('data/evidence'));

// Initialize Passport
app.use(passport.initialize());

// API Routes
app.use('/api/health', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/workspaces', workspaceRoutes);
app.use('/api/demo', demoRoutes);
app.use('/api/recon', reconRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/chat', chatRoutes);

// ── Global Error Handler ───────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    // CORS errors
    if (err.message?.startsWith('CORS:')) {
        return res.status(403).json({ error: err.message });
    }
    console.error('[App] Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

export default app;
