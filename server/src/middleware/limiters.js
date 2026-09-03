/**
 * middleware/limiters.js — Express Rate Limiters
 *
 * Defined here (not in app.js) to avoid circular imports:
 *   app.js → recon.route.js → app.js  ← was broken
 *   app.js → limiters.js ← recon.route.js  ← correct
 */

import rateLimit from 'express-rate-limit';
import config from '../config/env.js';

/** General API limiter — applied globally in app.js */
export const generalLimiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: config.RATE_LIMIT_GENERAL_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests — please slow down.' },
});

/** Recon limiter — heavy endpoint, very strict */
export const reconLimiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: config.RATE_LIMIT_RECON_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Recon rate limit exceeded — max scans per minute reached.' },
    // Note: no custom keyGenerator — default handles IPv4 and IPv6 correctly
});

/** Chat limiter */
export const chatLimiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: config.RATE_LIMIT_CHAT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Chat rate limit exceeded.' },
});

/** Auth limiter — for login/signup */
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again after 15 minutes' }
});

/** Demo limiter */
export const demoLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Demo booking limit reached for this hour' }
});
