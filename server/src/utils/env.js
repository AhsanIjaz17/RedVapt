/**
 * config/env.js — Centralised Environment Configuration
 *
 * Single source of truth for every environment variable used in the server.
 * Loads .env once at startup, validates required keys, and exports a frozen
 * config object — all other modules import from here, never touch process.env.
 *
 * Usage:
 *   import config from '../config/env.js';
 *   import { callLLM } from '../llm/llmRouter.js';
 */

import { config as loadDotenv } from 'dotenv';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

// Load .env from the repo root (two levels up from server/src/)
const __dirname = dirname(fileURLToPath(import.meta.url));
loadDotenv({ path: resolve(__dirname, '../../../.env') });

const HOME = process.env.HOME || process.env.USERPROFILE || '';

// ── Validation ────────────────────────────────────────────────────────────────


const REQUIRED_VARS = ['OPENROUTER_API_KEY'];
const missing = REQUIRED_VARS.filter(v => !process.env[v]);

if (missing.length > 0) {
    console.error(`\n❌ [Config] Missing required environment variables: ${missing.join(', ')}`);
    console.error('   Copy .env.example to .env and fill in the values.\n');
    // Warn but don't crash — allows server to start without full scan functionality
}

// ── Config Object ─────────────────────────────────────────────────────────────

const env = Object.freeze({
    // ── Server ────────────────────────────────────────────────────────────────
    PORT: parseInt(process.env.SERVER_PORT || '3001', 10),
    NODE_ENV: process.env.NODE_ENV || 'development',

    // ── CORS ──────────────────────────────────────────────────────────────────
    // Comma-separated list of allowed frontend origins.
    // Example: "http://localhost:3000,https://redvapt.yourdomain.com"
    CORS_ORIGINS: (process.env.CORS_ORIGINS || 'http://localhost:3000')
        .split(',')
        .map(o => o.trim())
        .filter(Boolean),

    // ── LLM / OpenRouter ──────────────────────────────────────────────────────
    // Runtime scanning uses OpenRouter free models only (see server/src/llm/llmRouter.js).
    // Claude Code is a developer workflow tool only — never used as a runtime API.
    OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY || '',
    GEMINI_API_KEY: process.env.GEMINI_API_KEY || process.env.API_KEY || '',

    // ── Redis / Queue ─────────────────────────────────────────────────────────
    REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
    QUEUE_CONCURRENCY: parseInt(process.env.QUEUE_CONCURRENCY || '2', 10),
    QUEUE_JOB_TTL_MS: parseInt(process.env.QUEUE_JOB_TTL_MS || String(24 * 60 * 60 * 1000), 10), // 24 h

    // ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),       // 1 min
    RATE_LIMIT_GENERAL_MAX: parseInt(process.env.RATE_LIMIT_GENERAL_MAX || '100', 10),     // general API
    RATE_LIMIT_RECON_MAX: parseInt(process.env.RATE_LIMIT_RECON_MAX || '50', 10),           // recon scans
    RATE_LIMIT_CHAT_MAX: parseInt(process.env.RATE_LIMIT_CHAT_MAX || '30', 10),            // chat

    // ── Tool Paths (overridable via .env) ─────────────────────────────────────
    LINKFINDER_PATH: process.env.LINKFINDER_PATH || join(HOME, 'tools/LinkFinder/linkfinder.py'),
    GO_BIN_PATH: process.env.GO_BIN_PATH || join(HOME, 'go/bin'),
    LOCAL_BIN_PATH: process.env.LOCAL_BIN_PATH || join(HOME, '.local/bin'),
});

export default env;
