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
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Load .env from the repo root (two levels up from server/src/)
const __dirname = dirname(fileURLToPath(import.meta.url));
loadDotenv({ path: resolve(__dirname, '../../../.env') });

const HOME = process.env.HOME || process.env.USERPROFILE || '';

// ── Validation ────────────────────────────────────────────────────────────────


const REQUIRED_VARS = ['DATABASE_URL'];
const missing = REQUIRED_VARS.filter(v => !process.env[v] || process.env[v].includes('your-google'));

if (missing.length > 0) {
    console.error(`\n❌ [Config] Missing or invalid environment variables: ${missing.join(', ')}`);
    console.error('   Please update your root .env file with actual credentials.\n');
}

// Warn if no LLM provider is configured
if (!process.env.ANTHROPIC_API_KEY && !process.env.OPENROUTER_API_KEY) {
    console.warn('\n⚠️  [Config] No LLM provider configured. Set ANTHROPIC_API_KEY (recommended) or OPENROUTER_API_KEY.');
    console.warn('   AI-powered analysis will be unavailable until a key is provided.\n');
}

// ── Config Object ─────────────────────────────────────────────────────────────

const env = {
    // ── Server ────────────────────────────────────────────────────────────────
    PORT: Number.parseInt(process.env.SERVER_PORT || '3001', 10),
    NODE_ENV: process.env.NODE_ENV || 'development',

    // ── CORS ──────────────────────────────────────────────────────────────────
    // Comma-separated list of allowed frontend origins.
    // Example: "http://localhost:3000,https://redvapt.yourdomain.com"
    CORS_ORIGINS: (process.env.CORS_ORIGINS || 'http://localhost:3000')
        .split(',')
        .map(o => o.trim())
        .filter(Boolean),

    // ── LLM / AI Providers ────────────────────────────────────────────────────
    // Primary: Claude 3 Haiku via Anthropic API (fast, cheap, reliable)
    // Fallback: OpenRouter free models (no cost but unreliable)
    ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY || '',
    OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY || '',
    GEMINI_API_KEY: process.env.GEMINI_API_KEY || process.env.API_KEY || '',

    // ── Redis / Queue ─────────────────────────────────────────────────────────
    REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
    QUEUE_CONCURRENCY: Number.parseInt(process.env.QUEUE_CONCURRENCY || '2', 10),
    QUEUE_JOB_TTL_MS: Number.parseInt(process.env.QUEUE_JOB_TTL_MS || String(24 * 60 * 60 * 1000), 10), // 24 h

    // ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_WINDOW_MS: Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),       // 1 min
    RATE_LIMIT_GENERAL_MAX: Number.parseInt(process.env.RATE_LIMIT_GENERAL_MAX || '100', 10),     // general API
    RATE_LIMIT_RECON_MAX: Number.parseInt(process.env.RATE_LIMIT_RECON_MAX || '50', 10),           // recon scans
    RATE_LIMIT_CHAT_MAX: Number.parseInt(process.env.RATE_LIMIT_CHAT_MAX || '30', 10),            // chat

    // ── Tool Paths ───────────────────────────────────────────────────────────
    LINKFINDER_PATH: process.env.LINKFINDER_PATH || join(HOME, 'tools/LinkFinder/linkfinder.py'),
    GO_BIN_PATH: process.env.GO_BIN_PATH || join(HOME, 'go/bin'),
    LOCAL_BIN_PATH: process.env.LOCAL_BIN_PATH || join(HOME, '.local/bin'),

    // ── Database & Auth ───────────────────────────────────────────────────────
    DATABASE_URL: process.env.DATABASE_URL || 'postgresql://postgres@localhost:5432/redvapt',
    DB_TYPE: process.env.DB_TYPE || 'postgres',
    JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET || 'dev-access-secret',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret',

    // ── Google OAuth & Frontend ───────────────────────────────────────────────
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
    GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3001/api/auth/google/callback',
    FRONTEND_URL: process.env.FRONTEND_URL || 'http://localhost:3000',

    // ── Scanner Engine Specific ───────────────────────────────────────────────
    ENABLE_BROWSER_PROOF: process.env.ENABLE_BROWSER_PROOF !== 'false', // Default true unless explicitly false
};

export default env;
