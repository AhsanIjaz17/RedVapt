/**
 * claudeClient.js — Anthropic Claude Haiku 4.5 Client for RedVapt
 *
 * Primary LLM for attack planning, signal verification, and report generation.
 * Features:
 *   - Singleton client (lazy init)
 *   - AbortController timeout (45s per request)
 *   - Exponential backoff retry (3 attempts)
 *   - Strict JSON mode with parsing
 *   - Token budget truncation
 *
 * SECURITY: API key is never logged or exposed in error messages.
 */

import Anthropic from '@anthropic-ai/sdk';

// ── Constants ─────────────────────────────────────────────────────────────────
const HAIKU_MODEL = 'claude-haiku-4-5-20251001';
const DEFAULT_MAX_TOKENS = 1500;
const REQUEST_TIMEOUT_MS = 45_000;
const MAX_RETRIES = 3;

// ── System Prompts ────────────────────────────────────────────────────────────

const SYSTEM_SECURITY = `You are a senior penetration tester and application security researcher with 10+ years of experience. You reason methodically about attack surfaces, vulnerability patterns, and exploitation chains. You are evidence-driven and never hallucinate. Your JSON is always well-formed and parseable. No markdown, no explanation outside JSON when JSON is requested.`;

const SYSTEM_REPORT = `You are a senior security consultant who writes professional penetration test reports for enterprise clients. Your writing is clear, technical, and actionable. You use precise security terminology without being unnecessarily alarming.`;

// ── Singleton Client ──────────────────────────────────────────────────────────

let _client = null;

function getClient() {
    if (!_client) {
        if (!process.env.ANTHROPIC_API_KEY) {
            throw new Error(
                "[ClaudeClient] ANTHROPIC_API_KEY is not set in .env. " +
                "Get your key at: https://console.anthropic.com/settings/keys"
            );
        }
        _client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    }
    return _client;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function isRetryable(err) {
    const status = err?.status || err?.response?.status;
    if (status === 429 || status === 529 || status >= 500) return true;
    if (err.name === 'AbortError' || err.code === 'ECONNRESET' || err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') return true;
    return false;
}

// ── Core Call Function ────────────────────────────────────────────────────────

/**
 * General purpose Claude call with retry + timeout.
 *
 * @param {string|Array} prompt - User prompt string, or full messages array
 * @param {object} [opts]
 * @param {string} [opts.system] - System prompt override
 * @param {number} [opts.maxTokens]
 * @param {number} [opts.temperature] - 0.0-1.0 (default 0.3 for security tasks)
 * @returns {Promise<string>}
 */
export async function claudeCall(prompt, opts = {}) {
    const {
        system = SYSTEM_SECURITY,
        maxTokens = DEFAULT_MAX_TOKENS,
        temperature = 0.3,
    } = opts;

    const messages = Array.isArray(prompt)
        ? prompt
        : [{ role: 'user', content: String(prompt) }];

    let lastErr = null;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        try {
            const client = getClient();
            const resp = await client.messages.create(
                {
                    model: HAIKU_MODEL,
                    max_tokens: maxTokens,
                    temperature,
                    system,
                    messages,
                },
                { signal: controller.signal }
            );

            clearTimeout(timer);

            const text = resp.content?.[0]?.text;
            if (!text) throw new Error('Empty response from Claude');

            return text;
        } catch (err) {
            clearTimeout(timer);
            lastErr = err;

            if (err.status === 401) {
                throw new Error('[ClaudeClient] Invalid ANTHROPIC_API_KEY — check console.anthropic.com');
            }

            if (isRetryable(err) && attempt < MAX_RETRIES - 1) {
                const delay = Math.pow(2, attempt) * 1000 + Math.random() * 500;
                console.warn(`[ClaudeClient] Retryable error (${err.status || err.code}). Retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms...`);
                await sleep(delay);
                continue;
            }

            throw err;
        }
    }

    throw lastErr || new Error('[ClaudeClient] All retries exhausted');
}

// ── Strict JSON Mode ──────────────────────────────────────────────────────────

/**
 * Claude call that enforces valid JSON output.
 * Appends JSON instruction to system prompt and parses result.
 *
 * @param {string|Array} prompt
 * @param {object} [opts] - Same as claudeCall opts
 * @returns {Promise<object>} - Parsed JSON object
 */
export async function claudeJSON(prompt, opts = {}) {
    const system = (opts.system || SYSTEM_SECURITY) +
        '\nReturn ONLY valid JSON. No markdown, no code fences, no extra text.';

    const text = await claudeCall(prompt, {
        ...opts,
        system,
        temperature: opts.temperature ?? 0,
    });

    // Try direct parse first
    try {
        return JSON.parse(text);
    } catch {
        // Fallback: extract JSON from markdown fences or surrounding text
        const cleaned = text
            .replace(/^```(?:json)?\s*/i, '')
            .replace(/```\s*$/i, '')
            .trim();
        try {
            return JSON.parse(cleaned);
        } catch {
            // Last resort: regex extract
            const match = text.match(/\{[\s\S]*\}/);
            if (match) {
                try { return JSON.parse(match[0]); } catch { /* fall through */ }
            }
            throw new Error(`[ClaudeClient] Invalid JSON returned by model: ${text.slice(0, 200)}`);
        }
    }
}

// ── Report Mode ───────────────────────────────────────────────────────────────

/**
 * Claude call tuned for report generation.
 * Uses higher temperature for natural prose.
 *
 * @param {string} prompt
 * @param {number} [maxTokens]
 * @returns {Promise<string>}
 */
export async function claudeReport(prompt, maxTokens = 1200) {
    return claudeCall(prompt, {
        system: SYSTEM_REPORT,
        maxTokens,
        temperature: 0.5,
    });
}

// ── Health Check ──────────────────────────────────────────────────────────────

/**
 * Lightweight connectivity check (~50 tokens).
 * Call at server startup to validate the key.
 *
 * @returns {Promise<boolean>}
 */
export async function claudePing() {
    try {
        await claudeCall('Reply with the single word: OK', {
            maxTokens: 10,
            temperature: 0,
        });
        console.log('[ClaudeClient] ✅ Claude Haiku 4.5 ready');
        return true;
    } catch (err) {
        console.error(`[ClaudeClient] ❌ Claude unavailable: ${err.message}`);
        return false;
    }
}

// ── Token Budget Helper ───────────────────────────────────────────────────────

/**
 * Rough estimate truncation to stay under token limit.
 * Rule of thumb: 1 token ≈ 4 characters.
 *
 * @param {string} text
 * @param {number} maxTokens - budget (e.g. 150_000 for 200K context)
 * @returns {string}
 */
export function truncateToTokenBudget(text, maxTokens = 150_000) {
    const maxChars = maxTokens * 4;
    if (text.length <= maxChars) return text;
    const half = Math.floor(maxChars / 2);
    return text.slice(0, half) +
        '\n\n... [truncated for context window] ...\n\n' +
        text.slice(-half);
}

/**
 * Check if Anthropic API key is configured.
 * @returns {boolean}
 */
export function isClaudeConfigured() {
    return Boolean(process.env.ANTHROPIC_API_KEY);
}

export { HAIKU_MODEL };
