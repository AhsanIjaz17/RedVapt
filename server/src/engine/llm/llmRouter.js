/**
 * llmRouter.js — Unified LLM Router for RedVapt
 *
 * Single entry point for all LLM calls across the codebase.
 * Strategy:
 *   1. Try Anthropic Claude (if ANTHROPIC_API_KEY is configured)
 *   2. Fallback to OpenRouter free models (if OPENROUTER_API_KEY is configured)
 *   3. Return structured error if no provider is available
 *
 * SECURITY: API keys are never logged or exposed in error output.
 *
 * @example
 *   import { callLLM } from '../llm/llmRouter.js';
 *   const result = await callLLM({ messages, max_tokens: 1200, temperature: 0.3 });
 *   if (result.success) console.log(result.output);
 */

import { claudeCall, isClaudeConfigured } from './claudeClient.js';
import { chatCompletion } from './openrouterClient.js';
import { fetchOpenRouterFreeModels, getLastSuccessfulModel, setLastSuccessfulModel } from './openrouterRegistry.js';

// ── Preferred OpenRouter models (ordered by quality for security tasks) ──────
const PREFERRED_MODELS = [
    'meta-llama/llama-3.3-70b-instruct:free',
    'meta-llama/llama-3.1-8b-instruct:free',
    'google/gemini-2.0-flash-exp:free',
    'mistralai/mistral-7b-instruct:free',
    'qwen/qwen3-8b:free',
];

/**
 * callLLM — Unified LLM call with provider fallback.
 *
 * @param {object} opts
 * @param {Array}  opts.messages      - OpenAI-format messages [{ role, content }]
 * @param {number} [opts.max_tokens]  - Max output tokens (default: 1500)
 * @param {number} [opts.temperature] - 0.0–1.0 (default: 0.3)
 * @param {boolean}[opts.jsonMode]    - If true, appends JSON instruction to system prompt
 * @returns {Promise<{ success: boolean, output: string|null, modelUsed: string|null, error: string|null }>}
 */
export async function callLLM({ messages, max_tokens = 1500, temperature = 0.3, jsonMode = false }) {
    // ── Strategy 1: Anthropic Claude ──────────────────────────────────────────
    if (isClaudeConfigured()) {
        try {
            const result = await _callClaude(messages, max_tokens, temperature, jsonMode);
            return result;
        } catch (err) {
            console.warn(`[llmRouter] Claude failed: ${err.message}. Falling back to OpenRouter.`);
        }
    }

    // ── Strategy 2: OpenRouter free models ────────────────────────────────────
    if (process.env.OPENROUTER_API_KEY) {
        try {
            const result = await _callOpenRouter(messages, max_tokens, temperature);
            return result;
        } catch (err) {
            console.warn(`[llmRouter] OpenRouter failed: ${err.message}`);
            return { success: false, output: null, modelUsed: null, error: err.message };
        }
    }

    // ── No provider available ─────────────────────────────────────────────────
    return {
        success: false,
        output: null,
        modelUsed: null,
        error: 'No LLM provider configured. Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY in .env',
    };
}

// ── Claude adapter ──────────────────────────────────────────────────────────

async function _callClaude(messages, maxTokens, temperature, jsonMode) {
    // Extract system prompt from messages (Claude uses a separate system param)
    let systemPrompt = '';
    const userMessages = [];

    for (const msg of messages) {
        if (msg.role === 'system') {
            systemPrompt += (systemPrompt ? '\n' : '') + msg.content;
        } else {
            userMessages.push(msg);
        }
    }

    if (jsonMode) {
        systemPrompt += '\nReturn ONLY valid JSON. No markdown, no code fences, no extra text.';
    }

    // claudeCall expects a messages array or string, and opts
    const text = await claudeCall(userMessages.length > 0 ? userMessages : messages, {
        system: systemPrompt || undefined,
        maxTokens,
        temperature,
    });

    return {
        success: true,
        output: text,
        modelUsed: 'claude-haiku-4-5-20251001',
        error: null,
    };
}

// ── OpenRouter adapter ──────────────────────────────────────────────────────

async function _callOpenRouter(messages, maxTokens, temperature) {
    // Try last successful model first, then preferred models, then live free models
    const modelsToTry = [];

    const lastSuccess = getLastSuccessfulModel();
    if (lastSuccess) modelsToTry.push(lastSuccess);

    modelsToTry.push(...PREFERRED_MODELS);

    // Fetch live free models as ultimate fallback
    try {
        const liveModels = await fetchOpenRouterFreeModels();
        for (const m of liveModels) {
            if (!modelsToTry.includes(m)) modelsToTry.push(m);
        }
    } catch { /* use existing list */ }

    // Deduplicate
    const uniqueModels = [...new Set(modelsToTry)];

    let lastErr = null;
    for (const model of uniqueModels.slice(0, 5)) {
        try {
            const text = await chatCompletion({ model, messages, max_tokens: maxTokens, temperature });
            if (text) {
                setLastSuccessfulModel(model);
                return { success: true, output: text, modelUsed: model, error: null };
            }
        } catch (err) {
            lastErr = err;
            console.warn(`[llmRouter] OpenRouter model ${model} failed: ${err.message}`);
        }
    }

    throw lastErr || new Error('All OpenRouter models failed');
}
