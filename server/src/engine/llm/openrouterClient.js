/**
 * openrouterClient.js — OpenRouter API Client
 *
 * OpenAI-compatible client pointed at https://openrouter.ai/api/v1
 * Uses the `openai` npm package as the transport layer.
 *
 * SECURITY: API key is NEVER logged or exposed in error messages.
 * USAGE:  import { getOpenRouterClient } from '../llm/openrouterClient.js';
 */

import OpenAI from 'openai';

let _client = null;

/**
 * Returns a singleton OpenAI-compatible client configured for OpenRouter.
 * Lazy-initialised so the module can be imported even when the key is absent.
 *
 * @throws {Error} if OPENROUTER_API_KEY is not set at call time.
 */
export function getOpenRouterClient() {
    if (_client) return _client;

    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
        throw new Error('[OpenRouter] OPENROUTER_API_KEY is not set. Scanning will continue without AI analysis.');
    }

    _client = new OpenAI({
        apiKey,
        baseURL: 'https://openrouter.ai/api/v1',
        timeout: 30_000,           // 30-second hard timeout per request
        maxRetries: 0,             // retries are handled by llmRouter.js
        defaultHeaders: {
            'HTTP-Referer': 'https://redvapt.local',
            'X-Title': 'RedVapt AI Security Scanner',
        },
    });

    return _client;
}

/**
 * Low-level chat completion via OpenRouter.
 * Prefer using llmRouter.callLLM() which adds model-fallback and safer error handling.
 *
 * @param {string}   model
 * @param {Array}    messages   - OpenAI-format message array
 * @param {number}   max_tokens
 * @param {number}   temperature
 * @returns {Promise<string>}   - raw text content from the model
 */
export async function chatCompletion({ model, messages, max_tokens = 1500, temperature = 0.3 }) {
    const client = getOpenRouterClient();

    const completion = await client.chat.completions.create({
        model,
        messages,
        max_tokens,
        temperature,
    });

    return completion.choices?.[0]?.message?.content || '';
}
