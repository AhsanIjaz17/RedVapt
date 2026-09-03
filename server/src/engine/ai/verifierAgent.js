/**
 * verifierAgent.js
 * 
 * Verifier Agent (Strong Reasoning)
 * Deep analysis of raw HTTP evidence, avoids WAF false positives, validates tool usage.
 *
 * Uses the unified LLM router (Claude Haiku first, OpenRouter fallback).
 */

import crypto from 'crypto';
import { scanMemory } from '../state/globalScanMemory.js';
import { callLLM } from '../llm/llmRouter.js';

// Robust JSON parser with Markdown stripping
export function safeParseLLMResponse(text) {
    if (!text) return null;
    let clean = text.trim();
    if (clean.startsWith('```json')) clean = clean.substring(7);
    else if (clean.startsWith('```')) clean = clean.substring(3);
    if (clean.endsWith('```')) clean = clean.substring(0, clean.length - 3);
    clean = clean.trim();
    try {
        return JSON.parse(clean);
    } catch {
        // Fallback greedy regex extraction if JSON is malformed
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            try { return JSON.parse(jsonMatch[0]); } catch { return null; }
        }
        return null;
    }
}

const verifierCache = new Map();

export async function runVerifierAgent(context) {
    const {
        endpoint = "unknown",
        baselines = [],
        injected = {},
        payload = "",
        detectedSignal = {},
        vulnCategory = "Unknown"
    } = context;

    // Build Cache Key from endpoint, payload, and signalSummary
    const _signalSummary = JSON.stringify({ diffScore: detectedSignal.diffScore, matchedKeywords: detectedSignal.matchedKeywords });
    const cacheStr = `${endpoint}-${payload}-${_signalSummary}`;
    const cacheKey = crypto.createHash('sha256').update(cacheStr).digest('hex');

    if (verifierCache.has(cacheKey)) {
        console.log(`[Verifier] Cache hit for endpoint & payload! Returning remembered verdict.`);
        return verifierCache.get(cacheKey);
    }

    const systemPrompt = `You are the RedVapt AI Verifier Agent.
Analyze the HTTP evidence deeply to determine if a vulnerability is present. Reduce false positives by detecting WAF blocks or random noise.

If XSS suspected: Only output "confirmed" if the payload execution is guaranteed strictly (e.g. alert(1) fires) or it hits a confirmed JS sink (onerror=, javascript:, <script> execution). If it only reflects as test data, it is a "false_positive" (reflected input, not exploitable).

If SQLi suspected: Output "confirmed" only if a boolean pair works consistently (AND 1=1 vs AND 1=2 differences) or an explicit DB error/timing delay occurs.

If WAF was suspected (from detectedSignal): Never output "confirmed" for SQLi/XSS unless explicit timing/boolean proof is provided.

Return strictly JSON matching:
{
    "verdict": "confirmed" | "false_positive" | "needs_tool_verification",
    "wafDetected": true | false,
    "vulnType": "SQLi" | "XSS" | "SSTI" | "None",
    "reason": "Detailed reasoning",
    "evidenceExtract": "Snippet proving it",
    "nextPayloads": []
}`;

    const userPrompt = `Input Context:
Target Vuln: ${vulnCategory}
Target Endpoint: ${endpoint}
Payload Tested: ${payload}
Signal Scorer Data: ${JSON.stringify(detectedSignal)}
Baseline Info: ${JSON.stringify(baselines)}
Injected Extract: Status ${injected.status}, Body Snippet: ${injected.bodySnippet}
GLOBAL SCAN MEMORY (Context):
${scanMemory.getSnapshot()}`;

    try {
        console.log(`[Verifier] Sending evidence to LLM router (Claude → OpenRouter fallback)...`);

        const result = await callLLM({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt }
            ],
            max_tokens: 1500,
            temperature: 0.1
        });

        if (result.success && result.output) {
            const parsed = safeParseLLMResponse(result.output);
            if (parsed) {
                console.log(`[Verifier] Verdict from ${result.modelUsed}: ${parsed.verdict}`);
                verifierCache.set(cacheKey, parsed);
                if (verifierCache.size > 1000) verifierCache.delete(verifierCache.keys().next().value);
                return parsed;
            } else {
                console.warn(`[Verifier] Model ${result.modelUsed} returned invalid JSON.`);
            }
        }
    } catch (err) {
        console.warn(`[Verifier] LLM router failed: ${err.message}`);
    }

    // Fallback if all models fail
    return {
        verdict: "needs_tool_verification",
        vulnType: vulnCategory || "UNKNOWN",
        reason: "Failed to verify. All LLM providers unavailable.",
        wafDetected: false,
        nextPayloads: [],
        evidenceExtract: "",
        confidenceScore: 0.1
    };
}
