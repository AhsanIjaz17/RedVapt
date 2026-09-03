/**
 * plannerAgent.js
 * 
 * Planner Agent (Fast)
 * Drives the breadth-first scan and dictates next actions/tools quickly.
 */

import { scanMemory } from '../state/globalScanMemory.js';
import { globalCoverage } from '../state/coverageTracker.js';
import { safeParseLLMResponse } from './verifierAgent.js';
import { callLLM } from '../llm/llmRouter.js';

function extractParamFromTarget(targetUrl) {
  if (!targetUrl) return 'q';
  try {
    const urlObj = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    const params = Array.from(urlObj.searchParams.keys());
    if (params.length > 0) return params[0];
  } catch { }

  const lower = targetUrl.toLowerCase();
  if (lower.includes('search.aspx') || lower.includes('search.jsp')) return 'query';
  if (lower.includes('login.aspx') || lower.includes('doLogin')) return 'uid';
  if (lower.includes('apply.aspx')) return 'lastname';
  if (lower.includes('comment.aspx') || lower.includes('feedback')) return 'comment';

  if (/search|query|find/.test(lower)) return 'q';
  if (/user|account|profile/.test(lower)) return 'id';
  if (/file|download|include/.test(lower)) return 'file';
  if (/redirect|return|next/.test(lower)) return 'redirect';
  return 'q';
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

export async function runPlannerAgent(contextMap) {
  const prompt = `
SYSTEM PROMPT:
You are a senior web application penetration tester with 10+ years of bug bounty experience.
You are methodical, evidence-driven, and follow the OWASP Testing Guide.
You NEVER report a vulnerability without concrete evidence.
You think in attack chains and always consider business impact.

You output ONLY valid JSON. No prose, no markdown, no explanation outside JSON.

USER PROMPT TEMPLATE:
{
  "task": "analyze_and_prioritize",
  "context": {
    "endpoints": ${JSON.stringify(contextMap || [])},
    "coverage_stats": ${JSON.stringify(globalCoverage.getCoverageStats())},
    "memory_snapshot": "${scanMemory.getSnapshot()}"
  },
  "instructions": [
    "1. Identify the 5 highest-risk endpoints for immediate testing, with justification",
    "2. For each endpoint, specify EXACT vulnerability type + parameter to test",
    "3. If auth endpoints exist, always prioritize SQLi auth bypass first",
    "4. If file parameters exist (?file=, ?path=), flag for LFI testing",
    "5. If existing findings are confirmed, suggest escalation attack chains",
    "6. If SPA/JS app detected, suggest API endpoint discovery techniques"
  ],
  "output_schema": {
    "priority_targets": [
      {
        "endpoint": "string",
        "method": "GET|POST",
        "parameter": "string",
        "vulnType": "XSS|SQLi|LFI|IDOR|SSTI|OpenRedirect|CSRF",
        "injectionLocation": "query|body|header|json_body",
        "justification": "string (1-2 sentences)",
        "riskScore": "1-10",
        "suggestedPayloads": ["string", "..."]
      }
    ],
    "attack_chains": [
      {
        "name": "string",
        "steps": ["string"],
        "requiredFindings": ["string"]
      }
    ],
    "skip_endpoints": ["string"],
    "skip_reason": "string"
  }
}`;

  try {
    const planResult = await callLLM({
      messages: [{ role: 'user', content: prompt }],
      jsonMode: true,
      temperature: 0.2
    });

    if (planResult.success && planResult.output) {
      const parsed = safeParseLLMResponse(planResult.output);
      if (parsed) {
        const validTools = ["http_request", "payload_execute", "response_diff", "none"];
        if (parsed.suggestedTool && !validTools.includes(parsed.suggestedTool)) {
          console.warn(`[Planner] Hallucinated tool ${parsed.suggestedTool} — overriding to none.`);
          parsed.suggestedTool = "none";
          parsed.nextAction = "move_to_next_endpoint";
        }
        return parsed;
      }
    }
  } catch (err) {
    console.warn(`[Planner] LLM Router failed or invalid JSON returned: ${err.message}`);
  }

  // ── Shannon Patch: Default fallback heuristics if AI planner fails ──
  console.warn(`[Planner] AI Planner exhausted or failed. Using deterministic fallback heuristic.`);
  return {
    priority_targets: (contextMap || []).slice(0, 3).map(ep => {
      const urlStr = typeof ep === 'string' ? ep : ep.url || ep.endpoint || '';
      return {
        endpoint: urlStr,
        method: "GET",
        parameter: extractParamFromTarget(urlStr),
        vulnType: /login/i.test(urlStr) ? "SQLi" : /search|feedback/i.test(urlStr) ? "XSS" : "SQLi",
        injectionLocation: urlStr.includes('?') ? "query" : "body",
        justification: "Fallback heuristic applied due to LLM failure",
        suggestedPayloads: []
      };
    }),
    attack_chains: [],
    skip_endpoints: [],
    skip_reason: "Planner degraded to heuristic mode"
  };
}
