/**
 * engine/verifiers/verifierRouter.js — Signal → Tool Router
 *
 * Routes a detected signal to the appropriate external verifier tool.
 * Only calls tools when signal.confidence >= CONFIDENCE_THRESHOLD.
 *
 * Routing table:
 *   sqli_error | sqli_timing | sqli_boolean → sqlmapVerifier
 *   xss_reflection | xss_sink              → dalfoxVerifier
 *   ssti_eval                              → internal pipeline (no tool)
 *   lfi_file_read | lfi_partial            → internal pipeline (no tool)
 *   info_disclosure                        → internal pipeline (no tool)
 *   nuclei_scan (explicit trigger)         → nucleiVerifier
 *
 * All tool calls are SERIAL per candidate (not parallel) to avoid
 * hammering the target. Parallelism is handled at the engine level
 * across different candidates.
 */

import * as sqlmap from './sqlmapVerifier.js';
import * as dalfox from './dalfoxVerifier.js';
import * as nuclei from './nucleiVerifier.js';

// Multi-Tier Verification Triggers (R13)
const TIER_IGNORE = 0.20;
const TIER_REFINE = 0.45;
const TIER_EXTERNAL = 0.65;

/**
 * Route a signal to the appropriate verifier.
 */
export async function routeToVerifier({ url, method, param, injectIn, proofToken, signal, technologies = [], onProgress = () => { } }) {
    const { signalType, confidence } = signal || {};

    // Gate 1: Ignore junk
    if (!signal || !signalType || confidence < TIER_IGNORE) {
        return { routed: false, tool: null, result: null, skipped: true, skipReason: `confidence ${confidence?.toFixed(2)} below ignore threshold ${TIER_IGNORE}` };
    }

    // Gate 2: Low-mid confidence -> Sugggest Refinement / Wait for better payload
    if (confidence < TIER_EXTERNAL) {
        // Here we could trigger a "refiner" loop, but for now we mark it for manual/deep dive review
        return {
            routed: false,
            tool: 'refiner',
            result: { confirmed: false, message: 'Weak signal: needs refinement' },
            skipped: true,
            skipReason: `confidence ${confidence?.toFixed(2)} < external tool threshold ${TIER_EXTERNAL}`
        };
    }

    onProgress({
        phase: 'verification',
        status: 'running',
        message: `🎯 Signal: ${signalType} (conf=${confidence?.toFixed(2)}) → routing to verifier...`,
    });

    // ── SQLi → sqlmap ────────────────────────────────────────────────────────
    if (['sqli_error', 'sqli_error_weak', 'sqli_timing', 'sqli_boolean'].includes(signalType)) {
        // Extract DB type hint from signal metadata (set by signalEngine when error fingerprint matches)
        const dbType = signal?.metadata?.dbType || null;
        // Use higher level/risk for timing signals (more permissive to avoid false negatives)
        const level = signalType === 'sqli_timing' ? 4 : 3;
        const risk = signalType === 'sqli_timing' ? 2 : 2;
        const result = await sqlmap.verify({ url, method, param, injectIn, signal, dbType, level, risk, onProgress });
        return { routed: true, tool: 'sqlmap', result, skipped: false, skipReason: null };
    }

    // ── XSS → dalfox ────────────────────────────────────────────────────────
    if (['xss_reflection', 'xss_sink'].includes(signalType)) {
        const result = await dalfox.verify({ url, method, param, injectIn, proofToken, signal, onProgress });
        return { routed: true, tool: 'dalfox', result, skipped: false, skipReason: null };
    }

    // ── SSTI → internal pipeline (no dedicated tool) ─────────────────────────
    if (signalType === 'ssti_eval') {
        // SSTI is confirmed by the signalEngine itself (math eval result = 49)
        // No external tool needed — return the signal as the confirmation evidence
        onProgress({
            phase: 'verification',
            status: 'done',
            message: `🚨 SSTI: Mathematical evaluation confirmed (no tool needed) at ${url} param="${param}"`,
        });
        return {
            routed: true,
            tool: 'internal',
            result: {
                confirmed: confidence >= 0.55,
                tool: 'internal_ssti',
                evidence: signal.evidenceSnippet,
                rawOutput: `Signal confidence: ${confidence}`,
                severity: 'critical',
                metadata: { signalType, signalConfidence: confidence },
            },
            skipped: false,
            skipReason: null,
        };
    }

    // ── LFI / Path Traversal → internal pipeline (no dedicated tool) ─────────
    if (['lfi_file_read', 'lfi_partial'].includes(signalType)) {
        const confirmed = signalType === 'lfi_file_read' && confidence >= 0.55;
        onProgress({
            phase: 'verification',
            status: confirmed ? 'done' : 'running',
            message: confirmed
                ? `🚨 LFI: File read confirmed at ${url} param="${param}"`
                : `🔍 LFI: Partial signal (path error) at ${url} param="${param}" — needs deeper probing`,
        });
        return {
            routed: true,
            tool: 'internal',
            result: {
                confirmed,
                tool: 'internal_lfi',
                evidence: signal.evidenceSnippet,
                rawOutput: `Signal: ${signalType}, confidence: ${confidence}`,
                severity: confirmed ? 'high' : 'medium',
                metadata: { signalType, signalConfidence: confidence },
            },
            skipped: false,
            skipReason: null,
        };
    }

    // ── Information Disclosure → internal pipeline ───────────────────────────
    if (signalType === 'info_disclosure') {
        onProgress({
            phase: 'verification',
            status: 'done',
            message: `🚨 Info Disclosure: Sensitive data found at ${url}`,
        });
        return {
            routed: true,
            tool: 'internal',
            result: {
                confirmed: confidence >= 0.55,
                tool: 'internal_info_disclosure',
                evidence: signal.evidenceSnippet,
                rawOutput: `Signal confidence: ${confidence}`,
                severity: 'medium',
                metadata: { signalType, signalConfidence: confidence },
            },
            skipped: false,
            skipReason: null,
        };
    }

    // ── Nuclei (explicit trigger for CVE scans) ──────────────────────────────
    if (signalType === 'nuclei_scan') {
        const results = await nuclei.verify({ url, technologies, signal, onProgress });
        // Pick first confirmed result
        const confirmed = results.find(r => r.confirmed);
        return {
            routed: true,
            tool: 'nuclei',
            result: confirmed || results[0],
            skipped: false,
            skipReason: null,
        };
    }

    // Unknown signal type — skip
    return {
        routed: false,
        tool: null,
        result: null,
        skipped: true,
        skipReason: `no verifier for signalType "${signalType}"`,
    };
}

/**
 * Trigger nuclei scan for a target independently of signal detection.
 * Called by the unifiedEngine after recon when tech stack is found.
 */
export async function runNucleiScan({ url, technologies, onProgress = () => { } }) {
    if (!technologies || technologies.length === 0) return [];

    return nuclei.verify({ url, technologies, onProgress });
}
