/**
 * orchestrator.js — Unified Scan Orchestrator
 *
 * Coordinates the transition from reconnaissance to exploitation.
 * Drives the ReAct agent and the Unified Vulnerability Engine.
 */

import { runUnifiedScan } from '../../engine/vuln/unifiedEngine.js';
import { runReactLoop } from './reactAgent.js';
import { generateFinalAnalysis, enrichConfirmedFindingsWithReviewerPoC } from './llmAnalyzer.js';
import { filterFindingsByEvidencePolicy } from '../reports/findingEvidenceGate.js';

/** Merge engine signals + confirmed findings into ReAct hypotheses without duplicates. */
function buildHypothesisQueue(engineResult) {
    const normalized = Array.isArray(engineResult)
        ? { findings: [], attemptedFindings: [], observedHeaders: {} }
        : engineResult;

    const fromSignals = (normalized.attemptedFindings || [])
        .filter(a => a.hadSignal && (a.confidence || 0) > 0.12)
        .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
        .slice(0, 45)
        .map(a => ({
            type: a.vulnType || 'XSS',
            endpoint: a.endpoint || a.url,
            paramName: a.param || 'q',
            confidence: (a.confidence || 0) > 0.45 ? 'high' : 'medium',
            reason: `Unified engine signal: ${a.signalType || 'unknown'} (conf=${(a.confidence || 0).toFixed(2)})`,
            payloads: a.payload ? [a.payload] : [],
        }));

    const fromConfirmed = (normalized.findings || []).map(f => ({
        type: f.type,
        endpoint: f.endpoint,
        paramName: f.param,
        confidence: typeof f.confidence === 'string'
            ? (f.confidence.toLowerCase().includes('high') ? 'high' : 'medium')
            : (f.confidence > 0.7 ? 'high' : 'medium'),
        reason: `Signal detected by unified engine (type: ${f.signalType || 'reflection'})`,
        payloads: f.payload ? [f.payload] : [],
    }));

    const seen = new Set();
    const out = [];
    for (const h of [...fromSignals, ...fromConfirmed]) {
        if (!h.endpoint) continue;
        const key = `${h.endpoint}::${h.paramName || ''}::${(h.type || '').toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(h);
    }
    return out;
}

/**
 * Main entry point for the exploitation pipeline.
 * 
 * @param {string} target - The target hostname or base URL.
 * @param {object} options - Configuration options (skipRecon, reconData, etc.)
 * @param {function} onProgress - Progress callback for SSE updates.
 */
export async function runAgentPipeline(target, options = {}, onProgress = () => { }) {
    const { 
        skipRecon = false, 
        reconData, 
        maxIterations = 90, 
        prismaScanId, 
        signal,
        attackPlan 
    } = options;
    
    const startTime = Date.now();
    let currentReconData = reconData;

    // 1. If we don't have recon data, the controller should have provided it.
    // In Stage 2, reconData is mandatory if skipRecon is true.
    if (skipRecon && !currentReconData) {
        console.warn('[Orchestrator] Warning: skipRecon is true but no reconData provided.');
    }

    // 2. Unified Engine Scan (Signals & Baseline)
    // This phase runs deterministic probes to find low-hanging fruit and signals.
    onProgress({ 
        phase: 'vuln_scan', 
        status: 'running', 
        message: '🔫 Phase 3: Running Unified Vulnerability Engine (Signal Triage)...' 
    });

    const engineResult = await runUnifiedScan({
        target,
        endpoints: currentReconData?.endpoints || [],
        forms: currentReconData?.forms || [],
        technologies: currentReconData?.technologies || [],
        onProgress,
        signal
    });

    // 3. ReAct Agent Deep Dive
    // Escalates confirmed signals and high-value endpoints to the reasoning loop.
    onProgress({ 
        phase: 'react', 
        status: 'running', 
        message: '🧠 Phase 4: Escalating signals to ReAct Agent Reasoning Loop...' 
    });

    const hypothesisQueue = buildHypothesisQueue(engineResult);

    const reactResult = await runReactLoop(target, {
        reconData: currentReconData,
        hypothesisQueue,
        maxIterations,
        attackPlan,
        signal
    }, onProgress);

    // 4. Final LLM Analysis
    onProgress({ 
        phase: 'final_analysis', 
        status: 'running', 
        message: '📝 Phase 5: Generating final security analysis...' 
    });

    const reactResultForAnalysis = { ...reactResult };
    const mergedRaw = (() => {
        const normalize = (url) => {
            if (!url) return '';
            try {
                const u = new URL(url);
                let path = u.pathname;
                path = path.replace(/\d+/g, 'ID');
                path = path.replace(/%3C.*$/i, '');
                path = path.replace(/['";].*$/, '');
                if (path.endsWith('/')) path = path.slice(0, -1);
                return `${u.origin}${path}`;
            } catch { return url; }
        };

        const merged = [...(reactResult.findings || [])];
        const eng = Array.isArray(engineResult) ? { findings: [] } : engineResult;
        if (eng.findings) {
            for (const f of eng.findings) {
                const normF = normalize(f.endpoint);
                const isDuplicate = merged.some(v =>
                    normalize(v.endpoint) === normF &&
                    v.type.toLowerCase() === f.type.toLowerCase() &&
                    (v.param === f.param || (!v.param && !f.param))
                );
                if (!isDuplicate) {
                    if (!f.id) {
                        const timestamp = Math.floor(Date.now() / 1000).toString(16);
                        f.id = `RVPT-${new Date().getFullYear()}-${timestamp.slice(-4)}${Math.floor(Math.random() * 0xFFFF).toString(16).padStart(4, '0')}`.toUpperCase();
                    }
                    merged.push(f);
                }
            }
        }
        return merged;
    })();

    const { passed: evidencePassed, dropped: evidenceDropped } = filterFindingsByEvidencePolicy(mergedRaw);
    if (evidenceDropped.length > 0) {
        onProgress({
            phase: 'vuln_scan',
            status: 'running',
            message: `📋 Evidence policy: ${evidencePassed.length} reportable findings (${evidenceDropped.length} withheld — missing PoC or proof artifact).`,
        });
    }

    const vulnsWithAiPoc = await enrichConfirmedFindingsWithReviewerPoC(evidencePassed, onProgress);
    reactResultForAnalysis.findings = vulnsWithAiPoc;

    const finalAnalysis = await generateFinalAnalysis(target, currentReconData, reactResultForAnalysis, onProgress);

    const duration = Date.now() - startTime;
    const engOut = Array.isArray(engineResult) ? { findings: [] } : engineResult;

    return {
        success: true,
        target,
        vulns: vulnsWithAiPoc,
        evidenceDropped,
        attemptedFindings: [
            ...(reactResult.trace?.attemptedFindings || []),
            ...evidenceDropped.map((d) => ({
                endpoint: d.endpoint,
                type: d.type,
                failReason: `Evidence gate: ${d.reason}`,
            })),
        ],
        summary: reactResult.summary,
        analysis: finalAnalysis,
        trace: reactResult.trace,
        duration_ms: duration,
        engineFindings: engOut.findings || [],
        stats: {
            steps: reactResult.trace?.totalSteps || 0,
            payloads: reactResult.trace?.payloadsTested || 0,
            endpoints: currentReconData?.endpoints?.length || 0
        }
    };
}
