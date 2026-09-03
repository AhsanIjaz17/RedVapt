/**
 * agentMemory.js — Agent Memory / State Tracker
 *
 * Tracks all observations, tested payloads, confirmed vulnerabilities,
 * and discovered endpoints during a pentest session. Prevents duplicate
 * testing and provides context window for LLM within token budget.
 */

export class AgentMemory {
    constructor() {
        /** @type {Array<{ step: number, thought: string, action: string, params: object, result: object, timestamp: number }>} */
        this.steps = [];

        /** @type {Map<string, Set<string>>} endpoint → Set of tested payloads */
        this.testedPayloads = new Map();

        /** @type {Array<object>} Confirmed vulnerabilities */
        this.confirmedVulns = [];

        /** @type {Set<string>} Discovered endpoints/URLs */
        this.discoveredEndpoints = new Set();

        /** @type {Map<string, object>} Key observations indexed by type */
        this.observations = new Map();

        /** @type {object|null} Recon data from Phase 1 */
        this.reconData = null;

        /** @type {Array<{ endpoint: string, type: string, confidence: string }>} */
        this.hypothesisQueue = [];

        /** @type {Array<string>} Hits from previous response analysis */
        this.adaptiveHints = [];
    }

    /**
     * Record a step in the reasoning loop.
     */
    addStep(step) {
        this.steps.push({
            ...step,
            timestamp: Date.now(),
        });
    }

    /**
     * Record that a payload was tested against an endpoint.
     * @returns {boolean} true if this was a new test (not duplicate)
     */
    recordPayloadTest(endpoint, payload) {
        if (!this.testedPayloads.has(endpoint)) {
            this.testedPayloads.set(endpoint, new Set());
        }
        const payloads = this.testedPayloads.get(endpoint);
        if (payloads.has(payload)) return false;
        payloads.add(payload);
        return true;
    }

    /**
     * Check if a specific payload was already tested on an endpoint.
     */
    wasPayloadTested(endpoint, payload) {
        return this.testedPayloads.get(endpoint)?.has(payload) || false;
    }

    /**
     * Get all payloads tested on an endpoint.
     */
    getTestedPayloads(endpoint) {
        return [...(this.testedPayloads.get(endpoint) || [])];
    }

    /**
     * Add a confirmed vulnerability.
     */
    addConfirmedVuln(vuln) {
        this.confirmedVulns.push({
            ...vuln,
            confirmedAt: Date.now(),
        });
    }

    /**
     * Add discovered endpoint(s).
     */
    addEndpoints(endpoints) {
        for (const ep of (Array.isArray(endpoints) ? endpoints : [endpoints])) {
            this.discoveredEndpoints.add(ep);
        }
    }

    /**
     * Store an observation by type.
     */
    addObservation(type, data) {
        if (!this.observations.has(type)) {
            this.observations.set(type, []);
        }
        this.observations.get(type).push(data);
    }

    /**
     * Set the hypothesis queue (from specialist agents).
     */
    setHypothesisQueue(queue) {
        this.hypothesisQueue = queue;
    }

    /**
     * Add adaptive hints from response analysis.
     */
    addAdaptiveHints(hints) {
        if (!Array.isArray(hints)) return;
        this.adaptiveHints = [...new Set([...this.adaptiveHints, ...hints])];
    }

    /**
     * Pop the next hypothesis from the queue.
     */
    popHypothesis() {
        return this.hypothesisQueue.shift() || null;
    }

    /**
     * Build a context summary for the LLM within a token budget.
     * Prioritizes recent steps and confirmed vulns.
     * @param {number} maxChars - Max characters for context (~4 chars per token)
     * @returns {string}
     */
    buildContextSummary(maxChars = 6000) {
        const parts = [];

        // 1. Confirmed vulns (highest priority)
        if (this.confirmedVulns.length > 0) {
            parts.push('## Confirmed Vulnerabilities');
            for (const v of this.confirmedVulns) {
                parts.push(`- **${v.type}** at \`${v.endpoint}\` — ${v.impact || 'N/A'}`);
            }
        }

        // 2. Discovered endpoints summary
        if (this.discoveredEndpoints.size > 0) {
            const eps = [...this.discoveredEndpoints].slice(0, 30);
            parts.push(`\n## Discovered Endpoints (${this.discoveredEndpoints.size} total)`);
            parts.push(eps.join('\n'));
            if (this.discoveredEndpoints.size > 30) parts.push(`... and ${this.discoveredEndpoints.size - 30} more`);
        }

        // 3. Remaining hypothesis queue
        if (this.hypothesisQueue.length > 0) {
            parts.push(`\n## Pending Hypotheses (${this.hypothesisQueue.length})`);
            for (const h of this.hypothesisQueue.slice(0, 10)) {
                parts.push(`- [${h.type}] ${h.endpoint} (${h.confidence})`);
            }
        }

        // 4. Recent steps (last 8)
        const recentSteps = this.steps.slice(-8);
        if (recentSteps.length > 0) {
            parts.push('\n## Recent Actions');
            for (const s of recentSteps) {
                const resultSnippet = typeof s.result === 'string'
                    ? s.result.slice(0, 200)
                    : JSON.stringify(s.result || {}).slice(0, 200);
                parts.push(`- Step ${s.step}: [${s.action}] → ${resultSnippet}`);
            }
        }

        // 5. Adaptive Hints
        if (this.adaptiveHints.length > 0) {
            parts.push(`\n## 🛠️ Adaptive Intelligence (Hints for next payloads)`);
            parts.push(`Signals detected: ${this.adaptiveHints.join(', ')}`);
            parts.push(`→ Use these signals to adapt your next payload (e.g. choose specific DB payloads or WAF evasion).`);
        }

        // 6. Tested payload summary
        if (this.testedPayloads.size > 0) {
            parts.push(`\n## Testing Coverage`);
            parts.push(`Endpoints tested: ${this.testedPayloads.size}`);
            let totalPayloads = 0;
            for (const [, payloads] of this.testedPayloads) totalPayloads += payloads.size;
            parts.push(`Total payloads sent: ${totalPayloads}`);
        }

        let summary = parts.join('\n');

        // Enforce budget
        if (summary.length > maxChars) {
            summary = summary.slice(0, maxChars - 20) + '\n... (truncated)';
        }

        return summary;
    }

    /**
     * Get full audit trail of all steps.
     */
    getFullTrace() {
        return {
            totalSteps: this.steps.length,
            steps: this.steps,
            confirmedVulns: this.confirmedVulns,
            endpointsDiscovered: this.discoveredEndpoints.size,
            payloadsTested: [...this.testedPayloads.entries()].reduce((sum, [, v]) => sum + v.size, 0),
        };
    }
}
