/**
 * coverageTracker.js — Hard breadth-first endpoint enforcement
 *
 * Tracks tested endpoints and parameters to ensure ReAct AI does not
 * get stuck on a single endpoint, supporting broad mapping.
 */

export const COVERAGE_TARGETS = {
    endpoints_tested: 0.8,        // test ≥80% of discovered endpoints
    params_per_endpoint: 0.9,     // test ≥90% of discovered params per endpoint
    vuln_types_per_endpoint: 3,    // test at least 3 vuln types per endpoint
    auth_surfaces: 1,            // test 100% of auth endpoints
};

export class CoverageTracker {
    constructor(maxAttemptsPerEndpoint = 3) {
        this.endpointsTested = new Map(); // endpoint -> number of tests
        this.paramsTested = new Map(); // endpoint:param -> number of tests
        this.confirmedFindings = [];
        this.pendingEscalation = [];
        this.maxAttempts = maxAttemptsPerEndpoint;
    }

    recordTest(endpoint, param, payload) {
        const currentEpCount = this.endpointsTested.get(endpoint) || 0;
        this.endpointsTested.set(endpoint, currentEpCount + 1);

        const paramKey = `${endpoint}:${param}`;
        const currentParam = this.paramsTested.get(paramKey) || { count: 0, payloads: [] };
        currentParam.count++;
        currentParam.payloads.push(payload);
        this.paramsTested.set(paramKey, currentParam);
    }

    canTestEndpoint(endpoint) {
        const count = this.endpointsTested.get(endpoint) || 0;
        return count < this.maxAttempts;
    }

    computeCoverage(endpointMap) {
        // compute coverage
        const endpointList = Array.from(endpointMap.keys ? endpointMap.keys() : endpointMap);
        const totalCount = endpointList.length;
        if (totalCount === 0) return { endpointCoverage: 1 }; // Nothing to check

        const testedCount = this.endpointsTested.size;
        return {
            endpointCoverage: testedCount / totalCount,
            testedCount,
            totalCount,
            untestedEndpoints: endpointList.filter(u => !this.endpointsTested.has(u)),
            stopReason: (testedCount / totalCount) >= COVERAGE_TARGETS.endpoints_tested ? 'threshold_met' : 'iterations_exhausted',
        };
    }

    getCoverageStats() {
        return {
            endpointsCovered: this.endpointsTested.size,
            endpoints: Object.fromEntries(this.endpointsTested),
            confirmedVulnCount: this.confirmedFindings.length,
            pendingTasks: this.pendingEscalation.length
        };
    }

    queueEscalation(task) {
        this.pendingEscalation.push(task);
    }

    addConfirmedFinding(finding) {
        this.confirmedFindings.push(finding);
    }
}

export const globalCoverage = new CoverageTracker();
