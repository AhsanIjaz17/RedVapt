import { signalScoringEngine } from '../src/engine/scoring/signalScoringEngine.js';

describe('Verifier Logic & Scoring tests', () => {
    it('ensures WAF pages do not confirm vulns', () => {
        const baseline = { status: 200, size: 1000 };
        const injected = {
            status: 403,
            size: 500,
            body: "<html><head><title>403 Forbidden</title></head><body><h1>Cloudflare Ray ID...</h1></body></html>"
        };

        const scoreObj = signalScoringEngine.evaluateSignal([baseline, baseline, baseline], injected, "' OR 1=1");

        expect(scoreObj.wafSuspected).toBe(true);
        expect(scoreObj.confidence).toBeLessThan(0.2);
        expect(scoreObj.signalType).toBe('WAF_BLOCK');
    });

    it('identifies valid SQL errors to increase confidence', () => {
        const baseline = { status: 200, size: 1000 };
        const injected = {
            status: 200,
            size: 1500,
            body: "Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource. You have an error in your SQL syntax."
        };

        const scoreObj = signalScoringEngine.evaluateSignal([baseline, baseline, baseline], injected, "'");

        expect(scoreObj.wafSuspected).toBe(false);
        expect(scoreObj.confidence).toBeGreaterThan(0.3);
        expect(scoreObj.signalType).toBe('SQLi_ERROR');
    });
});
