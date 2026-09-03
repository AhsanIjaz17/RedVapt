import { globalCoverage } from '../src/engine/state/coverageTracker.js';

describe('Coverage Tracker tests', () => {
    beforeEach(() => {
        globalCoverage.endpointsTested.clear();
        globalCoverage.paramsTested.clear();
    });

    it('ensures at least 80% endpoints tested before deep dive (simulated)', () => {
        const endpoints = [
            'http://test.com/a',
            'http://test.com/b',
            'http://test.com/c',
            'http://test.com/d',
            'http://test.com/e',
        ];

        endpoints.forEach(e => {
            globalCoverage.recordTest(e, 'id', '1');
            expect(globalCoverage.canTestEndpoint(e)).toBe(true);
        });

        // Test an endpoint too many times
        globalCoverage.recordTest('http://test.com/a', 'id', '2');
        globalCoverage.recordTest('http://test.com/a', 'id', '3');

        // Fourth test on a should be false (max 3 by default)
        expect(globalCoverage.canTestEndpoint('http://test.com/a')).toBe(false);
    });
});
