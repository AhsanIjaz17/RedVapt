import { escalateSQLi } from '../src/engine/vuln/escalation/sqlEscalator.js';

describe('SQLi Escalation deterministic test', () => {
    it('ensures escalation chain triggers automatically', () => {
        const res = escalateSQLi({}, {}, "SQL error detected");

        expect(res.vulnType).toBe("SQLi");
        expect(res.requiresConfirmationTool).toBe(true);
        expect(res.escalationPlan.length).toBeGreaterThan(2);
        expect(res.nextPayloads).toContain("' AND 1=1--");
        expect(res.nextPayloads).toContain("' UNION SELECT NULL--");
        expect(res.nextPayloads).toContain("pg_sleep(5)");
    });
});
