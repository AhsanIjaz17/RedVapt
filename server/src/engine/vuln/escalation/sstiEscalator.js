/**
 * sstiEscalator.js
 * 
 * Target template engines via deterministic evaluation payloads.
 */

export function escalateSSTI(baselineResponse, injectedResponse, initialEvidence) {
    // SSTI generally tries arithmetic first, then object execution paths
    const escalationPlan = [
        "Test basic arithmetic execution (49, 7777)",
        "Detect engine (Jinja vs Freemarker vs Twig vs EJS)",
        "Try language-specific RCE structure or info leak"
    ];

    const nextPayloads = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "#{7*7}",
        "*{7*7}"
    ];

    return {
        vulnType: "SSTI",
        requiresConfirmationTool: false, // can usually be verified purely via regex (49)
        escalationPlan,
        nextPayloads
    };
}
