import { escapeRegExp } from '../../utils/parsers.js';

// ── Context Codes ─────────────────────────────────────────────────────────────

export const CONTEXT_CODES = {
    HTML_TEXT: 'HTML_TEXT',           // <div>MARKER</div>  — raw HTML body text
    SCRIPT_STRING_DOUBLE: 'SCRIPT_STRING_DOUBLE',// var x = "MARKER";
    SCRIPT_STRING_SINGLE: 'SCRIPT_STRING_SINGLE',// var x = 'MARKER';
    SCRIPT_BLOCK: 'SCRIPT_BLOCK',        // inside <script> but not in a string
    ATTR_DOUBLE_QUOTE: 'ATTR_DOUBLE_QUOTE',   // value="MARKER"
    ATTR_SINGLE_QUOTE: 'ATTR_SINGLE_QUOTE',   // value='MARKER'
    ATTR_UNQUOTED: 'ATTR_UNQUOTED',       // value=MARKER
    HREF_ATTR: 'HREF_ATTR',           // href="MARKER" or action="MARKER"
    SVG_CONTEXT: 'SVG_CONTEXT',         // <svg>...<script>let v="MARKER"</script>
    HTML_COMMENT: 'HTML_COMMENT',        // <!-- MARKER -->
    STYLE_ATTR: 'STYLE_ATTR',          // style="..MARKER.."
    NO_REFLECTION: 'NO_REFLECTION',       // marker not found in response
};

// ── Context Detection Rules ────────────────────────────────────────────────────

/**
 * Ordered list of detection rules. The first match wins.
 * Each rule has a priority (lower = more specific/trustworthy) and a test function.
 */
const DETECTION_RULES = [
    {
        code: CONTEXT_CODES.NO_REFLECTION,
        priority: 0,
        test: (marker, body) => !body.includes(marker),
    },
    {
        // <svg> and then a <script> containing the marker (XML parser context)
        code: CONTEXT_CODES.SVG_CONTEXT,
        priority: 1,
        test: (marker, body) => {
            const svgMatch = body.match(/<svg[\s\S]*?<\/svg>/i);
            if (!svgMatch) return false;
            return svgMatch[0].includes(marker);
        },
    },
    {
        // href="MARKER" or src="MARKER" or action="MARKER"
        code: CONTEXT_CODES.HREF_ATTR,
        priority: 2,
        test: (marker, body) => {
            return new RegExp(`(?:href|src|action|formaction|data|codebase)\\s*=\\s*["']?${escapeRegExp(marker)}`, 'i').test(body);
        },
    },
    {
        // Inside <script> block, in a double-quoted string: var x = "MARKER"
        code: CONTEXT_CODES.SCRIPT_STRING_DOUBLE,
        priority: 3,
        test: (marker, body) => {
            // Find script blocks and check if marker is inside a double-quoted string
            const scripts = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
            return scripts.some(m => {
                const js = m[1];
                return new RegExp(`"[^"]*${escapeRegExp(marker)}[^"]*"`, 'i').test(js);
            });
        },
    },
    {
        // Inside <script> block, in a single-quoted string: var x = 'MARKER'
        code: CONTEXT_CODES.SCRIPT_STRING_SINGLE,
        priority: 4,
        test: (marker, body) => {
            const scripts = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
            return scripts.some(m => {
                const js = m[1];
                return new RegExp(`'[^']*${escapeRegExp(marker)}[^']*'`, 'i').test(js);
            });
        },
    },
    {
        // Inside a <script> block but not in a quoted string
        code: CONTEXT_CODES.SCRIPT_BLOCK,
        priority: 5,
        test: (marker, body) => {
            const scripts = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
            return scripts.some(m => m[1].includes(marker));
        },
    },
    {
        // Inside an HTML comment <!-- MARKER -->
        code: CONTEXT_CODES.HTML_COMMENT,
        priority: 6,
        test: (marker, body) => new RegExp(`<!--[^-]*${escapeRegExp(marker)}`, 'i').test(body),
    },
    {
        // Inside style attribute: style="...MARKER..."
        code: CONTEXT_CODES.STYLE_ATTR,
        priority: 7,
        test: (marker, body) => new RegExp(`style\\s*=\\s*["'][^"']*${escapeRegExp(marker)}`, 'i').test(body),
    },
    {
        // value="MARKER" — double-quoted attribute
        code: CONTEXT_CODES.ATTR_DOUBLE_QUOTE,
        priority: 8,
        test: (marker, body) => new RegExp(`=\\s*"[^"]*${escapeRegExp(marker)}[^"]*"`, 'i').test(body),
    },
    {
        // value='MARKER' — single-quoted attribute
        code: CONTEXT_CODES.ATTR_SINGLE_QUOTE,
        priority: 9,
        test: (marker, body) => new RegExp(`=\\s*'[^']*${escapeRegExp(marker)}[^']*'`, 'i').test(body),
    },
    {
        // value=MARKER — unquoted attribute
        code: CONTEXT_CODES.ATTR_UNQUOTED,
        priority: 10,
        test: (marker, body) => new RegExp(`=\\s*${escapeRegExp(marker)}(?:[\\s/>])`, 'i').test(body),
    },
    {
        // Raw HTML text fallback: <div>MARKER</div>
        code: CONTEXT_CODES.HTML_TEXT,
        priority: 11,
        test: (marker, body) => body.includes(marker),
    },
];


// ── Core Functions ─────────────────────────────────────────────────────────────

/**
 * Detect which HTML context a marker string appears in within a response body.
 *
 * @param {string} marker       - The unique probe string injected (e.g. 'rvctx_ab12cd34')
 * @param {string} responseBody - The full HTTP response body
 * @returns {string}            - A CONTEXT_CODES value
 */
export function detectXssContext(marker, responseBody) {
    if (!marker || !responseBody) return CONTEXT_CODES.NO_REFLECTION;

    // Run rules in priority order — first match wins
    const sorted = [...DETECTION_RULES].sort((a, b) => a.priority - b.priority);
    for (const rule of sorted) {
        if (rule.test(marker, responseBody)) {
            return rule.code;
        }
    }

    return CONTEXT_CODES.NO_REFLECTION;
}

/**
 * Detect if htmlspecialchars() (or equivalent) is active.
 * This is done by checking if angle brackets < > were HTML-encoded.
 *
 * @param {string} marker       - The probe string (e.g. '<rvctx_test>')
 * @param {string} responseBody - The response body
 * @returns {boolean}           - true if htmlspecialchars is encoding angle brackets
 */
export function classifyHtmlspecialchars(marker, responseBody) {
    // If the raw marker with angle brackets is NOT in the body but
    // the encoded version IS — htmlspecialchars is active
    const rawPresent = responseBody.includes(marker);
    const encodedPresent = responseBody.includes(marker.replace('<', '&lt;').replace('>', '&gt;'));
    return !rawPresent && encodedPresent;
}

/**
 * Detect if the ENT_QUOTES flag is in use (i.e., both ' and " are encoded).
 * Used to determine if single-quote bypass or javascript: bypass is viable.
 *
 * @param {string} responseBody
 * @returns {{ singleQuoteEncoded: boolean, doubleQuoteEncoded: boolean }}
 */
export function detectQuoteEncoding(responseBody) {
    return {
        singleQuoteEncoded: responseBody.includes('&#039;') || responseBody.includes('&apos;'),
        doubleQuoteEncoded: responseBody.includes('&quot;') || responseBody.includes('&#34;'),
    };
}

/**
 * Full context analysis — combines context detection with sanitization awareness.
 *
 * @param {string} marker       - Probe marker
 * @param {string} responseBody - HTTP response body
 * @returns {{ context: string, htmlspecialcharsActive: boolean, quoteEncoding: object }}
 */
export function analyzeReflectionContext(marker, responseBody) {
    const context = detectXssContext(marker, responseBody);
    const angleMarker = `<${marker}>`;
    const htmlspecialcharsActive = classifyHtmlspecialchars(angleMarker, responseBody);
    const quoteEncoding = detectQuoteEncoding(responseBody);

    return { context, htmlspecialcharsActive, quoteEncoding };
}
