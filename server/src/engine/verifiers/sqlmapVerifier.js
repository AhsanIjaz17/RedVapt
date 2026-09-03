/**
 * engine/verifiers/sqlmapVerifier.js — SQLMap Verification Module
 *
 * Called when signalEngine detects SQLi with confidence ≥ 0.25.
 * Uses execFile() — never exec() with string interpolation (no injection risk).
 * Hard-killed after 120s via AbortController.
 *
 * Implements user's SQLmap tips:
 *   --dbms    : specify DB type when known (halves queries sent)
 *   --level   : 3 by default (was 2) — tests cookies/headers too
 *   --risk    : 2 by default (was 1) — includes OR-based tests
 *   -p        : focus on specific parameter
 *   --dbs     : enumerate databases when extractDbs=true
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

const execFileAsync = promisify(execFile);
const SQLMAP_TIMEOUT_MS = 120_000;

// ── DB type → sqlmap --dbms value ─────────────────────────────────────────────
const DBMS_MAP = {
    mysql: 'MySQL',
    postgres: 'PostgreSQL',
    mssql: 'Microsoft SQL Server',
    oracle: 'Oracle',
    sqlite: 'SQLite',
};

// ── Tool detection ────────────────────────────────────────────────────────────

async function findBin(name) {
    try {
        const { stdout } = await execFileAsync('which', [name], { timeout: 5000 });
        return stdout.trim() || null;
    } catch { return null; }
}

// ── Output parser ─────────────────────────────────────────────────────────────

function parseSqlmapOutput(stdout, paramName) {
    const lines = stdout.split('\n');
    const confirmed = lines.some(l =>
        /parameter ['"]?.*['"]? is vulnerable/i.test(l) ||
        /\[CRITICAL\].*injectable/i.test(l) ||
        /sqlmap identified the following injection point/i.test(l)
    );

    // Extract DBMS line
    const dbmsLine = lines.find(l => /back-end DBMS/i.test(l));
    const dbms = dbmsLine ? dbmsLine.replace(/.*DBMS[:\s]*/i, '').trim() : null;

    // Extract payload evidence snippet (first payload line)
    const payloadLine = lines.find(l => /payload:/i.test(l));
    const evidencePayload = payloadLine ? payloadLine.replace(/.*payload:\s*/i, '').trim() : null;

    // Extract title line
    const titleLine = lines.find(l => /\[INFO\] testing '/.test(l) || /Type:/.test(l));
    const injectionType = titleLine?.trim() || null;

    // Extract injection technique summary
    const techniqueLine = lines.find(l => /technique:/i.test(l));
    const technique = techniqueLine?.trim() || null;

    // Grab last 20 lines as raw output (enough context, not too large)
    const rawOutput = lines.slice(-20).join('\n');

    return { confirmed, dbms, evidencePayload, injectionType, technique, rawOutput };
}

// ── Main verifier export ──────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {string}  opts.url         - full URL (base, without param appended)
 * @param {string}  opts.method      - GET | POST
 * @param {string}  opts.param       - parameter name to test
 * @param {string}  opts.injectIn    - 'query' | 'body'
 * @param {object}  opts.signal      - signal object from signalEngine
 * @param {string}  [opts.dbType]    - detected DB type ('mysql','postgres','mssql', etc.)
 *                                     Passed as --dbms to halve query count (user tip #1)
 * @param {number}  [opts.level]     - sqlmap --level (1-5, default 3)
 * @param {number}  [opts.risk]      - sqlmap --risk (1-3, default 2)
 * @param {boolean} [opts.extractDbs] - if true, pass --dbs to enumerate databases
 * @param {Function} [opts.onProgress] - SSE callback
 * @returns {Promise<{confirmed, tool, evidence, rawOutput, severity, metadata}>}
 */
export async function verify({
    url,
    method,
    param,
    injectIn,
    signal,
    dbType = null,
    level = 3,
    risk = 2,
    extractDbs = false,
    onProgress = () => { },
}) {
    const bin = await findBin('sqlmap');

    if (!bin) {
        return {
            confirmed: false,
            tool: 'sqlmap',
            evidence: '',
            rawOutput: 'sqlmap not installed — install with: pip install sqlmap',
            severity: null,
            metadata: { skipped: true, reason: 'tool_not_found' },
        };
    }

    // Build test URL (sqlmap needs the full URL with param for GET)
    const testUrl = injectIn === 'query'
        ? (url.includes('?') ? url : `${url}?${param}=1`)
        : url;

    // Create isolated output dir
    const outDir = await mkdtemp(join(tmpdir(), 'rv_sqlmap_'));

    // ── Build args ────────────────────────────────────────────────────────────
    const args = [
        '-u', testUrl,
        '-p', param,           // USER TIP: focus on specific parameter with -p
        '--batch',
        '--random-agent',
        '--level', String(Math.min(Math.max(level, 1), 5)),    // USER TIP: --level controls depth (1-5)
        '--risk', String(Math.min(Math.max(risk, 1), 3)),      // USER TIP: --risk controls intensity (1-3)
        '--threads', '2',
        '--output-dir', outDir,
        '--flush-session',
        '--no-logging',
    ];

    // USER TIP: --dbms speeds up detection dramatically when DB type is known
    if (dbType && DBMS_MAP[dbType.toLowerCase()]) {
        args.push('--dbms', DBMS_MAP[dbType.toLowerCase()]);
    }

    // Optional: enumerate all databases
    if (extractDbs) {
        args.push('--dbs');
    }

    // For POST, add data
    if (injectIn === 'body' || (method || '').toUpperCase() === 'POST') {
        args.push('--data', `${param}=1`);
        args.push('--method', 'POST');
    }

    const dbmsHint = dbType ? ` [dbms=${DBMS_MAP[dbType.toLowerCase()] || dbType}]` : '';
    onProgress({
        phase: 'verification',
        status: 'running',
        message: `🔬 sqlmap: Verifying SQLi on ${url} param="${param}"${dbmsHint} --level=${level} --risk=${risk} (up to 120s)...`,
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const controller = new AbortController();
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, SQLMAP_TIMEOUT_MS);

    try {
        const result = await execFileAsync(bin, args, {
            timeout: SQLMAP_TIMEOUT_MS,
            maxBuffer: 4 * 1024 * 1024,
            signal: controller.signal,
        });
        stdout = result.stdout || '';
        stderr = result.stderr || '';
    } catch (err) {
        stdout = err.stdout || '';
        stderr = err.stderr || '';
        if (timedOut || err.code === 'ABORT_ERR') {
            stderr = 'sqlmap killed after 120s timeout';
        }
    } finally {
        clearTimeout(timer);
        await rm(outDir, { recursive: true, force: true }).catch(() => { });
    }

    const parsed = parseSqlmapOutput(stdout, param);

    if (parsed.confirmed) {
        const evidence = [
            parsed.evidencePayload && `Payload: ${parsed.evidencePayload}`,
            parsed.dbms && `DBMS: ${parsed.dbms}`,
            parsed.injectionType,
            parsed.technique,
            signal.evidenceSnippet && `Signal: ${signal.evidenceSnippet.slice(0, 200)}`,
        ].filter(Boolean).join('\n');

        onProgress({
            phase: 'verification',
            status: 'done',
            message: `🚨 sqlmap CONFIRMED: SQL Injection at ${url} param="${param}" [${parsed.dbms || dbType || 'unknown DB'}]`,
        });

        return {
            confirmed: true,
            tool: 'sqlmap',
            evidence,
            rawOutput: parsed.rawOutput,
            severity: 'critical',
            metadata: {
                dbms: parsed.dbms || dbType,
                param,
                technique: parsed.technique,
                signalType: signal.signalType,
                signalConfidence: signal.confidence,
            },
        };
    }

    onProgress({
        phase: 'verification',
        status: 'done',
        message: `✅ sqlmap: No injection confirmed at ${url} param="${param}"${timedOut ? ' (timed out)' : ''}`,
    });

    return {
        confirmed: false,
        tool: 'sqlmap',
        evidence: '',
        rawOutput: parsed.rawOutput,
        severity: null,
        metadata: { timedOut, signalType: signal.signalType, dbType },
    };
}
