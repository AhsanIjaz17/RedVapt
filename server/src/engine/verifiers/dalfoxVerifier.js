/**
 * engine/verifiers/dalfoxVerifier.js — Dalfox XSS Verification Module
 *
 * Called ONLY when signalEngine detects XSS with confidence ≥ 0.70.
 * Uses execFile() — never exec() with string injection risk.
 * Hard timeout: 60 seconds.
 *
 * Runs dalfox with:
 *   --silence         (suppress banner and progress, clean output)
 *   --timeout 10      (per-request timeout)
 *   --only-discovery  (no deep payload fuzzing — we already have signal)
 *
 * Also injects the proofToken as a custom payload to confirm reflection.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const DALFOX_TIMEOUT_MS = 60_000;

// ── Tool detection ────────────────────────────────────────────────────────────

async function findBin(name) {
    try {
        const { stdout } = await execFileAsync('which', [name], { timeout: 5000 });
        return stdout.trim() || null;
    } catch { return null; }
}

// ── Output parser ─────────────────────────────────────────────────────────────

function parseDalfoxOutput(stdout, proofToken) {
    const lines = stdout.split('\n').filter(Boolean);

    // Dalfox marks findings with [V] or VULN or POC
    const vulnLines = lines.filter(l =>
        /\[V\]|\[VULN\]|VULN|POC|XSS/i.test(l)
    );

    const confirmed = vulnLines.length > 0 || (proofToken && stdout.includes(proofToken));

    // Extract PoC URL if present
    const pocLine = lines.find(l => /poc|payload/i.test(l) && l.includes('http'));
    const evidencePayload = pocLine || vulnLines[0] || '';

    // Check if our token appears in reported sink
    const tokenConfirmed = proofToken && stdout.includes(proofToken);

    const rawOutput = lines.slice(0, 30).join('\n');

    return { confirmed, evidencePayload, tokenConfirmed, rawOutput };
}

// ── Build test URL with param ─────────────────────────────────────────────────

function buildTestUrl(url, paramName, injectIn) {
    if (injectIn === 'body') return url; // dalfox handles POST via --data
    const sep = url.includes('?') ? '&' : '?';
    // Use FUZZ marker so dalfox knows which param to test
    return `${url}${sep}${encodeURIComponent(paramName)}=FUZZ`;
}

// ── Main verifier export ──────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {string}  opts.url
 * @param {string}  opts.method
 * @param {string}  opts.param
 * @param {string}  opts.injectIn
 * @param {string}  opts.proofToken
 * @param {object}  opts.signal
 * @param {Function} [opts.onProgress]
 */
export async function verify({ url, method, param, injectIn, proofToken, signal, onProgress = () => { } }) {
    const bin = await findBin('dalfox');

    if (!bin) {
        return {
            confirmed: false,
            tool: 'dalfox',
            evidence: '',
            rawOutput: 'dalfox not installed — install with: go install github.com/hahwul/dalfox/v2@latest',
            severity: null,
            metadata: { skipped: true, reason: 'tool_not_found' },
        };
    }

    const testUrl = buildTestUrl(url, param, injectIn);

    // Custom payload using the proofToken for verification
    const customPayload = proofToken
        ? `<img src=x onerror=alert('${proofToken}')>`
        : `<script>alert(1)</script>`;

    const args = [
        'url', testUrl,
        '--silence',
        '--timeout', '10',
        '--only-discovery',
        '--custom-payload', customPayload,
        '--output-format', 'plain',
    ];

    // POST support
    if (injectIn === 'body' || (method || '').toUpperCase() === 'POST') {
        args.push('--data', `${param}=FUZZ`);
        args.push('--method', 'POST');
    }

    onProgress({
        phase: 'verification',
        status: 'running',
        message: `🔬 dalfox: Verifying XSS on ${url} param="${param}" (up to 60s)...`,
    });

    let stdout = '';
    let timedOut = false;

    try {
        const result = await execFileAsync(bin, args, {
            timeout: DALFOX_TIMEOUT_MS,
            maxBuffer: 2 * 1024 * 1024,
        });
        stdout = result.stdout || '';
    } catch (err) {
        stdout = err.stdout || '';
        if (err.killed || err.signal === 'SIGTERM') {
            timedOut = true;
        }
    }

    const parsed = parseDalfoxOutput(stdout, proofToken);

    if (parsed.confirmed) {
        const evidence = [
            parsed.evidencePayload && `PoC: ${parsed.evidencePayload}`,
            parsed.tokenConfirmed && `Token confirmed in response: ${proofToken}`,
            signal.evidenceSnippet && `Signal snippet: ${signal.evidenceSnippet.slice(0, 200)}`,
        ].filter(Boolean).join('\n');

        onProgress({
            phase: 'verification',
            status: 'done',
            message: `🚨 dalfox CONFIRMED: XSS at ${url} param="${param}"`,
        });

        return {
            confirmed: true,
            tool: 'dalfox',
            evidence,
            rawOutput: parsed.rawOutput,
            severity: 'high',
            metadata: {
                param,
                tokenConfirmed: parsed.tokenConfirmed,
                signalType: signal.signalType,
                signalConfidence: signal.confidence,
            },
        };
    }

    onProgress({
        phase: 'verification',
        status: 'done',
        message: `✅ dalfox: No XSS confirmed at ${url} param="${param}"${timedOut ? ' (timed out)' : ''}`,
    });

    return {
        confirmed: false,
        tool: 'dalfox',
        evidence: '',
        rawOutput: parsed.rawOutput,
        severity: null,
        metadata: { timedOut, signalType: signal.signalType },
    };
}
