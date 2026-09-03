/**
 * engine/verifiers/nucleiVerifier.js — Nuclei CVE/Misconfig Verification Module
 *
 * Called ONLY when recon detects a known tech stack (WordPress, Apache, nginx,
 * PHP, outdated headers, etc.) indicating CVE candidates exist.
 *
 * Uses execFile() — never exec() with string interpolation.
 * Runs nuclei with JSON output for reliable structured parsing.
 * Hard timeout: 90 seconds with SIGTERM.
 *
 * Key flags:
 *   -json             newline-delimited JSON for easy parsing
 *   -severity         medium,high,critical only (ignore info noise)
 *   -timeout 10       per-request timeout
 *   -rl 10            rate limit 10 req/s (polite)
 *   -no-interactsh    disable OAST (no external callbacks needed)
 *   -silent           suppress banner
 */

import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const NUCLEI_TIMEOUT_MS = 90_000;

// ── Tool detection ────────────────────────────────────────────────────────────

async function findBin(name) {
    try {
        const { stdout } = await execFileAsync('which', [name], { timeout: 5000 });
        return stdout.trim() || null;
    } catch { return null; }
}

// ── Tech stack → nuclei tag mapping ──────────────────────────────────────────

const TECH_TAG_MAP = {
    wordpress: ['wordpress', 'wp-plugin', 'wp-theme'],
    apache: ['apache', 'misconfig'],
    nginx: ['nginx', 'misconfig'],
    php: ['php', 'misconfig'],
    iis: ['iis', 'misconfig'],
    drupal: ['drupal'],
    joomla: ['joomla'],
    laravel: ['laravel'],
    django: ['django'],
    spring: ['spring', 'java'],
    struts: ['struts'],
};

function techToTags(technologies = []) {
    const tags = new Set(['misconfig', 'cves', 'exposure']);
    for (const tech of technologies) {
        const t = tech.toLowerCase();
        for (const [key, tagList] of Object.entries(TECH_TAG_MAP)) {
            if (t.includes(key)) tagList.forEach(tag => tags.add(tag));
        }
    }
    return [...tags].join(',');
}

// ── JSON output parser ────────────────────────────────────────────────────────

function parseNucleiJsonOutput(stdout) {
    const findings = [];
    for (const line of stdout.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('{')) continue;
        try {
            const item = JSON.parse(trimmed);
            if (!item['template-id']) continue;

            findings.push({
                templateId: item['template-id'],
                name: item.info?.name || item['template-id'],
                severity: item.info?.severity || 'unknown',
                description: (item.info?.description || '').slice(0, 300),
                url: item.url || item.matched || item.host,
                type: item.type,
                request: (item.request || '').slice(0, 400),
                response: (item.response || '').slice(0, 400),
                matcher: item['matched-at'] || '',
                cve: item.info?.classification?.['cve-id']?.[0] || null,
            });
        } catch { /* skip non-JSON lines */ }
    }
    return findings;
}

// ── Main verifier export ──────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {string}   opts.url           - base URL to scan
 * @param {string[]} opts.technologies  - from recon (WordPress, PHP, etc.)
 * @param {object}   [opts.signal]      - signal context (optional)
 * @param {Function} [opts.onProgress]
 * @returns {Promise<Array<{confirmed, tool, evidence, rawOutput, severity, metadata}>>}
 */
export async function verify({ url, technologies = [], signal = null, onProgress = () => { } }) {
    const bin = await findBin('nuclei');

    if (!bin) {
        return [{
            confirmed: false,
            tool: 'nuclei',
            evidence: '',
            rawOutput: 'nuclei not installed — install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            severity: null,
            metadata: { skipped: true, reason: 'tool_not_found' },
        }];
    }

    const tags = techToTags(technologies);

    const args = [
        '-u', url,
        '-tags', tags,
        '-severity', 'medium,high,critical',
        '-json',
        '-timeout', '10',
        '-rl', '10',
        '-no-interactsh',
        '-silent',
        '-no-color',
    ];

    onProgress({
        phase: 'verification',
        status: 'running',
        message: `🔬 nuclei: Scanning ${url} for CVEs/misconfigs [tags: ${tags}] (up to 90s)...`,
    });

    let stdout = '';
    let timedOut = false;

    try {
        const result = await execFileAsync(bin, args, {
            timeout: NUCLEI_TIMEOUT_MS,
            maxBuffer: 4 * 1024 * 1024,
        });
        stdout = result.stdout || '';
    } catch (err) {
        stdout = err.stdout || '';
        if (err.killed || err.signal === 'SIGTERM') timedOut = true;
    }

    const findings = parseNucleiJsonOutput(stdout);

    if (findings.length === 0) {
        onProgress({
            phase: 'verification',
            status: 'done',
            message: `✅ nuclei: No CVEs/misconfigs found at ${url}${timedOut ? ' (timed out)' : ''}`,
        });
        return [{
            confirmed: false,
            tool: 'nuclei',
            evidence: '',
            rawOutput: stdout.slice(0, 500),
            severity: null,
            metadata: { timedOut, tags },
        }];
    }

    onProgress({
        phase: 'verification',
        status: 'done',
        message: `🚨 nuclei: ${findings.length} finding(s) at ${url} [${findings.map(f => f.templateId).slice(0, 3).join(', ')}...]`,
    });

    // Return one result per nuclei finding
    return findings.map(f => ({
        confirmed: true,
        tool: 'nuclei',
        evidence: [
            f.description,
            f.matcher && `Matched: ${f.matcher}`,
            f.request && `Request snippet: ${f.request.slice(0, 200)}`,
        ].filter(Boolean).join('\n'),
        rawOutput: JSON.stringify(f),
        severity: f.severity,
        metadata: {
            templateId: f.templateId,
            name: f.name,
            url: f.url,
            cve: f.cve,
            tags,
        },
    }));
}
