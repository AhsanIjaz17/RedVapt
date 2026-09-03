/**
 * utils/responseDiff.js — Blind Injection Detection via Response Diffing
 *
 * Sends two requests (true condition vs false condition) and compares
 * the responses to detect Boolean-based or Time-based blind injection.
 */

import axios from 'axios';

export const schema = {
    description: "Compare two HTTP responses to detect blind injection signals (Boolean/Timing-based).",
    parameters: {
        type: "object",
        properties: {
            url: { type: "string", description: "Target URL" },
            method: { type: "string", enum: ["GET", "POST"], default: "GET" },
            param: { type: "string", description: "Parameter to inject into" },
            payloadA: { type: "string", description: "True condition payload (e.g. '1=1')" },
            payloadB: { type: "string", description: "False condition payload (e.g. '1=2')" }
        },
        required: ["url", "param", "payloadA", "payloadB"]
    }
};

async function probe(url, method, param, payload) {
    const start = Date.now();
    const client = axios.create({ timeout: 15_000, maxRedirects: 5, validateStatus: () => true });

    let config = { method };
    if (method === 'POST') {
        config.url = url;
        config.data = { [param]: payload };
    } else {
        const u = new URL(url.startsWith('http') ? url : `https://${url}`);
        u.searchParams.set(param, payload);
        config.url = u.href;
    }

    const resp = await client.request(config);
    const body = (typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data));
    return {
        status: resp.status,
        size: body.length,
        time_ms: Date.now() - start,
        snippet: body.slice(0, 500),
    };
}

export async function execute({ url, method = 'GET', param, payloadA, payloadB }) {
    const [resA, resB] = await Promise.all([
        probe(url, method, param, payloadA),
        probe(url, method, param, payloadB),
    ]);

    const sizeDiff = Math.abs(resA.size - resB.size);
    const timeDiff = Math.abs(resA.time_ms - resB.time_ms);
    const statusDiff = resA.status !== resB.status;

    const isLikelyVulnerable = statusDiff || sizeDiff > 50 || timeDiff > 2000;

    return {
        resA,
        resB,
        diff: { statusDiff, sizeDiff, timeDiff, isLikelyVulnerable },
        conclusion: isLikelyVulnerable
            ? `Behavior diverged (size Δ${sizeDiff}, time Δ${timeDiff}ms, status: ${resA.status} vs ${resB.status}) — possible blind injection.`
            : `Responses identical — no blind injection detected for this parameter.`,
    };
}
