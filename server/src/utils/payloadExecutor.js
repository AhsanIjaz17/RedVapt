/**
 * utils/payloadExecutor.js — Payload Injection + Verification Wrapper
 *
 * Used by both aiPlanner.js and reactAgent.js.
 * Injects a payload into a URL parameter and checks the response for evidence.
 */

import axios from 'axios';

export const schema = {
    description: "Inject a security payload into a URL parameter and return the full HTTP response.",
    parameters: {
        type: "object",
        properties: {
            url: { type: "string", description: "Target URL" },
            param: { type: "string", description: "Parameter name to inject" },
            method: { type: "string", enum: ["GET", "POST"], default: "GET" },
            payload: { type: "string", description: "Payload string to inject" },
            expectedDelay: { type: "number", description: "For time-based checks: expected delay in ms" }
        },
        required: ["url", "payload"]
    }
};

export async function execute({ url, param, method = 'GET', payload, expectedDelay }) {
    const start = Date.now();

    const client = axios.create({
        timeout: expectedDelay ? Math.min(expectedDelay + 10000, 60_000) : 30_000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (RedVapt/1.0)' },
    });

    let config = { url, method };

    if (method === 'GET') {
        const u = new URL(url.startsWith('http') ? url : `https://${url}`);
        if (param) u.searchParams.set(param, payload);
        config.url = u.href;
    } else {
        config.data = param ? { [param]: payload } : payload;
    }

    try {
        const resp = await client.request(config);
        const elapsed = Date.now() - start;
        const body = (typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data)).slice(0, 5000);

        // Timing-based detection hint
        const timingHit = expectedDelay && elapsed >= expectedDelay;

        return {
            status: resp.status,
            elapsed_ms: elapsed,
            body,
            timing_hit: timingHit,
            headers: Object.fromEntries(Object.entries(resp.headers).slice(0, 10)),
        };
    } catch (err) {
        const elapsed = Date.now() - start;
        console.error(`[PayloadExecutor] Request failed: ${err.message} (${url})`);
        return {
            status: 0,
            elapsed_ms: elapsed,
            body: '',
            error: err.message,
            socket_hang: err.code === 'ECONNRESET' || err.message.includes('socket hang up'),
            timeout: err.code === 'ECONNABORTED' || err.message.includes('timeout'),
        };
    }
}
