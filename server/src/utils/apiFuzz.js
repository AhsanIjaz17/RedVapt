/**
 * utils/apiFuzz.js — API Endpoint Fuzzer for ReAct Agent
 *
 * Probes common API paths on a target to discover hidden functionality.
 */

import axios from 'axios';

export const schema = {
    description: "Fuzz common API endpoint paths (e.g. /api/v1/users) to discover hidden routes.",
    parameters: {
        type: "object",
        properties: {
            url: { type: "string", description: "Base URL to fuzz (e.g. https://target.com)" },
            method: { type: "string", enum: ["GET", "POST"], default: "GET" }
        },
        required: ["url"]
    }
};

const API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/users', '/api/admin',
    '/api/login', '/api/auth', '/api/register', '/api/config',
    '/graphql', '/rest', '/v1', '/v2', '/admin', '/dashboard',
];

export async function execute({ url, method = 'GET' }) {
    const base = url.replace(/\/$/, '');
    const client = axios.create({ timeout: 8_000, maxRedirects: 3, validateStatus: () => true });
    const hits = [];

    await Promise.allSettled(
        API_PATHS.map(async (path) => {
            try {
                const r = await client.request({ method, url: `${base}${path}` });
                if (r.status < 404) {
                    hits.push({ path, status: r.status, size: String(r.data).length });
                }
            } catch { /* skip unreachable */ }
        })
    );

    return {
        base,
        found: hits.sort((a, b) => a.status - b.status),
        summary: `Discovered ${hits.length}/${API_PATHS.length} paths.`,
    };
}
