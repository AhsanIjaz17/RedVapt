/**
 * utils/httpRequest.js — Simple Axios HTTP Wrapper for ReAct Agent
 */

import axios from 'axios';
import { globalSession } from './sessionManager.js';

export const schema = {
    description: "Make an HTTP request (GET/POST) to a target URL and return the response.",
    parameters: {
        type: "object",
        properties: {
            url: { type: "string", description: "Target URL" },
            method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"], default: "GET" },
            params: { type: "object", description: "Query parameters (GET)" },
            data: { type: "object", description: "Body data (POST)" },
            headers: { type: "object", description: "Extra headers" }
        },
        required: ["url"]
    }
};

export async function execute({ url, method = 'GET', params = {}, data = null, headers = {} }) {
    // R7: Attach persisted cookies from session
    const cookieHeader = globalSession.getCookieHeader();
    const finalHeaders = {
        'User-Agent': 'Mozilla/5.0 (RedVapt/2.0)',
        ...headers
    };
    if (cookieHeader) finalHeaders['Cookie'] = cookieHeader;

    const resp = await axios({
        url,
        method,
        params,
        data,
        headers: finalHeaders,
        timeout: 15_000,
        maxRedirects: 10, // R7: Follow redirects aggressively
        validateStatus: () => true,
    });

    const MAX_BODY = 200000;
    const body = (typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '')).slice(0, MAX_BODY);

    // R7: Update session with new cookies and extracted tokens
    globalSession.updateFromHeaders(resp.headers);
    globalSession.extractTokens(body);

    return {
        status: resp.status,
        headers: Object.fromEntries(Object.entries(resp.headers).slice(0, 30)),
        body,
        timing_ms: null,
    };
}

export async function executeFast({ url, method = 'GET', params = {}, data = null, headers = {} }) {
    const cookieHeader = globalSession.getCookieHeader();
    const finalHeaders = {
        'User-Agent': 'Mozilla/5.0 (RedVapt/2.0)',
        ...headers
    };
    if (cookieHeader) finalHeaders['Cookie'] = cookieHeader;

    const resp = await axios({
        url,
        method,
        params,
        data,
        headers: finalHeaders,
        timeout: 7_000, // 7s for triage (was 15s)
        maxRedirects: 3, // 3 hops for triage (was 10)
        validateStatus: () => true,
    });

    const body = (typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '')).slice(0, 50_000);
    globalSession.updateFromHeaders(resp.headers);
    globalSession.extractTokens(body);

    return {
        status: resp.status,
        headers: Object.fromEntries(Object.entries(resp.headers).slice(0, 30)),
        body,
        timing_ms: null
    };
}
