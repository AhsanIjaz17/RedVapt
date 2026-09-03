/**
 * paramDiscovery.js — RedVapt Parameter Discovery & Normalization
 *
 * This module consolidates parameters discovered from multiple sources:
 * - URL query parameters (GAU, Wayback)
 * - HTML Forms (DeepIntelligence, Crawler)
 * - JS-extracted endpoints
 *
 * It filters out static noise and prioritizes "attackable" parameters.
 */

import { cleanUrl } from './parsers.js';

/**
 * Extract parameters from a list of URLs and Forms.
 * Returns a deduplicated map of URL -> Set of parameters.
 */
export function discoverParameters(endpoints = [], forms = []) {
    const paramMap = new Map(); // URL -> Set of params

    // 1. Process URLs
    for (const ep of endpoints) {
        const rawUrl = typeof ep === 'string' ? ep : ep.url;
        const url = cleanUrl(rawUrl);
        if (!url) continue;

        try {
            const parsed = new URL(url);
            const base = `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`;
            const params = [...parsed.searchParams.keys()];

            if (params.length > 0) {
                if (!paramMap.has(base)) paramMap.set(base, new Set());
                params.forEach(p => paramMap.get(base).add(p));
            }
        } catch {
            continue;
        }
    }

    // 2. Process Forms
    for (const form of forms) {
        const action = cleanUrl(form.action);
        if (!action) continue;

        if (!paramMap.has(action)) paramMap.set(action, new Set());
        const inputs = Array.isArray(form.inputs) ? form.inputs : [];
        for (const input of inputs) {
            const name = typeof input === 'string' ? input : input.name;
            if (name) paramMap.get(action).add(name);
        }
    }

    // 3. Convert to structured array
    const results = [];
    for (const [url, params] of paramMap.entries()) {
        results.push({
            url,
            params: [...params].join(', '),
            param_count: params.size,
            source: 'ParamDiscovery'
        });
    }

    return results.sort((a, b) => b.param_count - a.param_count);
}

/**
 * Heuristic to identify high-value parameters (likely to interact with DB or shell).
 */
export function isHighValueParam(name) {
    const risky = ['id', 'user', 'email', 'file', 'path', 'url', 'search', 'query', 'cmd', 'exec', 'order', 'sort', 'page'];
    return risky.some(r => name.toLowerCase().includes(r));
}
