/**
 * paramMiner.js — Contextual Parameter Discovery
 * 
 * Mines hidden, contextual, and API-schema supplied parameters for a given endpoint.
 */

const LFI_PRIORITY_PARAMS = [
    { name: 'file', location: 'query', lfi_priority: true },
    { name: 'path', location: 'query', lfi_priority: true },
    { name: 'filename', location: 'query', lfi_priority: true },
    { name: 'doc', location: 'query', lfi_priority: true },
    { name: 'folder', location: 'query', lfi_priority: true }
];

const OPEN_REDIRECT_PARAMS = [
    { name: 'redirect', location: 'query', openredirect: true },
    { name: 'next', location: 'query', openredirect: true },
    { name: 'url', location: 'query', openredirect: true },
    { name: 'return', location: 'query', openredirect: true },
    { name: 'target', location: 'query', openredirect: true },
    { name: 'dest', location: 'query', openredirect: true }
];

export async function mineParameters(endpoint, method, techStack) {
    const params = new Map();

    // Source 1: URL query string
    try {
        const url = new URL(endpoint);
        url.searchParams.forEach((_, k) => params.set(k, { name: k, source: 'url', location: 'query' }));
    } catch { }

    // Source 2: Known parameter lists (context-aware)
    const contextParams = getContextualParams(endpoint, techStack);
    contextParams.forEach(p => {
        if (!params.has(p.name)) params.set(p.name, { ...p, source: 'contextual' });
    });

    // Source 3: API schema (if swagger found)
    if (techStack?.swagger?.paths?.[endpoint]) {
        const schema = techStack.swagger.paths[endpoint];
        (schema.parameters || []).forEach(p => {
            if (!params.has(p.name)) params.set(p.name, { name: p.name, source: 'swagger', location: p.in || 'query' });
        });
    }

    return [...params.values()];
}

export function getContextualParams(endpoint, techStack) {
    const path = endpoint.toLowerCase();
    const params = [];

    if (/search|query|find|filter/.test(path)) params.push(
        { name: 'q', location: 'query' },
        { name: 'search', location: 'query' },
        { name: 'keyword', location: 'query' },
        { name: 'term', location: 'query' },
    );
    if (/user|account|profile|dashboard/.test(path)) params.push(
        { name: 'id', location: 'query' },
        { name: 'userId', location: 'query' },
        { name: 'uid', location: 'query' },
    );
    if (/file|download|read|include|export|load|content|page|template|view|module|layout/i.test(path)) {
        params.push(...LFI_PRIORITY_PARAMS);
    }
    if (/redirect|return|next|back|login|auth/.test(path)) {
        params.push(...OPEN_REDIRECT_PARAMS);
    }

    return params;
}
