/**
 * config/constants.js — Application-Wide Constants
 *
 * Hard-coded limits, names, and lookup tables that are NOT secrets
 * (don't belong in .env) but also shouldn't be scattered across files.
 */

// ── Recon Pipeline ────────────────────────────────────────────────────────────

export const RECON = Object.freeze({
    /** Max iterations for the ReAct exploitation loop */
    MAX_REACT_ITERATIONS: 25,
    /** Max JS files to run deep analysis on (LinkFinder) */
    MAX_JS_DEEP_ANALYSIS: 15,
    /** Max JS files forwarded to the agent */
    MAX_JS_FOR_AGENT: 20,
    /** Max pages the web crawler visits */
    CRAWLER_MAX_PAGES: 50,
    /** Max crawl depth */
    CRAWLER_MAX_DEPTH: 3,
    /** DNS batch size */
    DNS_BATCH_SIZE: 50,
    /** Valid hostname regex */
    HOSTNAME_RE: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
});

// ── Tool Timeouts (ms) ────────────────────────────────────────────────────────

export const TIMEOUTS = Object.freeze({
    /** Global scan watchdog (60 minutes) */
    GLOBAL_WATCHDOG_MS: 3_600_000,
    SUBFINDER: 180_000,
    SUBLIST3R: 180_000,
    ASSETFINDER: 120_000,
    CRTSH: 60_000,
    HTTPX: 120_000,
    WAFW00F: 60_000,
    WAPPALYZER: 90_000,
    NMAP: 300_000,
    SUBJS: 90_000,
    GETJS: 90_000,
    GAU: Number(process.env.TIMEOUT_GAU) || 300_000,
    WAYBACKURLS: Number(process.env.TIMEOUT_WAYBACKURLS) || 240_000,
    LINKFINDER: 60_000,
    PARAMSPIDER: 120_000,
    FFUF: Number(process.env.TIMEOUT_FFUF) || 300_000,
    DNS_RESOLVE: 5_000,
    BINARY_CHECK: 5_000,
    ARJUN: 240_000,

    NUCLEI: 300_000,
    GF: 30_000,
});

// ── LLM ───────────────────────────────────────────────────────────────────────

export const LLM = Object.freeze({
    /** Groq model fallback chain (ordered by capability → speed) */
    MODEL_FALLBACK_CHAIN: [
        'llama-3.3-70b-versatile',
        'llama3-70b-8192',
        'llama3-8b-8192',
        'gemma2-9b-it',
        'mixtral-8x7b-32768',
    ],
    /** Max tokens per LLM response */
    MAX_RESPONSE_TOKENS: 1500,
    /** Conservative token estimation ratio (chars per token) */
    CHARS_PER_TOKEN: 3.5,
    /** Groq token budget per minute */
    TOKENS_PER_MINUTE: 6000,
    /** Max LLM retries per call */
    MAX_RETRIES: 4,
});

// ── Queue ────────────────────────────────────────────────────────────────────

export const QUEUE = Object.freeze({
    RECON_QUEUE_NAME: 'recon-jobs',
    /** Job states */
    STATUS: {
        QUEUED: 'queued',
        RUNNING: 'running',
        DONE: 'done',
        FAILED: 'failed',
    },
    /** How long completed job data is kept in Redis (ms) */
    COMPLETED_TTL_MS: 24 * 60 * 60 * 1000,   // 24 h
    FAILED_TTL_MS: 7 * 24 * 60 * 60 * 1000,  //  7 d
});

// ── Security ─────────────────────────────────────────────────────────────────

export const SECURITY = Object.freeze({
    /** Max request body size */
    BODY_LIMIT: '1mb',
    /** Max query-string parameter length */
    MAX_TARGET_LENGTH: 253,
    /** SSE heartbeat interval (ms) */
    SSE_HEARTBEAT_MS: 15_000,
});

// ── Report ────────────────────────────────────────────────────────────────────

export const REPORT = Object.freeze({
    SCAN_TYPES: {
        RECON: 'Recon Scan',
        FULL: 'Full Security Assessment',
    },
});
