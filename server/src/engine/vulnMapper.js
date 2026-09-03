/**
 * vulnMapper.js — Vulnerability Intelligence Mapper
 * 
 * Maps scanner findings to CWE, OWASP, MITRE ATT&CK, and relevant CVEs using NVD API.
 * Uses LLM-assisted ranking for CVE relevance.
 */

import axios from 'axios';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { callLLM } from './llm/llmRouter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CACHE_FILE = path.join(__dirname, '../../data/cache/nvd_cache.json');
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// ── Static Mapping Table ──────────────────────────────────────────────────────

const STATIC_MAPPINGS = {
    'SQL Injection': {
        cwe: [{ id: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command (\'SQL Injection\')', url: 'https://cwe.mitre.org/data/definitions/89.html' }],
        owasp: [{ id: 'A03:2021', name: 'Injection' }],
        mitre_attack: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }]
    },
    'XSS': {
        cwe: [{ id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')', url: 'https://cwe.mitre.org/data/definitions/79.html' }],
        owasp: [{ id: 'A03:2021', name: 'Injection' }],
        mitre_attack: [{ id: 'T1059.007', name: 'Command and Scripting Interpreter: JavaScript', tactic: 'Execution' }]
    },
    'SSTI': {
        cwe: [{ id: 'CWE-1336', name: 'Improper Neutralization of Special Elements Used in a Template Engine', url: 'https://cwe.mitre.org/data/definitions/1336.html' }],
        owasp: [{ id: 'A03:2021', name: 'Injection' }],
        mitre_attack: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }]
    },
    'LFI': {
        cwe: [{ id: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')', url: 'https://cwe.mitre.org/data/definitions/22.html' }],
        owasp: [{ id: 'A05:2021', name: 'Security Misconfiguration' }],
        mitre_attack: [{ id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' }]
    },
    'IDOR': {
        cwe: [{ id: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key', url: 'https://cwe.mitre.org/data/definitions/639.html' }],
        owasp: [{ id: 'A01:2021', name: 'Broken Access Control' }],
        mitre_attack: [{ id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' }]
    },
    'Directory Listing': {
        cwe: [{ id: 'CWE-548', name: 'Exposure of Information Through Directory Listing', url: 'https://cwe.mitre.org/data/definitions/548.html' }],
        owasp: [{ id: 'A05:2021', name: 'Security Misconfiguration' }],
        mitre_attack: [{ id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' }]
    },
    'Sensitive File Exposure': {
        cwe: [{ id: 'CWE-200', name: 'Exposure of Sensitive Information to an Unauthorized Actor', url: 'https://cwe.mitre.org/data/definitions/200.html' }],
        owasp: [{ id: 'A05:2021', name: 'Security Misconfiguration' }],
        mitre_attack: [{ id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' }]
    },
    'Auth Bypass': {
        cwe: [{ id: 'CWE-287', name: 'Improper Authentication', url: 'https://cwe.mitre.org/data/definitions/287.html' }],
        owasp: [{ id: 'A07:2021', name: 'Identification and Authentication Failures' }],
        mitre_attack: [{ id: 'T1556', name: 'Modify Authentication Process', tactic: 'Credential Access' }]
    }
};

// ── NVD API Integration ───────────────────────────────────────────────────────

let nvdCache = null;

async function loadCache() {
    if (nvdCache) return nvdCache;
    try {
        const data = await fs.readFile(CACHE_FILE, 'utf8');
        nvdCache = JSON.parse(data);
    } catch (err) {
        nvdCache = {};
    }
    return nvdCache;
}

async function saveCache() {
    if (!nvdCache) return;
    try {
        await fs.writeFile(CACHE_FILE, JSON.stringify(nvdCache, null, 2), 'utf8');
    } catch (err) {
        console.error('[vulnMapper] Failed to save cache:', err.message);
    }
}

/**
 * queryNvd — Search NVD for CVEs based on keyword (product + version).
 */
export async function queryNvd(keyword) {
    if (!keyword) return [];
    
    const cache = await loadCache();
    if (cache[keyword]) {
        console.log(`[vulnMapper] NVD Cache hit for: ${keyword}`);
        return cache[keyword];
    }

    console.log(`[vulnMapper] Querying NVD for: ${keyword}`);
    
    let retries = 3;
    let delay = 2000;

    while (retries > 0) {
        try {
            const response = await axios.get(NVD_API_URL, {
                params: { keywordSearch: keyword },
                timeout: 10000,
                headers: { 'User-Agent': 'RedVapt-Security-Scanner' }
            });

            const vulnerabilities = response.data?.vulnerabilities || [];
            const cves = vulnerabilities.map(v => {
                const cve = v.cve;
                const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
                return {
                    cveId: cve.id,
                    score: metrics?.cvssData?.baseScore || 0,
                    description: cve.descriptions.find(d => d.lang === 'en')?.value || 'No description',
                    references: (cve.references || []).map(r => r.url)
                };
            });

            // Filter for high quality results
            const filteredCves = cves.filter(c => c.score > 4.0).slice(0, 10);
            
            cache[keyword] = filteredCves;
            await saveCache();
            return filteredCves;

        } catch (err) {
            if (err.response?.status === 429) {
                console.warn(`[vulnMapper] NVD Rate limit (429). Retrying in ${delay}ms...`);
                await new Promise(res => setTimeout(res, delay));
                delay *= 2;
                retries--;
            } else {
                console.error(`[vulnMapper] NVD API error: ${err.message}`);
                return [];
            }
        }
    }
    return [];
}

/**
 * rankCves — Use LLM (Claude Haiku) to rank CVEs based on finding relevance.
 */
async function rankCves(finding, cves) {
    if (!cves || cves.length === 0) return [];

    const prompt = `You are a vulnerability intelligence assistant.

Given:
1) A confirmed vulnerability finding (type, endpoint, payload, evidence)
2) A list of CVEs returned from NVD search

Your task:
- Select the CVEs that are most relevant to this finding.
- If none match, return an empty list.
- You must not hallucinate.
- Only select CVEs that explicitly match the detected technology/version if present.
- Output STRICT JSON.

Finding:
${JSON.stringify(finding, null, 2)}

CVE List:
${JSON.stringify(cves, null, 2)}

Return JSON:
{
  "relevant": [
    {
      "cveId": "...",
      "reason": "...",
      "matchConfidence": 0.0-1.0
    }
  ],
  "notes": "..."
}`;

    const result = await callLLM({
        messages: [{ role: 'system', content: 'You are a cybersecurity expert specializing in vulnerability mapping.' }, { role: 'user', content: prompt }],
        jsonMode: true,
        max_tokens: 1000
    });

    if (result.success && result.output) {
        try {
            const parsed = JSON.parse(result.output);
            return parsed.relevant || [];
        } catch (err) {
            console.error('[vulnMapper] LLM ranking parse error:', err.message);
        }
    }
    return [];
}

/**
 * mapFinding — Main entry point for mapping a finding.
 */
export async function mapFinding(finding, techInfo = {}) {
    const { type, endpoint, parameter, payload, evidence } = finding;
    const { server, framework, libraries = [] } = techInfo;

    // 1. Static Mapping
    const mapping = STATIC_MAPPINGS[type] || {
        cwe: [],
        owasp: [],
        mitre_attack: []
    };

    // 2. Identify Technology for CVE Search
    const searchKeywords = [];
    // Only search if the technology string contains numbers (indicating a version).
    // Generic strings like "Modern Web Stack" or "Express" will be ignored to prevent false CVE mappings.
    const hasVersion = (str) => /\d/.test(str || '');

    if (server && hasVersion(server)) searchKeywords.push(server);
    if (framework && hasVersion(framework)) searchKeywords.push(framework);
    libraries.forEach(l => { if (hasVersion(l)) searchKeywords.push(l); });

    let allCves = [];
    for (const kw of searchKeywords) {
        const cves = await queryNvd(kw);
        allCves.push(...cves);
    }

    // Deduplicate by CVE ID
    const uniqueCves = Array.from(new Map(allCves.map(c => [c.cveId, c])).values());

    // 3. LLM-Assisted Ranking
    let relevantCves = [];
    if (uniqueCves.length > 0) {
        relevantCves = await rankCves(finding, uniqueCves);
    }

    return {
        ...mapping,
        cve_candidates: relevantCves,
        mappingConfidence: mapping.cwe.length > 0 ? 1.0 : 0.5,
        mappingMethod: relevantCves.length > 0 ? 'llm_assisted' : 'static_rules'
    };
}
