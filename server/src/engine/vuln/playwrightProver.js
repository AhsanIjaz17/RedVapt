/**
 * playwrightProver.js — Visual Proof Capture for Confirmed Vulnerabilities
 *
 * Captures screenshots ONLY for CONFIRMED vulnerabilities.
 * Produces professional evidence: baseline vs exploited state.
 *
 * Supports:
 *  - XSS (alert proof)
 *  - IDOR (auth vs anon comparison)
 *  - SQLi auth bypass (post-login page proof)
 *  - Directory listing / sensitive file exposure
 *  - Open redirect (redirect destination proof)
 */

import fs from "fs";
import path from "path";
import { chromium } from "playwright";

const EVIDENCE_DIR = path.join(process.cwd(), "data", "evidence");
const TIMEOUT = 15_000;

function ensureEvidenceDir() {
  if (!fs.existsSync(EVIDENCE_DIR)) {
    fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  }
}

function safeName(str) {
  return str.replace(/[^a-z0-9]/gi, "_").slice(0, 120);
}

// Lazy chromium module to prevent crashes on unsupported systems
let _chromiumModule = null;

async function getChromium() {
  if (!_chromiumModule) {
    try {
      const pw = await import("playwright");
      _chromiumModule = pw.chromium;
    } catch {
      return null;
    }
  }
  return _chromiumModule;
}

export async function isPlaywrightAvailable() {
  try {
    const browserType = await getChromium();
    if (!browserType) return false;
    const execPath = browserType.executablePath();
    return !!execPath;
  } catch {
    return false;
  }
}

async function launch() {
  const browserType = await getChromium();
  if (!browserType) throw new Error("Playwright is not available");
  return await browserType.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
  });
}

/**
 * Save screenshot safely
 */
async function saveShot(page, filename) {
  const filePath = path.join(EVIDENCE_DIR, filename);
  await page.screenshot({ path: filePath, fullPage: true });
  return filePath;
}

/**
 * ───────────────────────────────────────────────────────────────
 * XSS PROOF
 * ───────────────────────────────────────────────────────────────
 */
/** Native alert() is not painted in headless Chromium screenshots — inject a visible overlay with the dialog text as proof. */
async function injectXssExecutionOverlay(page, dialogMessage) {
  await page.evaluate((m) => {
    const old = document.getElementById("rvpt-xss-proof-overlay");
    if (old) old.remove();

    const root = document.createElement("div");
    root.id = "rvpt-xss-proof-overlay";
    Object.assign(root.style, {
      position: "fixed",
      inset: "0",
      background: "rgba(0,0,0,0.85)",
      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "system-ui,sans-serif",
    });

    const card = document.createElement("div");
    Object.assign(card.style, {
      background: "#0f172a",
      color: "#f8fafc",
      padding: "28px 32px",
      borderRadius: "16px",
      maxWidth: "92vw",
      border: "3px solid #EE4344",
      boxShadow: "0 0 48px rgba(238,67,68,0.35)",
    });

    const h = document.createElement("div");
    h.textContent = "JavaScript execution confirmed";
    Object.assign(h.style, {
      fontSize: "11px",
      textTransform: "uppercase",
      letterSpacing: "0.18em",
      color: "#f87171",
      marginBottom: "10px",
    });

    const line = document.createElement("div");
    line.textContent = "Native alert() fired with message:";
    Object.assign(line.style, { fontSize: "15px", color: "#e2e8f0", marginBottom: "6px" });

    const pre = document.createElement("pre");
    pre.textContent = String(m ?? "");
    Object.assign(pre.style, {
      marginTop: "14px",
      padding: "14px",
      background: "#020617",
      borderRadius: "10px",
      color: "#4ade80",
      whiteSpace: "pre-wrap",
      wordBreak: "break-all",
      fontSize: "14px",
      fontFamily: "ui-monospace, monospace",
    });

    const foot = document.createElement("div");
    foot.textContent = "Represents XSS execution in the victim browser context.";
    Object.assign(foot.style, { marginTop: "12px", fontSize: "12px", color: "#94a3b8" });

    card.append(h, line, pre, foot);
    root.appendChild(card);
    document.body.appendChild(root);
  }, dialogMessage ?? "");
  await page.waitForTimeout(450);
}

export async function captureXssProof({ url, injectedUrl, vulnId, payloads = null }) {
  ensureEvidenceDir();
  const browser = await launch();

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    const baseFile = `${Date.now()}_${vulnId}_xss_baseline.png`;
    const exploitFile = `${Date.now()}_${vulnId}_xss_exploit.png`;

    await page.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT }).catch(() => {});
    const baselinePath = await saveShot(page, baseFile).catch(() => null);

    const proofToken = `RVPT_${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    const tryUrls = [];

    if (injectedUrl) tryUrls.push(injectedUrl);

    const payloadList = Array.isArray(payloads) && payloads.length > 0
      ? payloads
      : [
          '<script>alert(1)</script>',
          `"><img src=x onerror="document.title='${proofToken}'">`,
          `'><img src=x onerror="alert('${proofToken}')">`,
        ];

    for (const p of payloadList) {
      try {
        const u = new URL(injectedUrl || url);
        const param = [...u.searchParams.keys()][0] || "id";
        u.searchParams.set(param, p);
        tryUrls.push(u.toString());
      } catch {
        /* ignore malformed */
      }
    }

    let alertText = null;
    let confirmed = false;
    let exploitPath = null;
    let proofType = null;

    for (const targetUrl of [...new Set(tryUrls)].slice(0, 6)) {
      let dialogFired = false;

      const dialogHandler = async (dialog) => {
        try {
          alertText = dialog.message();
          dialogFired = true;
          confirmed = true;
          proofType = "dialog";
        } catch {
          /* ignore */
        }
        try {
          await dialog.dismiss();
        } catch {
          /* ignore */
        }
      };
      page.on("dialog", dialogHandler);

      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: TIMEOUT }).catch(() => {});
      await page.waitForTimeout(2200);
      page.off("dialog", dialogHandler);

      if (dialogFired) {
        try {
          await injectXssExecutionOverlay(page, alertText);
          exploitPath = path.join(EVIDENCE_DIR, exploitFile);
          await page.screenshot({ path: exploitPath, fullPage: true });
        } catch {
          /* ignore */
        }
        break;
      }

      try {
        const title = await page.title();
        if (title && title.includes(proofToken)) {
          confirmed = true;
          proofType = "document_title";
          alertText = `document.title=${title}`;
          await injectXssExecutionOverlay(page, alertText);
          exploitPath = path.join(EVIDENCE_DIR, exploitFile);
          await page.screenshot({ path: exploitPath, fullPage: true });
          break;
        }
      } catch {
        /* ignore */
      }
    }

    await context.close();

    return {
      confirmed,
      vulnType: "XSS",
      alertText: alertText || (proofType === "document_title" ? "title-change proof" : null),
      proofType,
      screenshots: confirmed
        ? { baseline: baselinePath, exploit: exploitPath }
        : { baseline: baselinePath, exploit: null },
    };
  } catch (err) {
    return { confirmed: false, error: err.message };
  } finally {
    await browser.close();
  }
}

/**
 * ───────────────────────────────────────────────────────────────
 * IDOR PROOF (Auth vs Anon screenshots)
 * ───────────────────────────────────────────────────────────────
 */
export async function captureIdorProof({ url, authCookies = [], vulnId }) {
  ensureEvidenceDir();
  const browser = await launch();

  try {
    // Auth context
    const authContext = await browser.newContext({ ignoreHTTPSErrors: true });
    if (authCookies.length > 0) await authContext.addCookies(authCookies);

    const authPage = await authContext.newPage();
    await authPage.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT });
    await authPage.waitForTimeout(1500);

    const authPath = await saveShot(authPage, `${Date.now()}_${vulnId}_idor_auth.png`);
    const authText = await authPage.evaluate(() => document.body.innerText.slice(0, 500));
    await authContext.close();

    // Anonymous context
    const anonContext = await browser.newContext({ ignoreHTTPSErrors: true });
    const anonPage = await anonContext.newPage();
    await anonPage.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT });
    await anonPage.waitForTimeout(1500);

    const anonPath = await saveShot(anonPage, `${Date.now()}_${vulnId}_idor_anon.png`);
    const anonText = await anonPage.evaluate(() => document.body.innerText.slice(0, 500));
    await anonContext.close();

    // Simple similarity check
    const confirmed = anonText.length > 200 && Math.abs(authText.length - anonText.length) < 200;

    return {
      confirmed,
      vulnType: "IDOR",
      screenshots: { auth: authPath, anon: anonPath },
      evidence: {
        authPreview: authText,
        anonPreview: anonText,
      },
    };
  } catch (err) {
    return { confirmed: false, error: err.message };
  } finally {
    await browser.close();
  }
}

/**
 * ───────────────────────────────────────────────────────────────
 * SQLi AUTH BYPASS PROOF
 * ───────────────────────────────────────────────────────────────
 */
export async function captureSqliAuthBypassProof({
  loginUrl,
  usernamePayload,
  passwordPayload,
  vulnId,
}) {
  ensureEvidenceDir();
  const browser = await launch();

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    await page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: TIMEOUT }).catch(() => {});

    // Fill login fields (generic selectors)
    const userSelectors = [
      'input[name="uid"]',
      'input[name="username"]',
      'input[name="user"]',
      'input[type="text"]',
    ];

    const passSelectors = [
      'input[name="passw"]',
      'input[name="password"]',
      'input[type="password"]',
    ];

    let filledUser = false;
    for (const sel of userSelectors) {
      try {
        await page.fill(sel, usernamePayload);
        filledUser = true;
        break;
      } catch {}
    }

    let filledPass = false;
    for (const sel of passSelectors) {
      try {
        await page.fill(sel, passwordPayload);
        filledPass = true;
        break;
      } catch {}
    }

    if (!filledUser || !filledPass) {
      await context.close();
      return { confirmed: false, error: "Could not locate login fields" };
    }

    // Screenshot 1: credentials entered (before submit) — pentest-style evidence
    const credsFile = `${Date.now()}_${vulnId}_credentials_entered.png`;
    const credentialsEnteredPath = await saveShot(page, credsFile);

    // Submit — prefer the banking login form (Altoro exposes a search form with its own submit first).
    const submitSelectors = [
      'form#login input[type="submit"]',
      'form[name="login"] input[type="submit"]',
      '#login input[type="submit"]',
      'input[type="submit"][name="btnSubmit"]',
      'input[type="submit"]',
      'button[type="submit"]',
    ];
    let clicked = false;
    for (const sel of submitSelectors) {
      const handle = await page.$(sel);
      if (!handle) continue;
      try {
        await handle.click();
        clicked = true;
        break;
      } catch {
        /* try next */
      }
    }
    if (!clicked) await page.keyboard.press("Enter");

    await Promise.race([
      page.waitForURL(/bank\/main|main\.jsp|account|logout\.jsp/i, { timeout: 12_000 }).catch(() => null),
      page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 12_000 }).catch(() => null),
    ]);
    await page.waitForTimeout(900);

    // Screenshot 2: post-login / authenticated view
    const sessionFile = `${Date.now()}_${vulnId}_post_login.png`;
    const postLoginPath = await saveShot(page, sessionFile);

    const bodyText = (await page.evaluate(() => document.body.innerText.toLowerCase())) || "";
    const urlNow = page.url().toLowerCase();
    const urlLooksAuth = /main\.jsp|bank\/main|logout\.jsp|account\.jsp/i.test(urlNow);

    const confirmed =
      urlLooksAuth ||
      bodyText.includes("logout") ||
      bodyText.includes("welcome") ||
      bodyText.includes("my account") ||
      bodyText.includes("sign out") ||
      bodyText.includes("sign off") ||
      bodyText.includes("dashboard") ||
      bodyText.includes("hello admin") ||
      bodyText.includes("admin user") ||
      bodyText.includes("administration") ||
      bodyText.includes("edit users") ||
      bodyText.includes("bank account") ||
      bodyText.includes("account summary") ||
      bodyText.includes("main.jsp");

    await context.close();

    return {
      confirmed,
      vulnType: "SQLi Auth Bypass",
      screenshots: {
        credentials_entered: credentialsEnteredPath,
        post_login: postLoginPath,
      },
      evidence: bodyText.slice(0, 500),
    };
  } catch (err) {
    return { confirmed: false, error: err.message };
  } finally {
    await browser.close();
  }
}

/**
 * ───────────────────────────────────────────────────────────────
 * DIRECTORY LISTING / SENSITIVE FILE PROOF
 * ───────────────────────────────────────────────────────────────
 */
export async function captureDirectoryListingProof({ url, vulnId }) {
  ensureEvidenceDir();
  const browser = await launch();

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    await page.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT });
    await page.waitForTimeout(1500);

    const bodyText = await page.evaluate(() => document.body.innerText);
    const confirmed =
      bodyText.includes("Index of /") ||
      bodyText.includes("Parent Directory") ||
      bodyText.includes("Directory listing");

    if (!confirmed) {
      await context.close();
      return { confirmed: false };
    }

    const shot = await saveShot(page, `${Date.now()}_${vulnId}_dir_listing.png`);
    await context.close();

    return {
      confirmed: true,
      vulnType: "Directory Listing",
      screenshots: { listing: shot },
      evidence: bodyText.slice(0, 500),
    };
  } catch (err) {
    return { confirmed: false, error: err.message };
  } finally {
    await browser.close();
  }
}

/**
 * ───────────────────────────────────────────────────────────────
 * OPEN REDIRECT PROOF
 * ───────────────────────────────────────────────────────────────
 */
export async function captureOpenRedirectProof({ injectedUrl, vulnId }) {
  ensureEvidenceDir();
  const browser = await launch();

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    await page.goto(injectedUrl, { waitUntil: "domcontentloaded", timeout: TIMEOUT });
    await page.waitForTimeout(2000);

    const finalUrl = page.url();
    const shot = await saveShot(page, `${Date.now()}_${vulnId}_redirect.png`);

    // Confirm redirect if URL changed domain
    const confirmed = !finalUrl.includes(new URL(injectedUrl).hostname);

    await context.close();

    return {
      confirmed,
      vulnType: "Open Redirect",
      screenshots: { redirect: shot },
      finalUrl,
    };
  } catch (err) {
    return { confirmed: false, error: err.message };
  } finally {
    await browser.close();
  }
}
