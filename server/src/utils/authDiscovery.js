/**
 * authDiscovery.js — Safe Pre-Scan Authentication Discovery (Production Version)
 *
 * Goal:
 *   Establish a valid session BEFORE scanning, without brute forcing.
 *
 * Safe Behavior:
 *   - Only attempts credentials for known intentionally vulnerable demo apps
 *   - Only attempts if fingerprints match
 *   - Does NOT attempt generic defaults (admin/admin etc.)
 *   - Verification must succeed (no fake "assume valid")
 */

import axios from 'axios';

const HTTP = axios.create({
  timeout: 10_000,
  validateStatus: () => true,
  maxRedirects: 5,
  headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) RedVapt/2.0' },
});

/**
 * Demo credential sets for intentionally vulnerable apps ONLY.
 * These are official public accounts, not real-world brute forcing.
 */
const DEMO_CREDENTIAL_SETS = {
  JUICE_SHOP: [
    { email: 'admin@juice-sh.op', password: 'admin123', type: 'admin' },
    { email: 'jim@juice-sh.op', password: 'ncc-1701', type: 'user' },
    { email: 'bender@juice-sh.op', password: 'OhG0dPlease', type: 'user' },
  ],
  DVWA: [
    { username: 'admin', password: 'password', type: 'admin' },
  ],
  WEBGOAT: [
    { username: 'guest', password: 'guest', type: 'user' },
  ],
};

/**
 * Extract auth token from response
 * Supports:
 *  - Set-Cookie
 *  - JSON token fields
 *  - nested authentication.token (Juice Shop)
 */
function extractTokenFromResponse(resp) {
  const result = {
    cookie: null,
    bearer: null,
    tokenField: null,
  };

  const setCookie = resp.headers?.['set-cookie'];
  if (setCookie) {
    const cookieParts = Array.isArray(setCookie) ? setCookie : [setCookie];
    result.cookie = cookieParts.map(c => c.split(';')[0]).join('; ');
  }

  if (resp.data && typeof resp.data === 'object') {
    const data = resp.data;

    const directFields = ['token', 'access_token', 'accessToken', 'jwt', 'authToken', 'auth_token'];
    for (const field of directFields) {
      if (typeof data[field] === 'string' && data[field].length > 10) {
        result.bearer = data[field];
        result.tokenField = field;
        break;
      }
    }

    if (!result.bearer && typeof data.authentication?.token === 'string') {
      result.bearer = data.authentication.token;
      result.tokenField = 'authentication.token';
    }
  }

  return result;
}

export function buildAuthHeaders(session) {
  const headers = {};
  if (session?.cookie) headers['Cookie'] = session.cookie;
  if (session?.bearer) headers['Authorization'] = `Bearer ${session.bearer}`;
  return headers;
}

/**
 * fingerprintTarget — detect known demo platforms.
 * Returns: "JUICE_SHOP" | "DVWA" | "WEBGOAT" | null
 */
async function fingerprintTarget(baseUrl) {
  try {
    const resp = await HTTP.get(baseUrl, { timeout: 7000 });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

    if (/OWASP Juice Shop|juice[- ]shop|ctf\.js/i.test(body)) return 'JUICE_SHOP';
    if (/Damn Vulnerable Web Application|DVWA/i.test(body)) return 'DVWA';
    if (/WebGoat/i.test(body)) return 'WEBGOAT';

    const server = resp.headers?.server || '';
    if (/juice-shop/i.test(server)) return 'JUICE_SHOP';

    return null;
  } catch {
    return null;
  }
}

/**
 * discoverLoginEndpoints — discover login endpoints from recon data + common demo paths
 */
export async function discoverLoginEndpoints(baseUrl, reconData = {}) {
  const candidates = new Map();

  // From recon forms
  for (const form of (reconData.forms || [])) {
    const action = form.action || '';
    if (/login|signin|auth|session/i.test(action)) {
      const url = new URL(action, baseUrl).toString();
      candidates.set(url, { url, method: form.method || 'POST', contentType: 'form' });
    }
  }

  // From recon endpoints
  for (const ep of (reconData.endpoints || [])) {
    const url = typeof ep === 'string' ? ep : ep.url || '';
    if (!url) continue;
    if (/\/(login|signin|auth|session|token)\b/i.test(url)) {
      const full = url.startsWith('http') ? url : new URL(url, baseUrl).toString();
      candidates.set(full, { url: full, method: 'POST', contentType: 'json' });
    }
  }

  // Common demo login paths
  const COMMON_LOGIN_PATHS = [
    '/rest/user/login', // Juice Shop
    '/dvwa/login.php',  // DVWA
    '/WebGoat/login',   // WebGoat
    '/login',
    '/api/login',
    '/auth/login',
  ];

  await Promise.allSettled(
    COMMON_LOGIN_PATHS.map(async path => {
      try {
        const url = new URL(path, baseUrl).toString();
        const resp = await HTTP.get(url, { timeout: 4000 });
        if (resp.status !== 404 && resp.status !== 0) {
          candidates.set(url, { url, method: 'POST', contentType: 'json' });
        }
      } catch {}
    })
  );

  return [...candidates.values()];
}

/**
 * Detect whether login was successful.
 * Must confirm token/cookie OR redirect.
 */
function isSuccessLogin(resp) {
  if (!resp || !resp.status) return false;
  if (resp.status >= 400) return false;

  // Redirect after login is common
  if (resp.status === 302 || resp.status === 301) return true;

  const hasSetCookie = !!resp.headers?.['set-cookie'];
  if (hasSetCookie) return true;

  // If JSON response contains token-like keys
  if (resp.data && typeof resp.data === 'object') {
    const s = JSON.stringify(resp.data);
    if (/token|jwt|access_token|authentication/i.test(s)) return true;
  }

  return false;
}

/**
 * verifySession — must confirm auth works.
 * If cannot confirm, return false.
 */
async function verifySession(baseUrl, authHeaders) {
  const AUTH_CHECK_PATHS = [
    '/rest/user/whoami',   // Juice Shop
    '/api/Users',          // some APIs
    '/profile',
    '/dashboard',
    '/account',
    '/me',
  ];

  for (const path of AUTH_CHECK_PATHS) {
    try {
      const url = new URL(path, baseUrl).toString();
      const resp = await HTTP.get(url, { headers: authHeaders, timeout: 6000 });

      if (resp.status === 200) return true;
      if (resp.status === 401 || resp.status === 403) continue;
    } catch {}
  }

  return false;
}

/**
 * runAuthDiscovery — safe pre-scan auth discovery
 */
export async function runAuthDiscovery(baseUrl, reconData = {}, onProgress = () => {}) {
  const noAuth = {
    authenticated: false,
    cookie: null,
    bearer: null,
    loginUrl: null,
    userType: 'none',
    headers: {},
    credentials: null,
  };

  onProgress({ phase: 'auth_discovery', status: 'running', message: '🔐 Pre-scan auth discovery...' });

  // 1) fingerprint the target
  const fingerprint = await fingerprintTarget(baseUrl);
  if (!fingerprint) {
    onProgress({
      phase: 'auth_discovery',
      status: 'done',
      message: '🔐 No known demo platform detected — scanning as anonymous (safe mode)',
    });
    return noAuth;
  }

  const allowedCreds = DEMO_CREDENTIAL_SETS[fingerprint] || [];
  if (allowedCreds.length === 0) return noAuth;

  onProgress({
    phase: 'auth_discovery',
    status: 'running',
    message: `🔐 Detected ${fingerprint} — attempting safe demo authentication...`,
  });

  // 2) Discover login endpoints
  const loginEndpoints = await discoverLoginEndpoints(baseUrl, reconData);
  if (loginEndpoints.length === 0) {
    onProgress({ phase: 'auth_discovery', status: 'done', message: '🔐 No login endpoints found — scanning as anonymous' });
    return noAuth;
  }

  // 3) Try a limited number of endpoints + credentials
  for (const loginEp of loginEndpoints.slice(0, 3)) {
    for (const creds of allowedCreds.slice(0, 5)) {
      try {
        const jsonBody = {
          ...(creds.email ? { email: creds.email } : { username: creds.username }),
          password: creds.password,
        };

        const formBody = new URLSearchParams(jsonBody).toString();

        let resp = await HTTP.post(loginEp.url, jsonBody, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 8000,
        });

        if (!isSuccessLogin(resp)) {
          resp = await HTTP.post(loginEp.url, formBody, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 8000,
          });
        }

        if (!isSuccessLogin(resp)) continue;

        const tokens = extractTokenFromResponse(resp);
        if (!tokens.cookie && !tokens.bearer) continue;

        const authHeaders = buildAuthHeaders(tokens);

        const verified = await verifySession(baseUrl, authHeaders);
        if (!verified) continue;

        const session = {
          authenticated: true,
          cookie: tokens.cookie,
          bearer: tokens.bearer,
          tokenField: tokens.tokenField,
          loginUrl: loginEp.url,
          userType: creds.type || 'user',
          headers: authHeaders,
          credentials: { account: creds.email || creds.username, password: '[REDACTED]' },
        };

        onProgress({
          phase: 'auth_discovery',
          status: 'done',
          message: `✅ Auth established for ${fingerprint} using demo account (${session.userType})`,
        });

        return session;
      } catch {}
    }
  }

  onProgress({
    phase: 'auth_discovery',
    status: 'done',
    message: `🔐 Authentication failed for ${fingerprint} demo accounts — scanning anonymous`,
  });

  return noAuth;
}
