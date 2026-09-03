/**
 * utils/sessionManager.js — Scan Session & Cookie Persistence
 *
 * Maintains a "Cookie Jar" and tracks CSRF tokens discovered during crawling/probing.
 * Ensures the scanner stays "logged in" or maintains state during deep tests.
 */

export class SessionManager {
    constructor() {
        this.cookies = new Map(); // name -> value
        this.csrfTokens = new Set();
        this.authToken = null; // JWT or other Bearer token
        this._bearerToken = null; // Alias for authToken
        this._cookieString = null; // Manually set cookie string
        this.lastResponseHeaders = {};
    }

    /**
     * Parse Set-Cookie headers and update the jar.
     */
    updateFromHeaders(headers) {
        if (!headers) return;
        this.lastResponseHeaders = headers;

        const setCookie = headers['set-cookie'];
        if (Array.isArray(setCookie)) {
            setCookie.forEach(c => this.parseCookie(c));
        } else if (typeof setCookie === 'string') {
            this.parseCookie(setCookie);
        }
    }

    parseCookie(cookieStr) {
        const [pair] = cookieStr.split(';');
        const [name, value] = pair.split('=');
        if (name && value) {
            this.cookies.set(name.trim(), value.trim());
        }
    }

    /**
     * Get Cookie header string for requests.
     */
    getCookieHeader() {
        if (this._cookieString) return this._cookieString;
        if (this.cookies.size === 0) return '';
        return [...this.cookies.entries()]
            .map(([n, v]) => `${n}=${v}`)
            .join('; ');
    }

    /**
     * Get Authorization header if token exists.
     */
    getAuthHeader() {
        return this.authToken ? `Bearer ${this.authToken}` : null;
    }

    setAuthToken(token) {
        this.authToken = token;
        this._bearerToken = token;
        console.log('[SessionManager] Bearer token set');
    }

    setBearerToken(token) {
        this.setAuthToken(token);
    }

    setCookieString(cookie) {
        this._cookieString = cookie;
    }

    /**
     * Get all applicable auth headers for a request.
     */
    getAuthHeaders() {
        const h = {};
        const cookie = this.getCookieHeader();
        if (cookie) h['Cookie'] = cookie;
        
        const token = this.authToken || this._bearerToken;
        if (token) {
            h['Authorization'] = `Bearer ${token}`;
        }
        return h;
    }

    /**
     * Scan body for potential CSRF tokens (nonces, _csrf, etc) and JWTs.
     */
    extractTokens(body) {
        if (!body || typeof body !== 'string') return;

        // Common patterns for tokens in hidden inputs or meta tags
        const patterns = [
            /name=["'](?:_csrf|csrf_token|wp-nonce|authentication_token)["']\s+value=["']([^"']+)["']/i,
            /value=["']([^"']+)["']\s+name=["'](?:_csrf|csrf_token|wp-nonce|authentication_token)["']/i,
            /meta\s+name=["']csrf-token["']\s+content=["']([^"']+)["']/i
        ];

        for (const p of patterns) {
            const matches = body.match(p);
            if (matches && matches[1]) {
                this.csrfTokens.add(matches[1]);
            }
        }

        // Bug #4 FIX: Extract JWT from JSON response bodies
        // Juice Shop pattern: {"authentication":{"token":"eyJhbGci..."}}
        try {
            const json = JSON.parse(body);
            const token = json.authentication?.token || json.token || json.access_token || json.jwt;
            if (token && typeof token === 'string' && token.startsWith('eyJ')) {
                this.authToken = token;
                console.log(`[SessionManager] JWT extracted from JSON body: ${token.slice(0, 20)}...`);
            }
        } catch {
            // Not JSON or no token found
            const jwtMatch = body.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
            if (jwtMatch) {
                this.authToken = jwtMatch[0];
            }
        }
    }

    getLatestToken() {
        return [...this.csrfTokens].pop() || null;
    }
}

// Global session singleton for the current scan process
export const globalSession = new SessionManager();
