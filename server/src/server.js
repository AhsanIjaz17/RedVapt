/**
 * server.js — RedVapt HTTP Server Entry Point
 *
 * Starts the Express HTTP server and boots the queue worker in-process.
 * Run with:  node src/server.js   (from the server/ directory)
 *
 * For high-throughput production use, run the worker separately:
 *   node src/queue/worker.js
 */

// Config must be the very first import so .env is loaded before anything else
import config from './config/env.js';
console.log("DATABASE_URL =", config.DATABASE_URL);
import app from './app.js';
import { initPostgres } from './utils/pg.js';

// Initialize Database
try {
    await initPostgres();
} catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
}

// ── Check Playwright & Auto-Disable if Missing ──────────────────────────────
if (config.ENABLE_BROWSER_PROOF) {
    try {
        const { chromium } = await import('playwright');
        const executablePath = chromium.executablePath(); // Throws if browsers are missing usually, or returns string.
        if (!executablePath) throw new Error("Missing binary");
    } catch (err) {
        console.warn(`\n⚠️  [Scanner] Playwright executables missing or un-runnable.`);
        console.warn(`⚠️  [Scanner] Disabling ENABLE_BROWSER_PROOF... static XSS validation will be used.`);
        console.warn(`⚠️  [Scanner] Run 'npx playwright install chromium' if you want full execution proofs.\n`);

        config.ENABLE_BROWSER_PROOF = false;
    }
}
// ── Start HTTP server ──────────────────────────────────────────────────────────
app.listen(config.PORT, () => {
    console.log(`\n🛡️  RedVapt Recon Server running on http://localhost:${config.PORT}`);
    console.log(`   Health check: http://localhost:${config.PORT}/api/health`);
    console.log(`   Enqueue scan: POST http://localhost:${config.PORT}/api/recon`);
    console.log(`   Stream:       GET  http://localhost:${config.PORT}/api/recon/:jobId/stream`);
    console.log(`   Reports:      GET  http://localhost:${config.PORT}/api/reports\n`);
});
