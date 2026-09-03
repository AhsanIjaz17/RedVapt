/**
 * mcpSessionClient.js — MCP Persistent JSON-RPC Client
 *
 * Keeps a single long-lived process per server to optimize speed and
 * maintain tool state/caching. Avoids repeatedly spawning Node processes.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

const CALL_TIMEOUT_MS = 60_000;
const VALID_SERVERS = new Set(['recon-server', 'jsintel-server', 'web-server', 'vuln-server']);

export class McpSessionClient {
    constructor(serverName) {
        if (!VALID_SERVERS.has(serverName)) {
            throw new Error(`McpSessionClient: unknown server "${serverName}"`);
        }
        this.serverName = serverName;
        this.serverPath = join(__dirname, '..', '..', 'engine', 'mcp', serverName, 'index.js');

        this.child = null;
        this.pendingRequests = new Map();
        this.resultCache = new Map(); // Simple caching per target/tool to save duplicate calls
        this.restartCount = 0;
        this.dead = false;
        this.stopped = false;

        this._startProcess();
    }

    _startProcess() {
        this.child = spawn(
            process.execPath,
            [this.serverPath],
            {
                stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env, MCP_SERVER_MODE: '1' }
            }
        );

        let stdoutBuf = '';
        this.child.stdout.on('data', (chunk) => {
            stdoutBuf += chunk.toString();
            let lines = stdoutBuf.split('\n');
            stdoutBuf = lines.pop(); // Keep the last incomplete line

            for (const line of lines) {
                if (!line.trim()) continue;
                try {
                    const parsed = JSON.parse(line);
                    if (parsed.id && this.pendingRequests.has(parsed.id)) {
                        const { resolve, reject, timer } = this.pendingRequests.get(parsed.id);
                        clearTimeout(timer);
                        this.pendingRequests.delete(parsed.id);

                        if (parsed.error) resolve({ success: false, error: parsed.error });
                        else resolve({ success: true, ...parsed.result });
                    }
                } catch (e) {
                    // ignore non-json
                }
            }
        });

        this.child.stderr.on('data', (chunk) => {
            console.error(`[${this.serverName} STDERR]: ${chunk.toString().slice(0, 200)}`);
        });

        this.child.on('close', () => {
            if (this.stopped) return;
            this.restartCount++;
            console.log(`[${this.serverName}] Process died. Restarting... (${this.restartCount}/3)`);
            for (const req of this.pendingRequests.values()) {
                clearTimeout(req.timer);
                req.resolve({ success: false, error: "Server Process closed unexpectedly" });
            }
            this.pendingRequests.clear();

            if (this.restartCount > 3) {
                console.error(`[${this.serverName}] FATAL: MCP Watchdog exceeded limits. Disabling wrapper.`);
                this.dead = true;
                return;
            }

            setTimeout(() => this._startProcess(), 1000);
        });
    }

    async call(toolName, params = {}, useCache = true) {
        if (this.dead) {
            return { success: false, error: "MCP Error: Dead Watchdog" };
        }
        // Caching optimization for idempotent reads
        const cacheKey = `${toolName}:${JSON.stringify(params)}`;
        if (useCache && this.resultCache.has(cacheKey)) {
            return this.resultCache.get(cacheKey);
        }

        const id = crypto.randomUUID();
        const request = JSON.stringify({
            jsonrpc: '2.0',
            id,
            method: 'tools/call',
            params: { name: toolName, arguments: params },
        });

        return new Promise((resolve) => {
            const timer = setTimeout(() => {
                this.pendingRequests.delete(id);
                resolve({ success: false, error: "MCP Session Call Timed Out" });
            }, CALL_TIMEOUT_MS);

            this.pendingRequests.set(id, { resolve, timer });

            this.child.stdin.write(request + '\n');
        }).then(res => {
            if (useCache && res.success) {
                this.resultCache.set(cacheKey, res);
            }
            return res;
        });
    }

    stop() {
        if (this.child) {
            this.stopped = true;
            this.child.kill('SIGTERM');
        }
    }
}

export async function mcpCall(serverName, toolName, params = {}) {
    const client = new McpSessionClient(serverName);
    const res = await client.call(toolName, params);
    client.stop();
    return res;
}
