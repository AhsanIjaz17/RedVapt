/**
 * graph/graphStore.js — Recon Graph (SQLite-backed)
 *
 * Stores nodes and edges from the recon pipeline.
 * Node types: domain, subdomain, ip, host, port, endpoint,
 *             parameter, form, jsfile, technology, finding
 * Edge types: resolves_to, serves, discovered_by, has_param,
 *             loads_js, confirmed_vuln
 *
 * In-memory by default (':memory:'). Use GRAPH_DB_PATH env to persist.
 *
 * SECURITY: SQL uses parameterized binding — no injection surface.
 */

import Database from 'better-sqlite3';

const DB_PATH = process.env.GRAPH_DB_PATH || ':memory:';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS nodes (
    id       TEXT PRIMARY KEY,
    type     TEXT NOT NULL,
    data     JSON,
    score    REAL DEFAULT 0,
    created  INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS edges (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    src      TEXT NOT NULL,
    dst      TEXT NOT NULL,
    rel      TEXT NOT NULL,
    metadata JSON,
    created  INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(src, dst, rel)
);

CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_edges_src  ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst  ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_rel  ON edges(rel);
`;

export class GraphStore {
    /**
     * @param {string} [dbPath] - SQLite path or ':memory:'
     */
    constructor(dbPath = DB_PATH) {
        this.db = new Database(dbPath);
        this.db.pragma('journal_mode = WAL');
        this.db.exec(SCHEMA);
    }

    // ── Nodes ────────────────────────────────────────────────────────────────

    /**
     * Add or update a node.
     * @param {{ id: string, type: string, data?: object, score?: number }} node
     */
    addNode({ id, type, data = {}, score = 0 }) {
        if (!id || !type) throw new Error('addNode: id and type required');
        this.db.prepare(`
            INSERT INTO nodes (id, type, data, score)
            VALUES (?, ?, json(?), ?)
            ON CONFLICT(id) DO UPDATE SET
                data  = json(?),
                score = excluded.score
        `).run(id, type, JSON.stringify(data), score, JSON.stringify(data));
    }

    /** Get node by id. Returns null if not found. */
    getNode(id) {
        const row = this.db.prepare('SELECT * FROM nodes WHERE id = ?').get(id);
        if (!row) return null;
        return { ...row, data: JSON.parse(row.data || '{}') };
    }

    /** Get all nodes matching a type. */
    getNodesByType(type) {
        return this.db.prepare('SELECT * FROM nodes WHERE type = ?').all(type)
            .map(r => ({ ...r, data: JSON.parse(r.data || '{}') }));
    }

    /** Update score for a node. */
    setScore(id, score) {
        this.db.prepare('UPDATE nodes SET score = ? WHERE id = ?').run(score, id);
    }

    // ── Edges ────────────────────────────────────────────────────────────────

    /**
     * Add an edge (upsert).
     * @param {string} src - Source node id
     * @param {string} dst - Destination node id
     * @param {string} rel - Relationship type
     * @param {object} [metadata]
     */
    addEdge(src, dst, rel, metadata = {}) {
        if (!src || !dst || !rel) throw new Error('addEdge: src, dst, rel required');
        this.db.prepare(`
            INSERT INTO edges (src, dst, rel, metadata)
            VALUES (?, ?, ?, json(?))
            ON CONFLICT(src, dst, rel) DO NOTHING
        `).run(src, dst, rel, JSON.stringify(metadata));
    }

    /** Get all edges from a source node. */
    getEdgesFrom(src) {
        return this.db.prepare('SELECT * FROM edges WHERE src = ?').all(src)
            .map(r => ({ ...r, metadata: JSON.parse(r.metadata || '{}') }));
    }

    /** Get all edges to a destination node. */
    getEdgesTo(dst) {
        return this.db.prepare('SELECT * FROM edges WHERE dst = ?').all(dst)
            .map(r => ({ ...r, metadata: JSON.parse(r.metadata || '{}') }));
    }

    // ── Convenience builders ─────────────────────────────────────────────────

    /** Add a subdomain node and edge from domain. */
    addSubdomain(subdomain, parentDomain, data = {}) {
        this.addNode({ id: `subdomain:${subdomain}`, type: 'subdomain', data: { host: subdomain, ...data } });
        this.addNode({ id: `domain:${parentDomain}`, type: 'domain', data: { domain: parentDomain } });
        this.addEdge(`domain:${parentDomain}`, `subdomain:${subdomain}`, 'discovered_by');
    }

    /** Add an endpoint node and edge from host. */
    addEndpoint(url, host, data = {}) {
        this.addNode({ id: `endpoint:${url}`, type: 'endpoint', data: { url, ...data } });
        this.addEdge(`host:${host}`, `endpoint:${url}`, 'serves');
    }

    /** Add a parameter node and edge from endpoint. */
    addParameter(paramName, endpointUrl, data = {}) {
        const id = `param:${endpointUrl}#${paramName}`;
        this.addNode({ id, type: 'parameter', data: { name: paramName, endpoint: endpointUrl, ...data } });
        this.addEdge(`endpoint:${endpointUrl}`, id, 'has_param');
    }

    /** Add a finding node and edge from endpoint. */
    addFinding(finding) {
        const id = `finding:${finding.id || finding.type + '_' + Date.now()}`;
        this.addNode({ id, type: 'finding', data: finding, score: this._severityScore(finding.severity) });
        if (finding.endpoint) {
            this.addEdge(`endpoint:${finding.endpoint}`, id, 'confirmed_vuln');
        }
    }

    _severityScore(severity) {
        return { critical: 100, high: 75, medium: 50, low: 25, info: 5 }[severity?.toLowerCase()] || 0;
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /** Return top N endpoints by score. */
    getTopEndpoints(limit = 30) {
        return this.db.prepare(`
            SELECT * FROM nodes WHERE type = 'endpoint'
            ORDER BY score DESC LIMIT ?
        `).all(limit).map(r => ({ ...r, data: JSON.parse(r.data || '{}') }));
    }

    /** Return all confirmed findings. */
    getFindings() {
        return this.getNodesByType('finding');
    }

    /** Return graph summary stats. */
    stats() {
        const counts = {};
        const rows = this.db.prepare(`
            SELECT type, COUNT(*) as cnt FROM nodes GROUP BY type
        `).all();
        for (const r of rows) counts[r.type] = r.cnt;
        const edgeCount = this.db.prepare('SELECT COUNT(*) as cnt FROM edges').get().cnt;
        return { nodes: counts, edges: edgeCount };
    }

    close() {
        this.db.close();
    }
}
