import pool from './pg.js';

/**
 * persistScanToPostgres — Dumps in-memory SQLite results to Postgres.
 * Designed to be called at the end of a scan.
 *
 * @param {string} target
 * @param {object} scanDB - The SQLite scanDB object
 * @param {object} metadata - Optional scan metadata
 */
export async function persistScanToPostgres(target, scanDB, workspaceId, userId, metadata = {}) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Create Scan Entry
        const scanRes = await client.query(
            'INSERT INTO scans (target, status, workspace_id, created_by_user_id) VALUES ($1, $2, $3, $4) RETURNING id',
            [target, 'completed', workspaceId, userId]
        );
        const scanId = scanRes.rows[0].id;

        // 2. Persist Findings
        const findings = scanDB.queries.allFindings();
        for (const f of findings) {
            await client.query(
                `INSERT INTO findings (scan_id, workspace_id, category, severity, detail, source_tool)
         VALUES ($1, $2, $3, $4, $5, $6)`,
                [scanId, workspaceId, f.category, f.severity, f.detail, f.source_tool]
            );
        }

        // 3. Persist Graph (Optional but recommended)
        // If graphStore is using the same sqlite instance, we can pull from it.

        await client.query('COMMIT');
        console.log(`[Persistence] Successfully persisted scan ${scanId} for ${target} to PostgreSQL.`);
        return scanId;
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[Persistence] Failed to persist scan to PostgreSQL:', err.message);
        throw err;
    } finally {
        client.release();
    }
}
