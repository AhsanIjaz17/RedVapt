import pool from '../../utils/pg.js';
import config from '../../config/env.js';

export const getMyWorkspaces = async (req, res) => {
    try {
        const userId = req.user.userId;
        const workspacesRes = await pool.query(
            `SELECT w.*, wm.role 
       FROM workspaces w 
       JOIN workspace_members wm ON w.id = wm.workspace_id 
       WHERE wm.user_id = $1`,
            [userId]
        );
        res.json(workspacesRes.rows);
    } catch (error) {
        console.error('[Workspace] List error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const createWorkspace = async (req, res) => {
    try {
        const { name } = req.body;
        const userId = req.user.userId;

        if (!name) return res.status(400).json({ error: 'Workspace name is required' });

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const workspaceRes = await client.query(
                'INSERT INTO workspaces (name, owner_user_id) VALUES ($1, $2) RETURNING id, name',
                [name, userId]
            );
            const workspace = workspaceRes.rows[0];

            await client.query(
                'INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3)',
                [workspace.id, userId, 'owner']
            );

            await client.query('COMMIT');
            res.status(201).json(workspace);
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('[Workspace] Create error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
