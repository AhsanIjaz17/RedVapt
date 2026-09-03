// src/middleware/auth.middleware.js
import jwt from 'jsonwebtoken';
import config from '../config/env.js';
import * as workspaceService from '../services/workspace.service.js';

/**
 * Standard JWT Authentication Middleware
 */
export const requireAuth = (req, res, next) => {
    let token = null;
    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    } else if (req.query.token) {
        token = req.query.token;
    }

    if (!token) {
        return res.status(401).json({ error: 'Authorization token required' });
    }

    try {
        const decoded = jwt.verify(token, config.JWT_ACCESS_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

/**
 * Workspace Scoped Authorization Middleware
 */
export const requireWorkspaceMember = async (req, res, next) => {
    const { workspace_id } = req.params;
    const userId = req.user.userId;

    if (!workspace_id) {
        return res.status(400).json({ error: 'workspace_id is required' });
    }

    try {
        const isMember = await workspaceService.isWorkspaceMember(workspace_id, userId);
        if (!isMember) {
            return res.status(403).json({ error: 'Forbidden: You are not a member of this workspace' });
        }
        next();
    } catch (err) {
        console.error('[Auth Middleware] Workspace check error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};
