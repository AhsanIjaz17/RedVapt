import { z } from 'zod';
import * as authService from '../services/auth.service.js';
import * as workspaceService from '../services/workspace.service.js';
import prisma from '../utils/prisma.js';
import config from '../config/env.js';

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8).regex(/[A-Z]/).regex(/[a-z]/).regex(/\d/).regex(/[^A-Za-z0-9]/),
    name: z.string().optional(),
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string(),
});

export const register = async (req, res) => {
    try {
        const { email, password, name } = registerSchema.parse(req.body);

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'Email already registered' });

        const hashedPassword = await authService.hashPassword(password);

        const user = await prisma.user.create({
            data: {
                email,
                password_hash: hashedPassword,
                name: name || email.split('@')[0],
                auth_provider: 'local'
            }
        });

        // Create Default Workspace
        const workspaceName = name ? `${name}'s Workspace` : 'My Workspace';
        const workspace = await workspaceService.createWorkspace(user.id, workspaceName);

        res.status(201).json({
            message: 'Registration successful',
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (err) {
        if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors });
        console.error('[Auth] Register error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = loginSchema.parse(req.body);

        const user = await prisma.user.findUnique({
            where: { email },
            include: { memberships: { take: 1, include: { workspace: true } } }
        });

        if (!user || !user.password_hash || !(await authService.comparePassword(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const { accessToken, refreshToken } = authService.generateTokens(user.id, 'user');
        await authService.storeRefreshToken(user.id, refreshToken);

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: config.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({
            accessToken,
            user: { id: user.id, email: user.email, name: user.name },
            workspaceId: user.memberships?.[0]?.workspace_id
        });
    } catch (err) {
        if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors });
        console.error('[Auth] Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const logout = async (req, res) => {
    const { refreshToken } = req.cookies;
    if (refreshToken) {
        // Logic to delete token hash from DB could be added here
        res.clearCookie('refreshToken');
    }
    res.json({ message: 'Logged out successfully' });
};
