import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../../utils/pg.js';
import config from '../../config/env.js';
import { z } from 'zod';

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string(),
});

export const register = async (req, res) => {
    try {
        const { email: cleanEmail, password } = registerSchema.parse(req.body);

        // Check if user exists
        const userCheck = await pool.query('SELECT id FROM users WHERE email = $1', [cleanEmail]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Create user
            const userRes = await client.query(
                'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
                [cleanEmail, hashedPassword]
            );
            const user = userRes.rows[0];
            user.email = cleanEmail;

            // Create default workspace
            const workspaceRes = await client.query(
                'INSERT INTO workspaces (name, owner_user_id) VALUES ($1, $2) RETURNING id',
                [`${cleanEmail.split('@')[0]}'s Workspace`, user.id]
            );
            const workspace = workspaceRes.rows[0];

            // Add user to workspace as owner
            await client.query(
                'INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3)',
                [workspace.id, user.id, 'owner']
            );

            await client.query('COMMIT');

            // TODO: Send verification email
            console.log(`[Auth] Verification link for ${cleanEmail}: http://localhost:3000/api/auth/verify?token=${user.id}`);

            res.status(201).json({
                message: 'Registration successful. Please verify your email.',
                user: { id: user.id, email: user.email }
            });
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        if (error instanceof z.ZodError) {
            const errorMessage = error.errors.map(err => err.message).join(', ');
            return res.status(400).json({ error: errorMessage });
        }
        console.error('[Auth] Register error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = loginSchema.parse(req.body);

        const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userRes.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.is_verified) {
            return res.status(403).json({ error: 'Please verify your email first' });
        }

        const accessToken = jwt.sign(
            { userId: user.id, role: user.role },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '30d' }
        );

        const refreshToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_REFRESH_SECRET || 'refresh_secret',
            { expiresIn: '30d' }
        );

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
    } catch (error) {
        if (error instanceof z.ZodError) {
            const errorMessage = error.errors.map(err => err.message).join(', ');
            return res.status(400).json({ error: errorMessage });
        }
        console.error('[Auth] Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const verifyEmail = async (req, res) => {
    try {
        const { token } = req.query; // Using userId as token for simplicity in demo
        if (!token) return res.status(400).json({ error: 'Missing token' });

        await pool.query('UPDATE users SET is_verified = true WHERE id = $1', [token]);
        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('[Auth] Verify error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
