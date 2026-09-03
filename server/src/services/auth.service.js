// src/services/auth.service.js
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../utils/prisma.js';
import config from '../config/env.js';

/**
 * Generate Access and Refresh tokens
 */
export const generateTokens = (userId, role) => {
    // Align with refresh window so long scans and report views are not cut off mid-session.
    const accessToken = jwt.sign(
        { userId, role },
        config.JWT_ACCESS_SECRET,
        { expiresIn: '30d' }
    );

    const refreshToken = jwt.sign(
        { userId },
        config.JWT_REFRESH_SECRET,
        { expiresIn: '30d' }
    );

    return { accessToken, refreshToken };
};

/**
 * Hash password
 */
export const hashPassword = async (password) => {
    return await bcrypt.hash(password, 12);
};

/**
 * Compare password
 */
export const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

/**
 * Store refresh token in DB
 */
export const storeRefreshToken = async (userId, token) => {
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    // Hash token for storage
    const tokenHash = await bcrypt.hash(token, 10);

    return await prisma.refreshToken.create({
        data: {
            user_id: userId,
            token_hash: tokenHash,
            expires_at: expiresAt
        }
    });
};

/**
 * Sync Google User
 */
export const syncGoogleUser = async (profile) => {
    const { id, emails, displayName } = profile;
    const email = emails[0].value;

    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        // Create new user if not exists
        user = await prisma.user.create({
            data: {
                email,
                name: displayName,
                google_id: id,
                auth_provider: 'google',
                is_verified: true
            }
        });

        // Auto-create workspace
        await createDefaultWorkspace(user.id, user.name || user.email.split('@')[0]);
    } else if (!user.google_id) {
        // Link google ID if email matches but registered locally
        user = await prisma.user.update({
            where: { id: user.id },
            data: { google_id: id, auth_provider: 'google' }
        });
    }

    return user;
};

const createDefaultWorkspace = async (userId, name) => {
    return await prisma.workspace.create({
        data: {
            name: `${name}'s Workspace`,
            owner_user_id: userId,
            members: {
                create: {
                    user_id: userId,
                    role: 'owner'
                }
            }
        }
    });
};
