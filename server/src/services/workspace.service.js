// src/services/workspace.service.js
import prisma from '../utils/prisma.js';

export const createWorkspace = async (userId, name) => {
    return await prisma.workspace.create({
        data: {
            name,
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

export const getMyWorkspaces = async (userId) => {
    return await prisma.workspaceMember.findMany({
        where: { user_id: userId },
        include: {
            workspace: {
                select: {
                    id: true,
                    name: true,
                    created_at: true
                }
            }
        }
    });
};

export const isWorkspaceMember = async (workspaceId, userId) => {
    const membership = await prisma.workspaceMember.findUnique({
        where: {
            workspace_id_user_id: {
                workspace_id: workspaceId,
                user_id: userId
            }
        }
    });
    return !!membership;
};
