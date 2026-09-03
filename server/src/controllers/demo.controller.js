// src/controllers/demo.controller.js
import { z } from 'zod';
import prisma from '../utils/prisma.js';

const demoSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    company: z.string().min(2),
    preferred_date: z.string().transform((str) => new Date(str)),
    message: z.string().max(500).optional(),
});

export const bookDemo = async (req, res) => {
    try {
        const data = demoSchema.parse(req.body);

        const request = await prisma.demoRequest.create({
            data: {
                ...data,
                ip_address: req.ip,
                user_agent: req.headers['user-agent']
            }
        });

        res.status(201).json({
            message: 'Demo request received successfully. We will contact you soon.',
            requestId: request.id
        });
    } catch (err) {
        if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors });
        console.error('[Demo] Booking error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};
