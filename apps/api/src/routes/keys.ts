import { Router } from 'express';
import { z } from 'zod';
import type { Pool } from 'pg';
import { requireAuth, AuthReq } from '../auth';

export default function keysRoutes(pool: Pool) {
    const r = Router();

    const schema = z.object({
        publicKey: z.string().min(20),
    });

    r.put('/keys/public', requireAuth, async (req: AuthReq, res) => {
        const parsed = schema.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ ok: false, error: parsed.error.flatten() });

        try {
            await pool.query(
                `UPDATE users SET public_key = $1 WHERE id = $2`,
                [parsed.data.publicKey, req.user!.id]
            );
            return res.json({ ok: true });
        } catch (e) {
            return res.status(500).json({ ok: false, error: String(e) });
        }
    });

    return r;
}