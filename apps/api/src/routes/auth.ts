import { Router } from 'express';
import { z } from 'zod';
import type { Pool } from 'pg';
import { hashPassword, verifyPassword, signAccessToken, requireAuth, AuthReq } from '../auth';

export default function authRoutes(pool: Pool) {
    const r = Router();

    const creds = z.object({
        email: z.email(),
        password: z.string().min(8).max(128),
    });

    r.post('/register', async (req, res) => {
        const parsed = creds.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ ok: false, error: parsed.error.flatten() });

        const { email, password } = parsed.data;
        try {
            const pwHash = await hashPassword(password);
            const { rows } = await pool.query(
                `INSERT INTO users (email, password_hash)
                 VALUES ($1,$2)
                     ON CONFLICT (email) DO NOTHING
         RETURNING id, email, created_at`,
                [email, pwHash]
            );
            if (rows.length === 0) {
                return res.status(409).json({ ok: false, error: 'Email already registered' });
            }
            return res.status(201).json({ ok: true, user: rows[0] });
        } catch (e) {
            return res.status(500).json({ ok: false, error: String(e) });
        }
    });

    r.post('/login', async (req, res) => {
        const parsed = creds.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ ok: false, error: parsed.error.flatten() });

        const { email, password } = parsed.data;
        try {
            const q = await pool.query(
                `SELECT id, email, password_hash FROM users WHERE email = $1`,
                [email]
            );
            if (q.rowCount === 0) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

            const ok = await verifyPassword(q.rows[0].password_hash, password);
            if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

            const token = signAccessToken({ id: q.rows[0].id, email: q.rows[0].email });
            return res.json({ ok: true, token });
        } catch (e) {
            return res.status(500).json({ ok: false, error: String(e) });
        }
    });

    r.get('/me', requireAuth, async (req: AuthReq, res) => {
        try {
            const q = await pool.query(
                `SELECT id, email, public_key, created_at FROM users WHERE id = $1`,
                [req.user!.id]
            );
            return res.json({ ok: true, me: q.rows[0] });
        } catch (e) {
            return res.status(500).json({ ok: false, error: String(e) });
        }
    });

    return r;
}