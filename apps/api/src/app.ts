import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import multer from 'multer';
import PinataClient from '@pinata/sdk';
import { Readable } from 'node:stream';
import authRoutes from './routes/auth';
import keyRoutes from './routes/keys';
import { requireAuth, type AuthReq } from './auth';

const app = express();
app.use(cors());
app.use(express.json());

export const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

app.use('/auth', authRoutes(pool));
app.use('/', keyRoutes(pool));

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 25 * 1024 * 1024 }
});

if (!process.env.PINATA_JWT) {
    console.warn('PINATA_JWT is not set. /api/upload will fail.');
}
const pinata = process.env.PINATA_JWT ? new PinataClient({ pinataJWTKey: process.env.PINATA_JWT }) : null;

app.post('/api/upload', requireAuth, upload.single('file'), async (req: AuthReq, res) => {
    try {
        if (!req.file) return res.status(400).json({ ok: false, error: 'No file provided' });
        if (!pinata) return res.status(500).json({ ok: false, error: 'Pinata not configured' });

        const { originalname, buffer, size } = req.file;

        const stream = new Readable();
        stream._read = () => {};
        stream.push(buffer);
        stream.push(null);

        const pinned = await pinata.pinFileToIPFS(stream, {
            pinataMetadata: { name: originalname },
            pinataOptions: { cidVersion: 1 }
        });
        const cid = pinned.IpfsHash;

        res.json({
            ok: true,
            provider: 'pinata',
            cid,
            path: cid,
            size,
            gatewayUrl: `https://gateway.pinata.cloud/ipfs/${cid}`,
        });
    } catch (e) {
        res.status(500).json({ ok: false, error: String(e) });
    }
});

app.post("/api/files/metadata", requireAuth, async (req: AuthReq, res) => {
    try {
        const {
            filename,
            mime,
            cid,
            cipher_iv_b64,
            wrapped_key_b64,
            cipher_sha256_b64,
        } = req.body ?? {};

        if (!filename || !cid || !cipher_iv_b64 || !wrapped_key_b64) {
            return res.status(400).json({ ok: false, error: "Missing fields" });
        }

        const { rows } = await pool.query(
            `INSERT INTO files (owner_id, filename, cid, file_hash, mime, cipher_iv, cipher_sha256)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, created_at
             `,
            [
                req.user!.id,
                filename,
                cid,
                cipher_sha256_b64 ?? null,
                mime ?? null,
                cipher_iv_b64,
                cipher_sha256_b64 ?? null,
            ]
        );

        const { id, created_at } = rows[0];
        await pool.query(
            `INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64)
             VALUES ($1, $2, $3)
             ON CONFLICT (file_id, user_id)
             DO UPDATE SET wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                 revoked_at = NULL`,
            [id, req.user!.id, wrapped_key_b64]
        );
        return res.json({ ok: true, fileId: id, createdAt: created_at });
    } catch (e: any) {
        console.error("metadata error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get("/api/files", requireAuth, async (req: AuthReq, res) => {
    try {
        const { rows } = await pool.query(
            `SELECT id, filename, cid, mime, created_at
             FROM files
             WHERE owner_id = $1
             ORDER BY created_at DESC`,
            [req.user!.id]
        );

        return res.json({ ok: true, files: rows });
    } catch (e: any) {
        console.error("list files error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get("/api/files/:fileId/access", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;

        const fileRes = await pool.query(
            `SELECT id, owner_id, filename, cid, mime, cipher_iv, cipher_sha256, created_at
             FROM files
             WHERE id = $1
                 LIMIT 1`,
            [fileId]
        );

        if (fileRes.rows.length === 0) {
            return res.status(404).json({ ok: false, error: "File not found" });
        }

        const file = fileRes.rows[0];
        const isOwner = file.owner_id === req.user!.id;

        const permRes = await pool.query(
            `SELECT wrapped_key_b64, revoked_at
             FROM file_permissions
             WHERE file_id = $1 AND user_id = $2
             LIMIT 1`,
            [fileId, req.user!.id]
        );

        if (!isOwner) {
            if (permRes.rows.length === 0) {
                return res.status(403).json({ ok: false, error: "Not authorised" });
            }
            if (permRes.rows[0].revoked_at) {
                return res.status(403).json({ ok: false, error: "Access revoked" });
            }
        }

        let wrapped_key_b64: string | null = null;

        if (permRes.rows.length > 0) {
            if (permRes.rows[0].revoked_at) {
                return res.status(403).json({ ok: false, error: "Access revoked" });
            }
            wrapped_key_b64 = permRes.rows[0].wrapped_key_b64;
        } else {
            const fallback = await pool.query(
                `SELECT wrapped_key
                 FROM files
                 WHERE id = $1
                 LIMIT 1`,
                [fileId]
            );
            wrapped_key_b64 = fallback.rows[0]?.wrapped_key ?? null;
        }

        if (!wrapped_key_b64) {
            return res.status(500).json({ ok: false, error: "Missing wrapped key for this file" });
        }

        return res.json({
            ok: true,
            file: {
                id: file.id,
                filename: file.filename,
                cid: file.cid,
                mime: file.mime,
                created_at: file.created_at,
                cipher_iv_b64: file.cipher_iv,
                cipher_sha256_b64: file.cipher_sha256 ?? null,
                wrapped_key_b64,
            },
        });
    } catch (e: any) {
        console.error("file access error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get("/api/users/public-key", requireAuth, async (req: AuthReq, res) => {
    try {
        const email = String(req.query.email || "").trim().toLowerCase();
        if (!email) return res.status(400).json({ ok: false, error: "Missing email" });

        const { rows } = await pool.query(
            `SELECT id, public_key
             FROM users
             WHERE lower(email) = $1
             LIMIT 1`,
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ ok: false, error: "User not found" });
        }

        return res.json({
            ok: true,
            userId: rows[0].id,
            publicKey: rows[0].public_key,
        });
    } catch (e: any) {
        console.error("public-key lookup error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.post("/api/files/:fileId/share", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;
        const { recipientUserId, wrapped_key_b64 } = req.body ?? {};

        if (!recipientUserId || !wrapped_key_b64) {
            return res.status(400).json({ ok: false, error: "Missing recipientUserId or wrapped_key_b64" });
        }

        const ownerCheck = await pool.query(
            `SELECT owner_id
             FROM files
             WHERE id = $1 
             LIMIT 1`,
            [fileId]
        );
        if (ownerCheck.rows.length === 0) {
            return res.status(404).json({ ok: false, error: "File not found" });
        }
        if (ownerCheck.rows[0].owner_id !== req.user!.id) {
            return res.status(403).json({ ok: false, error: "Only the owner can share this file" });
        }

        const userCheck = await pool.query(
            `SELECT id 
             FROM users 
             WHERE id = $1 
             LIMIT 1`,
            [recipientUserId]
        );
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ ok: false, error: "User not found" });
        }

        await pool.query(
            `INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64)
             VALUES ($1, $2, $3)
             ON CONFLICT (file_id, user_id)
             DO UPDATE SET wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                     revoked_at = NULL`,
            [fileId, recipientUserId, wrapped_key_b64]
        );

        return res.json({ ok: true });
    } catch (e: any) {
        console.error("share error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get("/api/files/shared-with-me", requireAuth, async (req: AuthReq, res) => {
    try {
        const { rows } = await pool.query(
            `SELECT f.id, f.filename, f.cid, f.mime, f.created_at, u.email AS owner_email
             FROM file_permissions fp
                 JOIN files f ON f.id = fp.file_id
                 JOIN users u ON u.id = f.owner_id
             WHERE fp.user_id = $1
               AND fp.revoked_at IS NULL
               AND f.owner_id <> $1
             ORDER BY f.created_at DESC;`,
            [req.user!.id]
        );

        return res.json({ ok: true, files: rows });
    } catch (e: any) {
        console.error("shared-with-me error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get('/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ ok: false, error: String(e) });
    }
});

export default app;
