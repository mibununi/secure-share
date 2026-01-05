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
            `INSERT INTO files (owner_id, filename, cid, file_hash, mime, cipher_iv, wrapped_key, cipher_sha256)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, created_at
             `,
            [
                req.user!.id,
                filename,
                cid,
                cipher_sha256_b64 ?? null,
                mime ?? null,
                cipher_iv_b64,
                wrapped_key_b64,
                cipher_sha256_b64 ?? null,
            ]
        );

        const { id, created_at } = rows[0];
        return res.json({ ok: true, fileId: id, createdAt: created_at });
    } catch (e: any) {
        console.error("metadata error:", e);
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
