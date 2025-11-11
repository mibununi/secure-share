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

async function insertFileRow(params: {
    ownerId: string | null; filename: string; cid: string; fileHash?: string; mime?: string;
}) {
    const { ownerId, filename, cid, fileHash = '', mime = null as any } = params;
    const { rows } = await pool.query(
        `INSERT INTO files (owner_id, filename, cid, file_hash, mime)
         VALUES ($1,$2,$3,$4,$5)
             RETURNING id, created_at`,
        [ownerId, filename, cid, fileHash, mime]
    );
    return rows[0];
}

app.post('/api/upload', requireAuth, upload.single('file'), async (req: AuthReq, res) => {
    try {
        if (!req.file) return res.status(400).json({ ok: false, error: 'No file provided' });
        if (!pinata) return res.status(500).json({ ok: false, error: 'Pinata not configured' });

        const { originalname, mimetype, buffer, size } = req.file;
        const filename = (req.body.filename as string) || originalname;
        const fileHash = (req.body.hash as string) || '';
        const ownerId = req.user!.id;

        const stream = new Readable();
        stream._read = () => {};
        stream.push(buffer);
        stream.push(null);

        const pinned = await pinata.pinFileToIPFS(stream, {
            pinataMetadata: { name: originalname },
            pinataOptions: { cidVersion: 1 }
        });
        const cid = pinned.IpfsHash;

        const rec = await insertFileRow({
            ownerId, filename, cid, fileHash, mime: mimetype
        });

        res.json({
            ok: true,
            provider: 'pinata',
            fileId: rec.id,
            createdAt: rec.created_at,
            cid,
            path: cid,
            size,
            gatewayUrl: 'https://gateway.pinata.cloud/ipfs/${cid}',
        });
    } catch (e) {
        res.status(500).json({ ok: false, error: String(e) });
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
