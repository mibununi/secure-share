import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import multer from 'multer';
import PinataClient from '@pinata/sdk';
import {Readable} from "node:stream";
import authRoutes from './routes/auth';
import keyRoutes from './routes/keys';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 4000);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use('/auth', authRoutes(pool));
app.use('/', keyRoutes(pool));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
});

if (!process.env.PINATA_JWT) {
    console.warn('PINATA_JWT is not set. /api/upload will fail.');
}
const pinata = new PinataClient({ pinataJWTKey: process.env.PINATA_JWT! });

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

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'No file provided' });

    const { originalname, mimetype, buffer, size } = req.file;
    const filename = (req.body.filename as string) || originalname;
    const fileHash = (req.body.hash as string) || '';
    const ownerId = "7d0c134f-9b56-459d-b3bb-7e0ef08ca9a4"; //temp - change after auth impl

    const stream = new Readable();
    stream._read = () => {};
    stream.push(buffer);
    stream.push(null);

    const pinned = await pinata.pinFileToIPFS(stream, {
    pinataMetadata: { name: filename },
    pinataOptions: { cidVersion: 1 },
    });
    const cid = pinned.IpfsHash;

    const rec = await insertFileRow({
      ownerId, filename, cid, fileHash, mime: mimetype
    });

    return res.json({
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
    console.error('Upload error:', e);
    return res.status(500).json({ ok: false, error: String(e) });
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

app.get('/users', async (_req, res) => {
  try {
    const result = await pool.query('SELECT id, email, created_at FROM users ORDER BY created_at DESC');
    res.json({ ok: true, users: result.rows });
  } catch (e) {
    console.error('Error fetching users: ', e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});