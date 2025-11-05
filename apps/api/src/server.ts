import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
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

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});