import dotenv from "dotenv";
dotenv.config({ path: ".env.test" });

import { pool } from './app';

afterAll(async () => {
    await pool.end();
});