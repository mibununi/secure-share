import { pool } from "./app";

export async function resetDb() {
    await pool.query('DELETE FROM audit_logs;');
    await pool.query('DELETE FROM shares;');
    await pool.query('DELETE FROM files;');
    await pool.query('DELETE FROM users;');
}

export async function closeDb() {
    await pool.end();
}