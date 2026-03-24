import { pool } from './db';

export async function resetDb() {
    await pool.query('DELETE FROM files;');
    await pool.query('DELETE FROM users;');
    await pool.query('DELETE FROM file_permissions;');
    await pool.query('DELETE FROM projects;');
    await pool.query('DELETE FROM project_members;');
}

export async function closeDb() {
    await pool.end();
}