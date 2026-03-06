import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import {pool} from "./db";
import multer from 'multer';
import PinataClient from '@pinata/sdk';
import {Readable} from 'node:stream';
import authRoutes from './routes/auth';
import keyRoutes from './routes/keys';
import {requireAuth, type AuthReq, type UserRole} from './auth';
import {getFilesLedger} from "./fabric/gateway";
import {FilesLedger} from "./fabric/filesLedger";
import {sha256B64, timingSafeEqualStr} from "./utils/crypto";
import { requireFileAccessOrOwner, HttpError } from "./utils/access";

let filesLedger: FilesLedger | null = null;

(async () => {
    try {
        filesLedger = await getFilesLedger(); // creates gateway + contract + wrapper
        console.log("Fabric ledger connected");
    } catch (e) {
        console.warn("Fabric ledger not connected:", e);
        filesLedger = null;
    }
})();

const app = express();
app.use(cors());
app.use(express.json());

app.use('/auth', authRoutes(pool));
app.use('/', keyRoutes(pool));

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {fileSize: 25 * 1024 * 1024}
});

if (!process.env.PINATA_JWT) {
    console.warn('PINATA_JWT is not set. /api/upload will fail.');
}
const pinata = process.env.PINATA_JWT ? new PinataClient({pinataJWTKey: process.env.PINATA_JWT}) : null;

function canShare(role: UserRole, isOwner: boolean) {
    if (role === "admin") return true;
    if (role === "manager") return true;
    return isOwner; // employee: only own
}

app.post('/api/upload', requireAuth, upload.single('file'), async (req: AuthReq, res) => {
    try {
        if (!req.file) return res.status(400).json({ok: false, error: 'No file provided'});
        if (!pinata) return res.status(500).json({ok: false, error: 'Pinata not configured'});

        const {originalname, buffer, size} = req.file;

        const stream = new Readable();
        stream._read = () => {
        };
        stream.push(buffer);
        stream.push(null);

        const pinned = await pinata.pinFileToIPFS(stream, {
            pinataMetadata: {name: originalname},
            pinataOptions: {cidVersion: 1}
        });
        const cid = pinned.IpfsHash;

        res.json({
            ok: true,
            provider: 'pinata',
            cid,
            path: cid,
            size,
            gatewayUrl: `https://ipfs.io/ipfs/${cid}`,
        });
    } catch (e) {
        res.status(500).json({ok: false, error: String(e)});
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

        if (!filename || !cid || !cipher_iv_b64 || !wrapped_key_b64 || !cipher_sha256_b64) {
            return res.status(400).json({ok: false, error: "Missing fields"});
        }

        const {rows} = await pool.query(
            `INSERT INTO files (owner_id, filename, cid, file_hash, mime, cipher_iv, cipher_sha256)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at
            `,
            [
                req.user!.id,
                filename,
                cid,
                cipher_sha256_b64,
                mime ?? null,
                cipher_iv_b64,
                cipher_sha256_b64,
            ]
        );

        const {id, created_at} = rows[0];

        if (filesLedger) {
            try {
                await filesLedger.createFile(
                    String(id),                 // fileId on ledger
                    String(req.user!.id),       // ownerId
                    String(cid),                // cid
                    String(cipher_sha256_b64),  // hash
                    new Date(created_at).toISOString()
                );
            } catch (e) {
                console.error("fabric CreateFile failed:", e);
                return res.status(503).json({ok: false, error: "Blockchain write failed"});
            }
        }

        await pool.query(
            `INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
                 DO
            UPDATE SET wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                revoked_at = NULL,
                granted_by_user_id = EXCLUDED.granted_by_user_id`,
            [id, req.user!.id, wrapped_key_b64, req.user!.id]
        );
        return res.json({ok: true, fileId: id, createdAt: created_at});
    } catch (e: any) {
        console.error("metadata error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/files", requireAuth, async (req: AuthReq, res) => {
    try {
        const {rows} = await pool.query(
            `SELECT id, filename, cid, mime, created_at
             FROM files
             WHERE owner_id = $1
             ORDER BY created_at DESC`,
            [req.user!.id]
        );

        return res.json({ok: true, files: rows});
    } catch (e: any) {
        console.error("list files error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/files/:fileId/access", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;

        const fileRes = await pool.query(
            `SELECT id,
                    owner_id,
                    filename,
                    cid,
                    mime,
                    cipher_iv,
                    cipher_sha256,
                    created_at
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );

        if (fileRes.rows.length === 0) {
            return res.status(404).json({ok: false, error: "File not found"});
        }

        const file = fileRes.rows[0];
        const isOwner = file.owner_id === req.user!.id;

        // Fabric enforcement
        await requireFileAccessOrOwner({
            filesLedger,
            fileId: String(fileId),
            ownerId: String(file.owner_id),
            userId: String(req.user!.id),
        });

        const permRes = await pool.query(
            `SELECT wrapped_key_b64
             FROM file_permissions
             WHERE file_id = $1
               AND user_id = $2
               AND revoked_at IS NULL LIMIT 1`,
            [fileId, req.user!.id]
        );

        if (permRes.rows.length === 0) {
            return res.status(isOwner ? 500 : 403).json({
                ok: false,
                error: isOwner ? "Owner permission record missing" : "Not authorised",
            });
        }

        const wrapped_key_b64 = permRes.rows[0].wrapped_key_b64;

        if (!wrapped_key_b64) {
            return res.status(500).json({ok: false, error: "Missing wrapped key for this file"});
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
        if (e instanceof HttpError) {
            return res.status(e.status).json({ ok: false, error: e.message });
        }
        console.error("... error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get("/api/files/:fileId/permissions", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;

        const fileRes = await pool.query(
            `SELECT owner_id
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );
        if (fileRes.rows.length === 0) return res.status(404).json({ok: false, error: "File not found"});

        const ownerId = fileRes.rows[0].owner_id;
        const isOwner = ownerId === req.user!.id;

        const hasActiveAccessRes = await pool.query(
            `SELECT 1
             FROM file_permissions
             WHERE file_id = $1
               AND user_id = $2
               AND revoked_at IS NULL LIMIT 1`,
            [fileId, req.user!.id]
        );
        const hasActiveAccess = hasActiveAccessRes.rows.length > 0;

        const role = req.user!.role;

        const canView =
            role === "admin" ||
            (role === "manager" && (isOwner || hasActiveAccess));

        if (!canView) {
            return res.status(403).json({ok: false, error: "Not authorised to view access list"});
        }

        const {rows} = await pool.query(
            `SELECT u.id                AS user_id,
                    u.email,
                    u.role              AS user_role,
                    fp.revoked_at,
                    (u.id = f.owner_id) AS is_owner
             FROM file_permissions fp
                      JOIN users u ON u.id = fp.user_id
                      JOIN files f ON f.id = fp.file_id
             WHERE fp.file_id = $1
             ORDER BY u.email`,
            [fileId]
        );

        return res.json({ok: true, permissions: rows});
    } catch (e: any) {
        console.error("permissions list error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/users/public-key", requireAuth, async (req: AuthReq, res) => {
    try {
        const email = String(req.query.email || "").trim().toLowerCase();
        if (!email) return res.status(400).json({ok: false, error: "Missing email"});

        const {rows} = await pool.query(
            `SELECT id, public_key
             FROM users
             WHERE lower(email) = $1 LIMIT 1`,
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ok: false, error: "User not found"});
        }

        return res.json({
            ok: true,
            userId: rows[0].id,
            publicKey: rows[0].public_key,
        });
    } catch (e: any) {
        console.error("public-key lookup error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/files/:fileId/share", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;
        const {recipientUserId, wrapped_key_b64} = req.body ?? {};

        if (!recipientUserId || !wrapped_key_b64) {
            return res.status(400).json({ok: false, error: "Missing recipientUserId or wrapped_key_b64"});
        }

        const fileQ = await pool.query(
            `SELECT id, owner_id, cid, cipher_sha256, created_at
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );
        if (fileQ.rows.length === 0) return res.status(404).json({ok: false, error: "File not found"});

        const isOwner = fileQ.rows[0].owner_id === req.user!.id;
        if (!canShare(req.user!.role, isOwner)) {
            return res.status(403).json({ok: false, error: "Not authorised to share this file"});
        }

        const userCheck = await pool.query(`SELECT id
                                            FROM users
                                            WHERE id = $1 LIMIT 1`, [recipientUserId]);
        if (userCheck.rows.length === 0) return res.status(404).json({ok: false, error: "User not found"});

        await pool.query(
            `INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
                 DO
            UPDATE SET wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                revoked_at = NULL,
                granted_by_user_id = EXCLUDED.granted_by_user_id`,
            [fileId, recipientUserId, wrapped_key_b64, req.user!.id]
        );

        if (filesLedger) {
            const ownerId = String(fileQ.rows[0].owner_id);

            try {
                await filesLedger.getACL(String(fileId));
            } catch (err: any) {
                try {
                    await filesLedger.createFile(
                        String(fileId),
                        ownerId,
                        String(fileQ.rows[0].cid),
                        String(fileQ.rows[0].cipher_sha256),
                        new Date(fileQ.rows[0].created_at).toISOString()
                    );
                } catch (e) {
                    console.error("fabric CreateFile backfill failed:", e);
                    return res.status(503).json({ok: false, error: "Blockchain backfill failed"});
                }
            }
            await filesLedger.grantAccess(
                String(fileId),
                ownerId,
                String(recipientUserId),
                new Date().toISOString()
            );
        }

        return res.json({ok: true});
    } catch (e: any) {
        console.error("share error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/files/:fileId/revoke", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;
        const {recipientUserId} = req.body ?? {};
        if (!recipientUserId) return res.status(400).json({ok: false, error: "Missing recipientUserId"});

        // employees cannot revoke
        if (req.user!.role === "employee") {
            return res.status(403).json({ok: false, error: "Not authorised to revoke access"});
        }

        // must have access to the file to manage it
        const accessQ = await pool.query(
            `SELECT 1
             FROM file_permissions
             WHERE file_id = $1
               AND user_id = $2
               AND revoked_at IS NULL LIMIT 1`,
            [fileId, req.user!.id]
        );
        if (accessQ.rows.length === 0) {
            return res.status(403).json({ok: false, error: "Not authorised"});
        }

        // prevent revoking owner (or yourself)
        const fileQ = await pool.query(
            `SELECT id, owner_id, cid, cipher_sha256, created_at
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );
        if (fileQ.rows.length === 0) return res.status(404).json({ok: false, error: "File not found"});

        if (recipientUserId === req.user!.id) {
            return res.status(400).json({ok: false, error: "You cannot revoke yourself"});
        }

        // manager cannot revoke admins
        const targetRes = await pool.query(
            `SELECT role
             FROM users
             WHERE id = $1 LIMIT 1`,
            [recipientUserId]
        );
        if (targetRes.rows.length === 0) return res.status(404).json({ok: false, error: "User not found"});

        if (req.user!.role === "manager") {
            const target = await pool.query(`SELECT role
                                             FROM users
                                             WHERE id = $1 LIMIT 1`, [recipientUserId]);
            if (target.rows[0]?.role === "admin") {
                return res.status(403).json({ok: false, error: "Managers cannot revoke admins"});
            }
        }

        const result = await pool.query(
            `UPDATE file_permissions
             SET revoked_at = NOW()
             WHERE file_id = $1
               AND user_id = $2
               AND revoked_at IS NULL RETURNING file_id, user_id, revoked_at`,
            [fileId, recipientUserId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ok: false, error: "Permission not found or already revoked"});
        }

        if (filesLedger) {
            const ownerId = String(fileQ.rows[0].owner_id);

            // ensure ledger record exists
            try {
                await filesLedger.getACL(String(fileId));
            } catch {
                await filesLedger.createFile(
                    String(fileId),
                    ownerId,
                    String(fileQ.rows[0].cid),
                    String(fileQ.rows[0].cipher_sha256),
                    new Date(fileQ.rows[0].created_at).toISOString()
                );
            }

            await filesLedger.revokeAccess(
                String(fileId),
                ownerId,
                String(recipientUserId),
                new Date().toISOString()
            );
        }

        return res.json({ok: true});
    } catch (e: any) {
        console.error("revoke error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/files/shared-with-me", requireAuth, async (req: AuthReq, res) => {
    try {
        const {rows} = await pool.query(
            `SELECT f.id,
                    f.owner_id,
                    f.filename,
                    f.cid,
                    f.mime,
                    f.created_at,
                    owner.email  AS owner_email,
                    sharer.email AS shared_by_email
             FROM file_permissions fp
                      JOIN files f ON f.id = fp.file_id
                      JOIN users owner ON owner.id = f.owner_id
                      LEFT JOIN users sharer ON sharer.id = fp.granted_by_user_id
             WHERE fp.user_id = $1
               AND fp.revoked_at IS NULL
               AND f.owner_id <> $1
             ORDER BY f.created_at DESC;`,
            [req.user!.id]
        );

        return res.json({ok: true, files: rows});
    } catch (e: any) {
        console.error("shared-with-me error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/files/:fileId/audit", requireAuth, async (req: AuthReq, res) => {
    if (!filesLedger) return res.status(503).json({ok: false, error: "Fabric not available"});
    const audit = await filesLedger.getAudit(String(req.params.fileId));
    audit.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
    return res.json({ok: true, audit});
});

app.get("/api/files/:fileId/download", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = String(req.params.fileId);

        // Fetch file metadata from DB
        const fileRes = await pool.query(
            `SELECT id, owner_id, filename, cid, mime, cipher_sha256
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );

        if (fileRes.rows.length === 0) {
            return res.status(404).json({ok: false, error: "File not found"});
        }

        const file = fileRes.rows[0];
        const ownerId = String(file.owner_id);
        const userId = String(req.user!.id);

        // Authoritative access check via Fabric
        await requireFileAccessOrOwner({
            filesLedger,
            fileId,
            ownerId,
            userId,
        });

        // Download ciphertext from IPFS gateway
        const cid = String(file.cid);
        const url = `https://ipfs.io/ipfs/${cid}`;
        const r = await fetch(url);

        if (!r.ok) {
            return res.status(502).json({ok: false, error: "Failed to fetch from IPFS gateway"});
        }

        const buf = Buffer.from(await r.arrayBuffer());

        // Integrity verification (ciphertext hash)
        const expectedB64 = String(file.cipher_sha256 || "");
        const actualB64 = sha256B64(buf);

        if (!expectedB64 || !timingSafeEqualStr(actualB64, expectedB64)) {
            return res.status(409).json({
                ok: false,
                error: "Integrity verification failed. The stored file may be corrupted or tampered with.",
            });
        }

        // Return ciphertext
        res.setHeader("Content-Type", file.mime || "application/octet-stream");
        res.setHeader("Content-Disposition", `attachment; filename="${file.filename}"`);
        return res.send(buf);
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ ok: false, error: e.message });
        }
        console.error("... error:", e);
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

app.get('/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ok: true});
    } catch (e) {
        res.status(500).json({ok: false, error: String(e)});
    }
});

app.get("/api/fabric/ping", requireAuth, async (_req: AuthReq, res) => {
    if (!filesLedger) return res.status(503).json({ok: false, error: "Fabric not available"});
    const out = await filesLedger.ping();
    return res.json({ok: true, out});
});

export default app;