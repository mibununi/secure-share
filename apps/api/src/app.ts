import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import {pool} from "./db";
import multer from 'multer';
import PinataClient from '@pinata/sdk';
import {Readable} from 'node:stream';
import authRoutes from './routes/auth';
import keyRoutes from './routes/keys';
import {requireAuth, type AuthReq} from './auth';
import {getFilesLedger} from "./fabric/gateway";
import {FilesLedger} from "./fabric/filesLedger";
import {sha256B64, timingSafeEqualStr} from "./utils/crypto";
import {requireFileAccessOrOwner, HttpError} from "./utils/access";

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

type ProjectRole = "admin" | "manager" | "employee";

type WrappedKeyInput = {
    userId: string;
    wrapped_key_b64: string;
};

async function getProjectMember(projectId: string, userId: string) {
    const q = await pool.query(
        `SELECT project_id, user_id, role
         FROM project_members
         WHERE project_id = $1
           AND user_id = $2 LIMIT 1`,
        [projectId, userId]
    );
    return q.rows[0] ?? null;
}

async function getProjectRole(projectId: string, userId: string): Promise<ProjectRole | null> {
    const row = await getProjectMember(projectId, userId);
    return (row?.role as ProjectRole | undefined) ?? null;
}

async function requireProjectExists(projectId: string) {
    const q = await pool.query(
        `SELECT id
         FROM projects
         WHERE id = $1`,
        [projectId]
    );

    if (q.rows.length === 0) {
        throw new HttpError(404, "Project not found");
    }

    return q.rows[0];
}

async function requireProjectMembership(projectId: string, userId: string): Promise<ProjectRole> {
    await requireProjectExists(projectId);

    const role = await getProjectRole(projectId, userId);
    if (!role) {
        throw new HttpError(403, "Not a member of this project");
    }
    return role;
}

async function requireProjectAdmin(projectId: string, userId: string): Promise<void> {
    const role = await requireProjectMembership(projectId, userId);
    if (role !== "admin") {
        throw new HttpError(403, "Only project admins can perform this action");
    }
}

async function getProjectLeaders(projectId: string): Promise<Array<{ user_id: string; role: ProjectRole }>> {
    const q = await pool.query(
        `SELECT user_id, role
         FROM project_members
         WHERE project_id = $1
           AND role IN ('admin', 'manager')`,
        [projectId]
    );

    return q.rows as Array<{ user_id: string; role: ProjectRole }>;
}

async function upsertFilePermission(
    fileId: string,
    userId: string,
    wrappedKeyB64: string,
    grantedByUserId: string
) {
    await pool.query(
        `INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
         VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
         DO
        UPDATE SET
            wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
            revoked_at = NULL,
            granted_by_user_id = EXCLUDED.granted_by_user_id`,
        [fileId, userId, wrappedKeyB64, grantedByUserId]
    );
}

function normaliseWrappedKeys(input: unknown): WrappedKeyInput[] {
    if (!Array.isArray(input)) return [];

    return input
        .map((item: any) => ({
            userId: String(item?.userId || "").trim(),
            wrapped_key_b64: String(item?.wrapped_key_b64 || "").trim(),
        }))
        .filter((item) => item.userId && item.wrapped_key_b64);
}

function uniqueUserIds(items: Array<{ userId: string }>): string[] {
    return [...new Set(items.map((x) => x.userId))];
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

app.post("/api/projects", requireAuth, async (req: AuthReq, res) => {
    try {
        const name = String(req.body?.name || "").trim();
        if (!name) {
            return res.status(400).json({ok: false, error: "Project name is required"});
        }

        const projectRes = await pool.query(
            `INSERT INTO projects (name)
             VALUES ($1) RETURNING id, name, created_at`,
            [name]
        );

        const project = projectRes.rows[0];

        await pool.query(
            `INSERT INTO project_members (project_id, user_id, role)
             VALUES ($1, $2, 'admin')`,
            [project.id, req.user!.id]
        );

        return res.status(201).json({ok: true, project});
    } catch (e: any) {
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/projects", requireAuth, async (req: AuthReq, res) => {
    try {
        const {rows} = await pool.query(
            `SELECT p.id, p.name, p.created_at, pm.role
             FROM project_members pm
                      JOIN projects p ON p.id = pm.project_id
             WHERE pm.user_id = $1
             ORDER BY p.created_at DESC`,
            [req.user!.id]
        );

        return res.json({ok: true, projects: rows});
    } catch (e: any) {
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/projects/:projectId", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        const role = await requireProjectMembership(projectId, req.user!.id);

        const q = await pool.query(
            `SELECT id, name, created_at
             FROM projects
             WHERE id = $1 LIMIT 1`,
            [projectId]
        );

        if (q.rows.length === 0) {
            return res.status(404).json({ok: false, error: "Project not found"});
        }

        return res.json({
            ok: true,
            project: {
                ...q.rows[0],
                role,
            }
        });
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/projects/:projectId/members", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        const {userId, role} = req.body ?? {};

        if (!userId || !role) {
            return res.status(400).json({ok: false, error: "Missing userId or role"});
        }

        if (!["manager", "employee"].includes(role)) {
            return res.status(400).json({ok: false, error: "Role must be manager or employee"});
        }

        await requireProjectAdmin(projectId, req.user!.id);

        const projectQ = await pool.query(
            `SELECT id
             FROM projects
             WHERE id = $1 LIMIT 1`,
            [projectId]
        );
        if (projectQ.rows.length === 0) {
            return res.status(404).json({ok: false, error: "Project not found"});
        }

        const userQ = await pool.query(
            `SELECT id
             FROM users
             WHERE id = $1 LIMIT 1`,
            [userId]
        );
        if (userQ.rows.length === 0) {
            return res.status(404).json({ok: false, error: "User not found"});
        }

        await pool.query(
            `INSERT INTO project_members (project_id, user_id, role)
             VALUES ($1, $2, $3) ON CONFLICT (project_id, user_id)
             DO
            UPDATE SET role = EXCLUDED.role`,
            [projectId, userId, role]
        );

        return res.json({ok: true});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/projects/:projectId/bootstrap-manager-access", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        const {userId, grants} = req.body ?? {};

        if (!userId || !Array.isArray(grants) || grants.length === 0) {
            return res.status(400).json({ok: false, error: "Missing userId or grants"});
        }

        await requireProjectAdmin(projectId, req.user!.id);

        const membershipQ = await pool.query(
            `SELECT role
             FROM project_members
             WHERE project_id = $1
               AND user_id = $2 LIMIT 1`,
            [projectId, userId]
        );

        if (membershipQ.rows.length === 0) {
            return res.status(404).json({ok: false, error: "Project member not found"});
        }

        if (membershipQ.rows[0].role !== "manager") {
            return res.status(400).json({ok: false, error: "Bootstrap access is only valid for managers"});
        }

        const parsedGrants = grants
            .map((g: any) => ({
                fileId: String(g?.fileId || "").trim(),
                wrapped_key_b64: String(g?.wrapped_key_b64 || "").trim(),
            }))
            .filter((g: any) => g.fileId && g.wrapped_key_b64);

        if (parsedGrants.length === 0) {
            return res.status(400).json({ok: false, error: "No valid grants supplied"});
        }

        const fileIds = [...new Set(parsedGrants.map((g: any) => g.fileId))];

        const filesQ = await pool.query(
            `SELECT id, owner_id, cid, cipher_sha256, created_at
             FROM files
             WHERE project_id = $1
               AND id = ANY ($2::uuid[])`,
            [projectId, fileIds]
        );

        const validFiles = new Map<string, any>();
        for (const row of filesQ.rows) {
            validFiles.set(String(row.id), row);
        }

        if (validFiles.size !== fileIds.length) {
            return res.status(400).json({ok: false, error: "One or more files do not belong to this project"});
        }

        for (const grant of parsedGrants) {
            await upsertFilePermission(
                grant.fileId,
                String(userId),
                grant.wrapped_key_b64,
                req.user!.id
            );

            if (filesLedger) {
                const file = validFiles.get(String(grant.fileId));

                try {
                    await filesLedger.getACL(String(grant.fileId));
                } catch {
                    await filesLedger.createFile(
                        String(grant.fileId),
                        String(file.owner_id),
                        String(file.cid),
                        String(file.cipher_sha256),
                        new Date(file.created_at).toISOString()
                    );
                }

                await filesLedger.grantAccess(
                    String(grant.fileId),
                    String(file.owner_id),
                    String(userId),
                    new Date().toISOString()
                );
            }
        }

        return res.json({ok: true, grantedCount: parsedGrants.length});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        console.error("bootstrap manager access error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/projects/:projectId/files-for-manager-bootstrap", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        const userId = String(req.query.userId || "").trim();

        if (!userId) {
            return res.status(400).json({ok: false, error: "Missing userId"});
        }

        await requireProjectAdmin(projectId, req.user!.id);

        const membershipQ = await pool.query(
            `SELECT role
             FROM project_members
             WHERE project_id = $1
               AND user_id = $2 LIMIT 1`,
            [projectId, userId]
        );

        if (membershipQ.rows.length === 0) {
            return res.status(404).json({ok: false, error: "Project member not found"});
        }

        if (membershipQ.rows[0].role !== "manager") {
            return res.status(400).json({ok: false, error: "Bootstrap listing is only valid for managers"});
        }

        const {rows} = await pool.query(
            `SELECT f.id, f.filename, f.owner_id, f.created_at
             FROM files f
             WHERE f.project_id = $1
             ORDER BY f.created_at DESC`,
            [projectId]
        );

        return res.json({ok: true, files: rows});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        console.error("files-for-manager-bootstrap error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/projects/:projectId/members", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        await requireProjectMembership(projectId, req.user!.id);

        const {rows} = await pool.query(
            `SELECT u.id AS user_id, u.email, pm.role
             FROM project_members pm
                      JOIN users u ON u.id = pm.user_id
             WHERE pm.project_id = $1
             ORDER BY u.email`,
            [projectId]
        );

        return res.json({ok: true, members: rows});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/projects/:projectId/revoke", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        const {userId} = req.body ?? {};

        if (!userId) {
            return res.status(400).json({ok: false, error: "Missing userId"});
        }

        await requireProjectAdmin(projectId, req.user!.id);

        if (userId === req.user!.id) {
            return res.status(400).json({ok: false, error: "You cannot remove yourself from the project"});
        }

        const projectQ = await pool.query(
            `SELECT id
             FROM projects
             WHERE id = $1 LIMIT 1`,
            [projectId]
        );
        if (projectQ.rows.length === 0) {
            return res.status(404).json({ok: false, error: "Project not found"});
        }

        const memberQ = await pool.query(
            `SELECT user_id, role
             FROM project_members
             WHERE project_id = $1
               AND user_id = $2 LIMIT 1`,
            [projectId, userId]
        );

        if (memberQ.rows.length === 0) {
            return res.status(404).json({ok: false, error: "Project member not found"});
        }

        if (memberQ.rows[0].role === "admin") {
            return res.status(403).json({ok: false, error: "Project admins cannot be removed"});
        }

        await pool.query(
            `DELETE
             FROM project_members
             WHERE project_id = $1
               AND user_id = $2`,
            [projectId, userId]
        );

        await pool.query(
            `UPDATE file_permissions fp
             SET revoked_at = NOW() FROM files f
             WHERE fp.file_id = f.id
               AND f.project_id = $1
               AND fp.user_id = $2
               AND fp.revoked_at IS NULL`,
            [projectId, userId]
        );

        return res.json({ok: true});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/files/metadata", requireAuth, async (req: AuthReq, res) => {
    try {
        const {
            filename,
            mime,
            cid,
            cipher_iv_b64,
            cipher_sha256_b64,
            projectId,
            wrapped_keys,
        } = req.body ?? {};

        if (!filename || !cid || !cipher_iv_b64 || !cipher_sha256_b64) {
            return res.status(400).json({ok: false, error: "Missing fields"});
        }

        const parsedWrappedKeys = normaliseWrappedKeys(wrapped_keys);
        if (parsedWrappedKeys.length === 0) {
            return res.status(400).json({ok: false, error: "wrapped_keys is required"});
        }

        let validatedProjectId: string | null = null;
        let expectedUserIds: string[] = [req.user!.id];

        if (projectId) {
            const projectRole = await requireProjectMembership(String(projectId), req.user!.id);
            if (!["admin", "manager", "employee"].includes(projectRole)) {
                return res.status(403).json({ok: false, error: "Not authorised for this project"});
            }

            validatedProjectId = String(projectId);

            const leaders = await getProjectLeaders(validatedProjectId);
            expectedUserIds = uniqueUserIds([
                {userId: req.user!.id},
                ...leaders.map((x) => ({userId: String(x.user_id)})),
            ]);
        }

        const providedUserIds = uniqueUserIds(parsedWrappedKeys);

        const missingUserIds = expectedUserIds.filter((id) => !providedUserIds.includes(id));
        if (missingUserIds.length > 0) {
            return res.status(400).json({
                ok: false,
                error: "Missing wrapped keys for required project recipients",
                missingUserIds,
            });
        }

        const unexpectedUserIds = providedUserIds.filter((id) => !expectedUserIds.includes(id));
        if (unexpectedUserIds.length > 0) {
            return res.status(400).json({
                ok: false,
                error: "wrapped_keys contains unexpected recipients",
                unexpectedUserIds,
            });
        }

        const {rows} = await pool.query(
            `INSERT INTO files (owner_id, filename, cid, mime, cipher_iv, cipher_sha256, project_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at`,
            [
                req.user!.id,
                filename,
                cid,
                mime ?? null,
                cipher_iv_b64,
                cipher_sha256_b64,
                validatedProjectId,
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

        for (const item of parsedWrappedKeys) {
            await upsertFilePermission(
                String(id),
                item.userId,
                item.wrapped_key_b64,
                req.user!.id
            );
        }
        return res.json({ok: true, fileId: id, createdAt: created_at});
    } catch (e: any) {
        console.error("metadata error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/files", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = String(req.query.projectId || "").trim();

        if (!projectId) {
            const {rows} = await pool.query(
                `SELECT id, filename, cid, mime, created_at, project_id
                 FROM files
                 WHERE owner_id = $1
                 ORDER BY created_at DESC`,
                [req.user!.id]
            );

            return res.json({ok: true, files: rows});
        }

        const projectRole = await requireProjectMembership(projectId, req.user!.id);

        let rows;
        if (projectRole === "admin" || projectRole === "manager") {
            const q = await pool.query(
                `SELECT f.id, f.filename, f.cid, f.mime, f.created_at, f.project_id, f.owner_id
                 FROM files f
                 WHERE f.project_id = $1
                 ORDER BY f.created_at DESC`,
                [projectId]
            );
            rows = q.rows;
        } else {
            const q = await pool.query(
                `SELECT DISTINCT f.id, f.filename, f.cid, f.mime, f.created_at, f.project_id, f.owner_id
                 FROM files f
                          LEFT JOIN file_permissions fp ON fp.file_id = f.id
                 WHERE f.project_id = $1
                   AND (
                     f.owner_id = $2
                         OR (fp.user_id = $2 AND fp.revoked_at IS NULL)
                     )
                 ORDER BY f.created_at DESC`,
                [projectId, req.user!.id]
            );
            rows = q.rows;
        }

        return res.json({ok: true, files: rows});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        console.error("list files error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/projects/:projectId/files", requireAuth, async (req: AuthReq, res) => {
    try {
        const projectId = req.params.projectId;
        const projectRole = await requireProjectMembership(projectId, req.user!.id);

        let rows;
        if (projectRole === "admin" || projectRole === "manager") {
            const q = await pool.query(
                `SELECT f.id, f.filename, f.cid, f.mime, f.created_at, f.owner_id, u.email AS owner_email
                 FROM files f
                          JOIN users u ON u.id = f.owner_id
                 WHERE f.project_id = $1
                 ORDER BY f.created_at DESC`,
                [projectId]
            );
            rows = q.rows;
        } else {
            const q = await pool.query(
                `SELECT DISTINCT f.id, f.filename, f.cid, f.mime, f.created_at, f.owner_id, u.email AS owner_email
                 FROM files f
                          JOIN users u ON u.id = f.owner_id
                          LEFT JOIN file_permissions fp ON fp.file_id = f.id
                 WHERE f.project_id = $1
                   AND (
                     f.owner_id = $2
                         OR (fp.user_id = $2 AND fp.revoked_at IS NULL)
                     )
                 ORDER BY f.created_at DESC`,
                [projectId, req.user!.id]
            );
            rows = q.rows;
        }

        return res.json({ok: true, files: rows, role: projectRole});
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
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
                    created_at,
                    project_id
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );

        if (fileRes.rows.length === 0) {
            return res.status(404).json({ok: false, error: "File not found"});
        }

        const file = fileRes.rows[0];
        const isOwner = file.owner_id === req.user!.id;

        if (file.project_id) {
            await requireProjectMembership(String(file.project_id), req.user!.id);
        }

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
                project_id: file.project_id ?? null,
            },
        });
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        console.error("file access error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.get("/api/files/:fileId/permissions", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;

        const fileRes = await pool.query(
            `SELECT id, owner_id, project_id
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );

        if (fileRes.rows.length === 0) {
            return res.status(404).json({ok: false, error: "File not found"});
        }

        const file = fileRes.rows[0];
        const isOwner = file.owner_id === req.user!.id;

        if (file.project_id) {
            const projectRole = await requireProjectMembership(String(file.project_id), req.user!.id);
            const canView = isOwner || projectRole === "admin" || projectRole === "manager";

            if (!canView) {
                return res.status(403).json({ok: false, error: "Not authorised to view access list"});
            }
        } else {
            if (!isOwner) {
                return res.status(403).json({ok: false, error: "Only the owner can view access list"});
            }
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
            `SELECT id, owner_id, project_id, cid, cipher_sha256, created_at
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );
        if (fileQ.rows.length === 0) return res.status(404).json({ok: false, error: "File not found"});

        const file = fileQ.rows[0];
        const isOwner = file.owner_id === req.user!.id;

        if (file.project_id) {
            const projectRole = await requireProjectMembership(String(file.project_id), req.user!.id);
            const allowed = isOwner || projectRole === "admin" || projectRole === "manager";

            if (!allowed) {
                return res.status(403).json({ok: false, error: "Not authorised to share this file"});
            }
        } else {
            if (!isOwner) {
                return res.status(403).json({ok: false, error: "Only the owner can share this file"});
            }
        }

        const userCheck = await pool.query(
            `SELECT id
             FROM users
             WHERE id = $1 LIMIT 1`,
            [recipientUserId]
        );
        if (userCheck.rows.length === 0) return res.status(404).json({ok: false, error: "User not found"});

        await pool.query(
            `INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
             DO
            UPDATE SET
                wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                revoked_at = NULL,
                granted_by_user_id = EXCLUDED.granted_by_user_id`,
            [fileId, recipientUserId, wrapped_key_b64, req.user!.id]
        );

        if (filesLedger) {
            const ownerId = String(file.owner_id);

            try {
                await filesLedger.getACL(String(fileId));
            } catch {
                await filesLedger.createFile(
                    String(fileId),
                    ownerId,
                    String(file.cid),
                    String(file.cipher_sha256),
                    new Date(file.created_at).toISOString()
                );
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
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
        console.error("share error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
    }
});

app.post("/api/files/:fileId/revoke", requireAuth, async (req: AuthReq, res) => {
    try {
        const fileId = req.params.fileId;
        const {recipientUserId} = req.body ?? {};
        if (!recipientUserId) return res.status(400).json({ok: false, error: "Missing recipientUserId"});

        const fileQ = await pool.query(
            `SELECT id, owner_id, project_id, cid, cipher_sha256, created_at
             FROM files
             WHERE id = $1 LIMIT 1`,
            [fileId]
        );
        if (fileQ.rows.length === 0) return res.status(404).json({ok: false, error: "File not found"});

        const file = fileQ.rows[0];
        const isOwner = file.owner_id === req.user!.id;

        if (recipientUserId === req.user!.id) {
            return res.status(400).json({ok: false, error: "You cannot revoke yourself"});
        }

        let allowed = false;

        if (file.project_id) {
            const projectRole = await requireProjectMembership(String(file.project_id), req.user!.id);
            allowed = isOwner || projectRole === "admin" || projectRole === "manager";
        } else {
            allowed = isOwner;
        }

        if (!allowed) {
            return res.status(403).json({ok: false, error: "Not authorised to revoke this file access"});
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
            const ownerId = String(file.owner_id);

            // ensure ledger record exists
            try {
                await filesLedger.getACL(String(fileId));
            } catch {
                await filesLedger.createFile(
                    String(fileId),
                    ownerId,
                    String(file.cid),
                    String(file.cipher_sha256),
                    new Date(file.created_at).toISOString()
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
        if (e instanceof HttpError) {
            return res.status(e.status).json({ok: false, error: e.message});
        }
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
                    f.project_id,
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
            `SELECT id, owner_id, filename, cid, mime, cipher_sha256, project_id
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

        if (file.project_id) {
            await requireProjectMembership(String(file.project_id), userId);
        }

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
            return res.status(e.status).json({ok: false, error: e.message});
        }
        console.error("download error:", e);
        return res.status(500).json({ok: false, error: String(e?.message || e)});
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