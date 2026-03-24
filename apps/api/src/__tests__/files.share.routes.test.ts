import request from "supertest";
import app from "../app";
import {resetDb} from "../testUtils";
import {pool} from "../db";

beforeEach(async () => {
    await resetDb();
});

async function registerAndLogin(email: string, password = "password1234") {
    await request(app).post("/auth/register").send({email, password});

    const login = await request(app)
        .post("/auth/login")
        .send({email, password});

    const me = await request(app)
        .get("/auth/me")
        .set("Authorization", `Bearer ${login.body.token}`);

    return {
        token: login.body.token as string,
        userId: me.body.me.id as string,
        email,
        password,
    };
}

async function relogin(email: string, password = "password1234") {
    const login = await request(app)
        .post("/auth/login")
        .send({email, password});

    return login.body.token as string;
}

async function setUserRole(userId: string, role: "admin" | "manager" | "employee") {
    await pool.query(`UPDATE users
                      SET role = $1
                      WHERE id = $2`, [role, userId]);
}

async function createMetadata(
    token: string,
    overrides?: Partial<{
        filename: string;
        mime: string;
        cid: string;
        cipher_iv_b64: string;
        wrapped_key_b64: string;
        cipher_sha256_b64: string;
    }>
) {
    const payload = {
        filename: "doc.txt",
        mime: "text/plain",
        cid: `bafy-${Math.random().toString(36).slice(2)}`,
        cipher_iv_b64: "iv-b64",
        wrapped_key_b64: "owner-wrapped-key-b64",
        cipher_sha256_b64: "sha256-b64",
        ...overrides,
    };

    return request(app)
        .post("/api/files/metadata")
        .set("Authorization", `Bearer ${token}`)
        .send(payload);
}

describe("Files share", () => {
    it("requires authentication", async () => {
        const res = await request(app)
            .post("/api/files/00000000-0000-0000-0000-000000000000/share")
            .send({
                recipientUserId: "00000000-0000-0000-0000-000000000000",
                wrapped_key_b64: "wrapped-key",
            });

        expect(res.status).toBe(401);
    });

    it("rejects missing recipientUserId or wrapped_key_b64", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "share-me.txt",
            cid: "bafy-share-missing-fields",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${owner.token}`)
            .send({recipientUserId: owner.userId});

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Missing recipientUserId or wrapped_key_b64");
    });

    it("returns 404 when file does not exist", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const res = await request(app)
            .post("/api/files/00000000-0000-0000-0000-000000000000/share")
            .set("Authorization", `Bearer ${owner.token}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "wrapped-key",
            });

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("File not found");
    });

    it("returns 404 when recipient user does not exist", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "share-target-missing.txt",
            cid: "bafy-share-recipient-missing",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${owner.token}`)
            .send({
                recipientUserId: "00000000-0000-0000-0000-000000000000",
                wrapped_key_b64: "wrapped-key",
            });

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("User not found");
    });

    it("allows the owner to share a file", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "owner-share.txt",
            cid: "bafy-owner-share-1",
            wrapped_key_b64: "owner-key-b64",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${owner.token}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "recipient-shared-key-b64",
            });

        expect(shareRes.status).toBe(200);
        expect(shareRes.body.ok).toBe(true);

        const dbRes = await pool.query(
            `
                SELECT wrapped_key_b64, revoked_at, granted_by_user_id
                FROM file_permissions
                WHERE file_id = $1
                  AND user_id = $2
            `,
            [createRes.body.fileId, recipient.userId]
        );

        expect(dbRes.rowCount).toBe(1);
        expect(dbRes.rows[0].wrapped_key_b64).toBe("recipient-shared-key-b64");
        expect(dbRes.rows[0].revoked_at).toBeNull();
        expect(dbRes.rows[0].granted_by_user_id).toBe(owner.userId);
    });

    it("allows an admin to share another user's file", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(owner.token, {
            filename: "admin-share-target.txt",
            cid: "bafy-admin-share-1",
            wrapped_key_b64: "owner-key-b64",
        });

        expect(createRes.status).toBe(200);

        await pool.query(
            `
                INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
                VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
      DO
                UPDATE SET
                    wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                    revoked_at = NULL,
                    granted_by_user_id = EXCLUDED.granted_by_user_id
            `,
            [createRes.body.fileId, admin.userId, "admin-own-access-key", owner.userId]
        );

        const shareRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "recipient-admin-shared-key-b64",
            });

        expect(shareRes.status).toBe(200);
        expect(shareRes.body.ok).toBe(true);
    });

    it("allows a manager to share another user's file", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const manager = await registerAndLogin("manager@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(manager.userId, "manager");
        const managerToken = await relogin(manager.email, manager.password);

        const createRes = await createMetadata(owner.token, {
            filename: "manager-share-target.txt",
            cid: "bafy-manager-share-1",
            wrapped_key_b64: "owner-key-b64",
        });

        expect(createRes.status).toBe(200);

        await pool.query(
            `
                INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
                VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
      DO
                UPDATE SET
                    wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                    revoked_at = NULL,
                    granted_by_user_id = EXCLUDED.granted_by_user_id
            `,
            [createRes.body.fileId, manager.userId, "manager-own-access-key", owner.userId]
        );

        const shareRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${managerToken}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "recipient-manager-shared-key-b64",
            });

        expect(shareRes.status).toBe(200);
        expect(shareRes.body.ok).toBe(true);
    });

    it("rejects an employee sharing another user's file", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const employee = await registerAndLogin("employee@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "employee-cannot-share.txt",
            cid: "bafy-employee-share-1",
            wrapped_key_b64: "owner-key-b64",
        });

        expect(createRes.status).toBe(200);

        await pool.query(
            `
                INSERT INTO file_permissions (file_id, user_id, wrapped_key_b64, granted_by_user_id)
                VALUES ($1, $2, $3, $4) ON CONFLICT (file_id, user_id)
      DO
                UPDATE SET
                    wrapped_key_b64 = EXCLUDED.wrapped_key_b64,
                    revoked_at = NULL,
                    granted_by_user_id = EXCLUDED.granted_by_user_id
            `,
            [createRes.body.fileId, employee.userId, "employee-own-access-key", owner.userId]
        );

        const shareRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${employee.token}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "recipient-employee-share-attempt",
            });

        expect(shareRes.status).toBe(403);
        expect(shareRes.body.ok).toBe(false);
        expect(shareRes.body.error).toBe("Not authorised to share this file");
    });

    it("updates an existing permission and clears revoked_at when sharing again", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "reshare.txt",
            cid: "bafy-reshare-1",
            wrapped_key_b64: "owner-key-b64",
        });

        expect(createRes.status).toBe(200);

        const firstShare = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${owner.token}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "recipient-old-key",
            });

        expect(firstShare.status).toBe(200);

        await pool.query(
            `
                UPDATE file_permissions
                SET revoked_at = NOW()
                WHERE file_id = $1
                  AND user_id = $2
            `,
            [createRes.body.fileId, recipient.userId]
        );

        const secondShare = await request(app)
            .post(`/api/files/${createRes.body.fileId}/share`)
            .set("Authorization", `Bearer ${owner.token}`)
            .send({
                recipientUserId: recipient.userId,
                wrapped_key_b64: "recipient-new-key",
            });

        expect(secondShare.status).toBe(200);
        expect(secondShare.body.ok).toBe(true);

        const dbRes = await pool.query(
            `
                SELECT wrapped_key_b64, revoked_at
                FROM file_permissions
                WHERE file_id = $1
                  AND user_id = $2
            `,
            [createRes.body.fileId, recipient.userId]
        );

        expect(dbRes.rowCount).toBe(1);
        expect(dbRes.rows[0].wrapped_key_b64).toBe("recipient-new-key");
        expect(dbRes.rows[0].revoked_at).toBeNull();
    });
});