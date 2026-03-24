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

async function shareFile(
    token: string,
    fileId: string,
    recipientUserId: string,
    wrapped_key_b64 = "recipient-shared-key"
) {
    return request(app)
        .post(`/api/files/${fileId}/share`)
        .set("Authorization", `Bearer ${token}`)
        .send({
            recipientUserId,
            wrapped_key_b64,
        });
}

async function giveActiveAccess(
    fileId: string,
    userId: string,
    grantedByUserId: string,
    wrappedKey = "active-access-key"
) {
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
        [fileId, userId, wrappedKey, grantedByUserId]
    );
}

describe("Files revoke", () => {
    it("requires authentication", async () => {
        const res = await request(app)
            .post("/api/files/00000000-0000-0000-0000-000000000000/revoke")
            .send({recipientUserId: "00000000-0000-0000-0000-000000000000"});

        expect(res.status).toBe(401);
    });

    it("rejects missing recipientUserId", async () => {
        const admin = await registerAndLogin("admin@test.com");
        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(adminToken, {
            filename: "missing-recipient.txt",
            cid: "bafy-revoke-missing-recipient",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({});

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Missing recipientUserId");
    });

    it("rejects employees trying to revoke access", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const employee = await registerAndLogin("employee@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "employee-cannot-revoke.txt",
            cid: "bafy-employee-cannot-revoke",
        });

        expect(createRes.status).toBe(200);

        await giveActiveAccess(createRes.body.fileId, employee.userId, owner.userId, "employee-access-key");
        await shareFile(owner.token, createRes.body.fileId, recipient.userId, "recipient-key");

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${employee.token}`)
            .send({recipientUserId: recipient.userId});

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised to revoke access");
    });

    it("returns 403 if caller does not have active access to the file", async () => {
        const admin = await registerAndLogin("admin@test.com");
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(owner.token, {
            filename: "admin-no-access.txt",
            cid: "bafy-admin-no-access",
        });

        expect(createRes.status).toBe(200);

        await shareFile(owner.token, createRes.body.fileId, recipient.userId, "recipient-key");

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised");
    });

    it("returns 404 when file does not exist", async () => {
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const res = await request(app)
            .post("/api/files/00000000-0000-0000-0000-000000000000/revoke")
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised");
    });

    it("prevents revoking yourself", async () => {
        const admin = await registerAndLogin("admin@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(adminToken, {
            filename: "self-revoke.txt",
            cid: "bafy-self-revoke",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: admin.userId});

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("You cannot revoke yourself");
    });

    it("returns 404 when recipient user does not exist", async () => {
        const admin = await registerAndLogin("admin@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(adminToken, {
            filename: "missing-target-user.txt",
            cid: "bafy-missing-target-user",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: "00000000-0000-0000-0000-000000000000"});

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("User not found");
    });

    it("allows an admin to revoke another user's access", async () => {
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(adminToken, {
            filename: "admin-revoke.txt",
            cid: "bafy-admin-revoke",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(adminToken, createRes.body.fileId, recipient.userId, "recipient-key");
        expect(shareRes.status).toBe(200);

        const revokeRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(revokeRes.status).toBe(200);
        expect(revokeRes.body.ok).toBe(true);

        const dbRes = await pool.query(
            `
                SELECT revoked_at
                FROM file_permissions
                WHERE file_id = $1
                  AND user_id = $2
            `,
            [createRes.body.fileId, recipient.userId]
        );

        expect(dbRes.rowCount).toBe(1);
        expect(dbRes.rows[0].revoked_at).not.toBeNull();
    });

    it("allows a manager to revoke a non-admin user", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const manager = await registerAndLogin("manager@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(manager.userId, "manager");
        const managerToken = await relogin(manager.email, manager.password);

        const createRes = await createMetadata(owner.token, {
            filename: "manager-revoke.txt",
            cid: "bafy-manager-revoke",
        });

        expect(createRes.status).toBe(200);

        await giveActiveAccess(createRes.body.fileId, manager.userId, owner.userId, "manager-access-key");

        const shareRes = await shareFile(owner.token, createRes.body.fileId, recipient.userId, "recipient-key");
        expect(shareRes.status).toBe(200);

        const revokeRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${managerToken}`)
            .send({recipientUserId: recipient.userId});

        expect(revokeRes.status).toBe(200);
        expect(revokeRes.body.ok).toBe(true);
    });

    it("prevents a manager from revoking an admin", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const manager = await registerAndLogin("manager@test.com");
        const admin = await registerAndLogin("admin@test.com");

        await setUserRole(manager.userId, "manager");
        await setUserRole(admin.userId, "admin");

        const managerToken = await relogin(manager.email, manager.password);

        const createRes = await createMetadata(owner.token, {
            filename: "manager-cannot-revoke-admin.txt",
            cid: "bafy-manager-cannot-revoke-admin",
        });

        expect(createRes.status).toBe(200);

        await giveActiveAccess(createRes.body.fileId, manager.userId, owner.userId, "manager-access-key");
        await shareFile(owner.token, createRes.body.fileId, admin.userId, "admin-key");

        const revokeRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${managerToken}`)
            .send({recipientUserId: admin.userId});

        expect(revokeRes.status).toBe(403);
        expect(revokeRes.body.ok).toBe(false);
        expect(revokeRes.body.error).toBe("Managers cannot revoke admins");
    });

    it("returns 404 when permission is already revoked", async () => {
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(adminToken, {
            filename: "already-revoked.txt",
            cid: "bafy-already-revoked",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(adminToken, createRes.body.fileId, recipient.userId, "recipient-key");
        expect(shareRes.status).toBe(200);

        const firstRevoke = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(firstRevoke.status).toBe(200);

        const secondRevoke = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(secondRevoke.status).toBe(404);
        expect(secondRevoke.body.ok).toBe(false);
        expect(secondRevoke.body.error).toBe("Permission not found or already revoked");
    });
});