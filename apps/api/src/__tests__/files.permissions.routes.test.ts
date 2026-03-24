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

describe("Files permissions list", () => {
    it("requires authentication", async () => {
        const res = await request(app).get(
            "/api/files/00000000-0000-0000-0000-000000000000/permissions"
        );

        expect(res.status).toBe(401);
    });

    it("returns 404 when file does not exist", async () => {
        const admin = await registerAndLogin("admin@test.com");
        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const res = await request(app)
            .get("/api/files/00000000-0000-0000-0000-000000000000/permissions")
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("File not found");
    });

    it("allows an admin to view the permissions list", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(owner.token, {
            filename: "admin-can-view.txt",
            cid: "bafy-admin-can-view",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.permissions)).toBe(true);

        const emails = res.body.permissions.map((p: any) => p.email);
        expect(emails).toEqual(expect.arrayContaining(["owner@test.com", "recipient@test.com"]));
    });

    it("allows a manager with active access to view the permissions list", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const manager = await registerAndLogin("manager@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(manager.userId, "manager");
        const managerToken = await relogin(manager.email, manager.password);

        const createRes = await createMetadata(owner.token, {
            filename: "manager-can-view.txt",
            cid: "bafy-manager-can-view",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        await giveActiveAccess(createRes.body.fileId, manager.userId, owner.userId, "manager-key");

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${managerToken}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.permissions)).toBe(true);

        const emails = res.body.permissions.map((p: any) => p.email);
        expect(emails).toEqual(
            expect.arrayContaining(["owner@test.com", "manager@test.com", "recipient@test.com"])
        );
    });

    it("allows a manager who owns the file to view the permissions list", async () => {
        const manager = await registerAndLogin("manager@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(manager.userId, "manager");
        const managerToken = await relogin(manager.email, manager.password);

        const createRes = await createMetadata(managerToken, {
            filename: "manager-owned-file.txt",
            cid: "bafy-manager-owned-file",
            wrapped_key_b64: "manager-owner-key",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            managerToken,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${managerToken}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.permissions).toHaveLength(2);

        const ownerRow = res.body.permissions.find((p: any) => p.email === "manager@test.com");
        const recipientRow = res.body.permissions.find((p: any) => p.email === "recipient@test.com");

        expect(ownerRow).toBeDefined();
        expect(ownerRow.is_owner).toBe(true);
        expect(recipientRow).toBeDefined();
        expect(recipientRow.is_owner).toBe(false);
    });

    it("rejects an employee even if they have active access", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const employee = await registerAndLogin("employee@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "employee-cannot-view.txt",
            cid: "bafy-employee-cannot-view",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        await giveActiveAccess(createRes.body.fileId, employee.userId, owner.userId, "employee-key");

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${employee.token}`);

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised to view access list");
    });

    it("rejects a manager without active access and not owner", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const manager = await registerAndLogin("manager@test.com");

        await setUserRole(manager.userId, "manager");
        const managerToken = await relogin(manager.email, manager.password);

        const createRes = await createMetadata(owner.token, {
            filename: "manager-no-access.txt",
            cid: "bafy-manager-no-access",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${managerToken}`);

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised to view access list");
    });

    it("includes revoked users in the permissions list with revoked_at set", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(owner.token, {
            filename: "revoked-user-visible.txt",
            cid: "bafy-revoked-user-visible",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);
        await pool.query(
            `
                UPDATE file_permissions
                SET revoked_at = NOW()
                WHERE file_id = $1
                  AND user_id = $2
            `,
            [createRes.body.fileId, recipient.userId]
        );

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);

        const recipientRow = res.body.permissions.find(
            (p: any) => p.email === "recipient@test.com"
        );

        expect(recipientRow).toBeDefined();
        expect(recipientRow.revoked_at).toBeDefined();
        expect(recipientRow.revoked_at).not.toBeNull();
    });

    it("returns expected fields for each permission row", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(owner.token, {
            filename: "permission-fields.txt",
            cid: "bafy-permission-fields",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.permissions.length).toBeGreaterThan(0);

        for (const row of res.body.permissions) {
            expect(row).toHaveProperty("user_id");
            expect(row).toHaveProperty("email");
            expect(row).toHaveProperty("user_role");
            expect(row).toHaveProperty("revoked_at");
            expect(row).toHaveProperty("is_owner");
        }
    });

    it("orders permissions by email", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const zUser = await registerAndLogin("zuser@test.com");
        const aUser = await registerAndLogin("auser@test.com");

        await setUserRole(admin.userId, "admin");
        const adminToken = await relogin(admin.email, admin.password);

        const createRes = await createMetadata(owner.token, {
            filename: "ordered-permissions.txt",
            cid: "bafy-ordered-permissions",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        const shareA = await shareFile(owner.token, createRes.body.fileId, aUser.userId, "a-key");
        const shareZ = await shareFile(owner.token, createRes.body.fileId, zUser.userId, "z-key");

        expect(shareA.status).toBe(200);
        expect(shareZ.status).toBe(200);

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/permissions`)
            .set("Authorization", `Bearer ${adminToken}`);

        expect(res.status).toBe(200);

        const emails = res.body.permissions.map((p: any) => p.email);
        const sorted = [...emails].sort((a, b) => a.localeCompare(b));
        expect(emails).toEqual(sorted);
    });
});