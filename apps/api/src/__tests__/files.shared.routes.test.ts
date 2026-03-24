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

describe("Files shared-with-me", () => {
    it("requires authentication", async () => {
        const res = await request(app).get("/api/files/shared-with-me");

        expect(res.status).toBe(401);
    });

    it("returns an empty array when nothing has been shared with the user", async () => {
        const user = await registerAndLogin("user@test.com");

        const res = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${user.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.files)).toBe(true);
        expect(res.body.files).toHaveLength(0);
    });

    it("returns files shared with the authenticated user", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const createRes = await createMetadata(owner.token, {
            filename: "shared-report.pdf",
            mime: "application/pdf",
            cid: "bafy-shared-with-me-1",
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
        expect(shareRes.body.ok).toBe(true);

        const res = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.files)).toBe(true);
        expect(res.body.files).toHaveLength(1);

        const file = res.body.files[0];
        expect(file.id).toBe(createRes.body.fileId);
        expect(file.filename).toBe("shared-report.pdf");
        expect(file.cid).toBe("bafy-shared-with-me-1");
        expect(file.mime).toBe("application/pdf");
        expect(file.owner_email).toBe("owner@test.com");
        expect(file.shared_by_email).toBe("owner@test.com");
        expect(file.created_at).toBeDefined();
    });

    it("does not include the user's own files", async () => {
        const user = await registerAndLogin("user@test.com");

        const createRes = await createMetadata(user.token, {
            filename: "my-own-file.txt",
            cid: "bafy-own-file-not-shared-with-me",
            wrapped_key_b64: "owner-key",
        });

        expect(createRes.status).toBe(200);

        const res = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${user.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.files)).toBe(true);
        expect(res.body.files).toHaveLength(0);
    });

    it("returns multiple shared files ordered by newest first", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const first = await createMetadata(owner.token, {
            filename: "older-shared.txt",
            cid: "bafy-older-shared-file",
            wrapped_key_b64: "owner-key-1",
        });

        expect(first.status).toBe(200);

        await new Promise((resolve) => setTimeout(resolve, 20));

        const second = await createMetadata(owner.token, {
            filename: "newer-shared.txt",
            cid: "bafy-newer-shared-file",
            wrapped_key_b64: "owner-key-2",
        });

        expect(second.status).toBe(200);

        const shareFirst = await shareFile(
            owner.token,
            first.body.fileId,
            recipient.userId,
            "recipient-key-1"
        );
        const shareSecond = await shareFile(
            owner.token,
            second.body.fileId,
            recipient.userId,
            "recipient-key-2"
        );

        expect(shareFirst.status).toBe(200);
        expect(shareSecond.status).toBe(200);

        const res = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.files).toHaveLength(2);
        expect(res.body.files[0].filename).toBe("newer-shared.txt");
        expect(res.body.files[1].filename).toBe("older-shared.txt");
    });

    it("does not include revoked shares", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await pool.query(`UPDATE users
                          SET role = 'admin'
                          WHERE id = $1`, [admin.userId]);

        const adminLogin = await request(app)
            .post("/auth/login")
            .send({email: admin.email, password: admin.password});

        const adminToken = adminLogin.body.token as string;

        const createRes = await createMetadata(owner.token, {
            filename: "revoked-shared-file.txt",
            cid: "bafy-revoked-shared-file",
            wrapped_key_b64: "owner-key",
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
            [createRes.body.fileId, admin.userId, "admin-access-key", owner.userId]
        );

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        const beforeRevoke = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(beforeRevoke.status).toBe(200);
        expect(beforeRevoke.body.files).toHaveLength(1);

        const revokeRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(revokeRes.status).toBe(200);
        expect(revokeRes.body.ok).toBe(true);

        const afterRevoke = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(afterRevoke.status).toBe(200);
        expect(afterRevoke.body.ok).toBe(true);
        expect(afterRevoke.body.files).toHaveLength(0);
    });

    it("shows the original sharer email when a different user granted access", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const manager = await registerAndLogin("manager@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await pool.query(`UPDATE users
                          SET role = 'manager'
                          WHERE id = $1`, [manager.userId]);

        const managerLogin = await request(app)
            .post("/auth/login")
            .send({email: manager.email, password: manager.password});

        const managerToken = managerLogin.body.token as string;

        const createRes = await createMetadata(owner.token, {
            filename: "manager-shared-file.txt",
            cid: "bafy-manager-shared-file",
            wrapped_key_b64: "owner-key",
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
            [createRes.body.fileId, manager.userId, "manager-access-key", owner.userId]
        );

        const shareRes = await shareFile(
            managerToken,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key-from-manager"
        );

        expect(shareRes.status).toBe(200);

        const res = await request(app)
            .get("/api/files/shared-with-me")
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.files).toHaveLength(1);
        expect(res.body.files[0].owner_email).toBe("owner@test.com");
        expect(res.body.files[0].shared_by_email).toBe("manager@test.com");
    });
});