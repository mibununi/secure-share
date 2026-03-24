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

    const res = await request(app)
        .post("/api/files/metadata")
        .set("Authorization", `Bearer ${token}`)
        .send(payload);

    return {
        res,
        payload,
    };
}

async function shareFile(
    token: string,
    fileId: string,
    recipientUserId: string,
    wrapped_key_b64 = "shared-wrapped-key-b64"
) {
    return request(app)
        .post(`/api/files/${fileId}/share`)
        .set("Authorization", `Bearer ${token}`)
        .send({
            recipientUserId,
            wrapped_key_b64,
        });
}

describe("Files access", () => {
    it("requires authentication", async () => {
        const res = await request(app).get("/api/files/123/access");
        expect(res.status).toBe(401);
    });

    it("returns 404 when file does not exist", async () => {
        const {token} = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .get("/api/files/00000000-0000-0000-0000-000000000000/access")
            .set("Authorization", `Bearer ${token}`);

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("File not found");
    });

    it("allows the owner to access file metadata and wrapped key", async () => {
        const {token} = await registerAndLogin("owner@test.com");

        const {res: createRes, payload} = await createMetadata(token, {
            filename: "owner-doc.txt",
            cid: "bafy-owner-access-1",
            cipher_iv_b64: "owner-iv-b64",
            wrapped_key_b64: "owner-wrapped-key-b64",
            cipher_sha256_b64: "owner-sha256-b64",
        });

        expect(createRes.status).toBe(200);

        const accessRes = await request(app)
            .get(`/api/files/${createRes.body.fileId}/access`)
            .set("Authorization", `Bearer ${token}`);

        expect(accessRes.status).toBe(200);
        expect(accessRes.body.ok).toBe(true);
        expect(accessRes.body.file).toBeDefined();

        expect(accessRes.body.file.id).toBe(createRes.body.fileId);
        expect(accessRes.body.file.filename).toBe(payload.filename);
        expect(accessRes.body.file.cid).toBe(payload.cid);
        expect(accessRes.body.file.mime).toBe(payload.mime);
        expect(accessRes.body.file.cipher_iv_b64).toBe(payload.cipher_iv_b64);
        expect(accessRes.body.file.cipher_sha256_b64).toBe(payload.cipher_sha256_b64);
        expect(accessRes.body.file.wrapped_key_b64).toBe(payload.wrapped_key_b64);
        expect(accessRes.body.file.created_at).toBeDefined();
    });

    it("allows a shared user to access file metadata and their wrapped key", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const {res: createRes} = await createMetadata(owner.token, {
            filename: "shared-doc.txt",
            cid: "bafy-shared-access-1",
            cipher_iv_b64: "shared-iv-b64",
            wrapped_key_b64: "owner-wrapped-key-b64",
            cipher_sha256_b64: "shared-sha256-b64",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-wrapped-key-b64"
        );

        expect(shareRes.status).toBe(200);
        expect(shareRes.body.ok).toBe(true);

        const accessRes = await request(app)
            .get(`/api/files/${createRes.body.fileId}/access`)
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(accessRes.status).toBe(200);
        expect(accessRes.body.ok).toBe(true);

        expect(accessRes.body.file.id).toBe(createRes.body.fileId);
        expect(accessRes.body.file.filename).toBe("shared-doc.txt");
        expect(accessRes.body.file.cid).toBe("bafy-shared-access-1");
        expect(accessRes.body.file.cipher_iv_b64).toBe("shared-iv-b64");
        expect(accessRes.body.file.cipher_sha256_b64).toBe("shared-sha256-b64");
        expect(accessRes.body.file.wrapped_key_b64).toBe("recipient-wrapped-key-b64");
    });

    it("rejects a user who has not been granted access", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const stranger = await registerAndLogin("stranger@test.com");

        const {res: createRes} = await createMetadata(owner.token, {
            filename: "private-doc.txt",
            cid: "bafy-private-access-1",
        });

        expect(createRes.status).toBe(200);

        const accessRes = await request(app)
            .get(`/api/files/${createRes.body.fileId}/access`)
            .set("Authorization", `Bearer ${stranger.token}`);

        expect(accessRes.status).toBe(403);
        expect(accessRes.body.ok).toBe(false);
    });

    it("returns 403 after access has been revoked", async () => {
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await pool.query(`UPDATE users
                          SET role = 'admin'
                          WHERE id = $1`, [admin.userId]);

        const relogin = await request(app)
            .post("/auth/login")
            .send({email: "admin@test.com", password: "password1234"});

        const adminToken = relogin.body.token as string;

        const {res: createRes} = await createMetadata(adminToken, {
            filename: "revoked-doc.txt",
            cid: "bafy-revoked-access-1",
            wrapped_key_b64: "admin-owner-key-b64",
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            adminToken,
            createRes.body.fileId,
            recipient.userId,
            "recipient-before-revoke-key-b64"
        );

        expect(shareRes.status).toBe(200);

        const beforeRevoke = await request(app)
            .get(`/api/files/${createRes.body.fileId}/access`)
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(beforeRevoke.status).toBe(200);
        expect(beforeRevoke.body.file.wrapped_key_b64).toBe("recipient-before-revoke-key-b64");

        const revokeRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(revokeRes.status).toBe(200);
        expect(revokeRes.body.ok).toBe(true);

        const afterRevoke = await request(app)
            .get(`/api/files/${createRes.body.fileId}/access`)
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(afterRevoke.status).toBe(403);
        expect(afterRevoke.body.ok).toBe(false);
    });

    it("returns 500 for an owner if the owner permission record is missing", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const {res: createRes} = await createMetadata(owner.token, {
            filename: "owner-missing-permission.txt",
            cid: "bafy-owner-missing-permission-1",
            wrapped_key_b64: "owner-key-to-delete",
        });

        expect(createRes.status).toBe(200);

        await pool.query(
            `
                DELETE
                FROM file_permissions
                WHERE file_id = $1
                  AND user_id = $2
            `,
            [createRes.body.fileId, owner.userId]
        );

        const accessRes = await request(app)
            .get(`/api/files/${createRes.body.fileId}/access`)
            .set("Authorization", `Bearer ${owner.token}`);

        expect(accessRes.status).toBe(500);
        expect(accessRes.body.ok).toBe(false);
        expect(accessRes.body.error).toBe("Owner permission record missing");
    });
});