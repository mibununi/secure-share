import request from "supertest";
import app from "../app";
import {resetDb} from "../testUtils";
import {pool} from "../db";

beforeEach(async () => {
    await resetDb();
});

async function registerAndLogin(email = "owner@test.com", password = "password1234") {
    await request(app).post("/auth/register").send({email, password});

    const login = await request(app).post("/auth/login").send({email, password});

    return {
        token: login.body.token as string,
        email,
        password,
    };
}

describe("Files metadata", () => {
    it("requires authentication", async () => {
        const res = await request(app).post("/api/files/metadata").send({
            filename: "doc.txt",
            mime: "text/plain",
            cid: "bafytestcid123",
            cipher_iv_b64: "iv-b64",
            wrapped_key_b64: "wrapped-key-b64",
            cipher_sha256_b64: "sha256-b64",
        });

        expect(res.status).toBe(401);
    });

    it("rejects missing required fields", async () => {
        const {token} = await registerAndLogin();

        const res = await request(app)
            .post("/api/files/metadata")
            .set("Authorization", `Bearer ${token}`)
            .send({
                filename: "doc.txt",
                cid: "bafytestcid123",
            });

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Missing fields");
    });

    it("creates file metadata successfully", async () => {
        const {token} = await registerAndLogin();

        const payload = {
            filename: "doc.txt",
            mime: "text/plain",
            cid: "bafytestcid123",
            cipher_iv_b64: "iv-b64",
            wrapped_key_b64: "wrapped-key-b64",
            cipher_sha256_b64: "sha256-b64",
        };

        const res = await request(app)
            .post("/api/files/metadata")
            .set("Authorization", `Bearer ${token}`)
            .send(payload);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.fileId).toBeDefined();
        expect(res.body.createdAt).toBeDefined();
    });

    it("stores the file record in the database", async () => {
        const {token, email} = await registerAndLogin();

        const payload = {
            filename: "doc.txt",
            mime: "text/plain",
            cid: "bafytestcid123",
            cipher_iv_b64: "iv-b64",
            wrapped_key_b64: "wrapped-key-b64",
            cipher_sha256_b64: "sha256-b64",
        };

        const res = await request(app)
            .post("/api/files/metadata")
            .set("Authorization", `Bearer ${token}`)
            .send(payload);

        expect(res.status).toBe(200);

        const dbRes = await pool.query(
            `
                SELECT f.id, f.filename, f.cid, f.mime, f.cipher_iv, f.cipher_sha256, u.email AS owner_email
                FROM files f
                         JOIN users u ON u.id = f.owner_id
                WHERE f.id = $1
            `,
            [res.body.fileId]
        );

        expect(dbRes.rowCount).toBe(1);
        expect(dbRes.rows[0].filename).toBe(payload.filename);
        expect(dbRes.rows[0].cid).toBe(payload.cid);
        expect(dbRes.rows[0].mime).toBe(payload.mime);
        expect(dbRes.rows[0].cipher_iv).toBe(payload.cipher_iv_b64);
        expect(dbRes.rows[0].cipher_sha256).toBe(payload.cipher_sha256_b64);
        expect(dbRes.rows[0].owner_email).toBe(email);
    });

    it("automatically creates an active owner permission record", async () => {
        const {token} = await registerAndLogin();

        const payload = {
            filename: "doc.txt",
            mime: "text/plain",
            cid: "bafytestcid123",
            cipher_iv_b64: "iv-b64",
            wrapped_key_b64: "wrapped-key-b64",
            cipher_sha256_b64: "sha256-b64",
        };

        const res = await request(app)
            .post("/api/files/metadata")
            .set("Authorization", `Bearer ${token}`)
            .send(payload);

        expect(res.status).toBe(200);

        const permRes = await pool.query(
            `
                SELECT fp.file_id, fp.user_id, fp.wrapped_key_b64, fp.revoked_at
                FROM file_permissions fp
                         JOIN files f ON f.id = fp.file_id
                WHERE fp.file_id = $1
                  AND fp.user_id = f.owner_id
            `,
            [res.body.fileId]
        );

        expect(permRes.rowCount).toBe(1);
        expect(permRes.rows[0].wrapped_key_b64).toBe(payload.wrapped_key_b64);
        expect(permRes.rows[0].revoked_at).toBeNull();
    });

    it("allows mime to be omitted", async () => {
        const {token} = await registerAndLogin();

        const res = await request(app)
            .post("/api/files/metadata")
            .set("Authorization", `Bearer ${token}`)
            .send({
                filename: "doc.txt",
                cid: "bafytestcid456",
                cipher_iv_b64: "iv-b64",
                wrapped_key_b64: "wrapped-key-b64",
                cipher_sha256_b64: "sha256-b64",
            });

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);

        const dbRes = await pool.query(`SELECT mime
                                        FROM files
                                        WHERE id = $1`, [res.body.fileId]);
        expect(dbRes.rowCount).toBe(1);
        expect(dbRes.rows[0].mime).toBeNull();
    });

    it("rejects duplicate cid values", async () => {
        const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {
        });

        try {
            const {token} = await registerAndLogin();

            const payload = {
                filename: "doc.txt",
                mime: "text/plain",
                cid: "bafyduplicatecid123",
                cipher_iv_b64: "iv-b64",
                wrapped_key_b64: "wrapped-key-b64",
                cipher_sha256_b64: "sha256-b64",
            };

            const first = await request(app)
                .post("/api/files/metadata")
                .set("Authorization", `Bearer ${token}`)
                .send(payload);

            expect(first.status).toBe(200);

            const second = await request(app)
                .post("/api/files/metadata")
                .set("Authorization", `Bearer ${token}`)
                .send({
                    ...payload,
                    filename: "doc-2.txt",
                    wrapped_key_b64: "wrapped-key-b64-2",
                });

            expect(second.status).toBe(500);
            expect(second.body.ok).toBe(false);
        } finally {
            consoleSpy.mockRestore();
        }
    });
});