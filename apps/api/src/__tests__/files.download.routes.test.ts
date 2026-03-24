import request from "supertest";
import app from "../app";
import {resetDb} from "../testUtils";
import {pool} from "../db";
import {sha256B64} from "../utils/crypto";
import {requireFileAccessOrOwner, HttpError} from "../utils/access";

const mockedRequireFileAccessOrOwner = requireFileAccessOrOwner as jest.Mock;

function binaryParser(
    res: any,
    callback: (err: Error | null, body: Buffer) => void
) {
    const data: Buffer[] = [];

    res.on("data", (chunk: Buffer) => {
        data.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });

    res.on("end", () => {
        callback(null, Buffer.concat(data));
    });
}

beforeEach(async () => {
    await resetDb();
    mockedRequireFileAccessOrOwner.mockResolvedValue(undefined);
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

describe("Files download", () => {
    const originalFetch = global.fetch;

    afterEach(() => {
        global.fetch = originalFetch;
        jest.restoreAllMocks();
    });

    it("requires authentication", async () => {
        const res = await request(app).get(
            "/api/files/00000000-0000-0000-0000-000000000000/download"
        );

        expect(res.status).toBe(401);
    });

    it("returns 404 when file does not exist", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .get("/api/files/00000000-0000-0000-0000-000000000000/download")
            .set("Authorization", `Bearer ${owner.token}`);

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("File not found");
    });

    it("allows the owner to download a file when integrity check passes", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const ciphertext = Buffer.from("encrypted file bytes");
        const hash = sha256B64(ciphertext);

        const createRes = await createMetadata(owner.token, {
            filename: "owner-download.txt",
            mime: "text/plain",
            cid: "bafy-owner-download",
            cipher_sha256_b64: hash,
        });

        expect(createRes.status).toBe(200);

        global.fetch = jest.fn(async () => ({
            ok: true,
            arrayBuffer: async () =>
                ciphertext.buffer.slice(
                    ciphertext.byteOffset,
                    ciphertext.byteOffset + ciphertext.byteLength
                ),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${owner.token}`)
            .buffer(true)
            .parse(binaryParser);

        expect(res.status).toBe(200);
        expect(res.headers["content-type"]).toContain("text/plain");
        expect(res.headers["content-disposition"]).toContain(
            'filename="owner-download.txt"'
        );
        expect(Buffer.isBuffer(res.body)).toBe(true);
        expect(res.body.toString()).toBe(ciphertext.toString());
    });

    it("allows a shared user to download a file when integrity check passes", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        const ciphertext = Buffer.from("shared encrypted bytes");
        const hash = sha256B64(ciphertext);

        const createRes = await createMetadata(owner.token, {
            filename: "shared-download.txt",
            mime: "application/octet-stream",
            cid: "bafy-shared-download",
            cipher_sha256_b64: hash,
        });

        expect(createRes.status).toBe(200);

        const shareRes = await shareFile(
            owner.token,
            createRes.body.fileId,
            recipient.userId,
            "recipient-key"
        );

        expect(shareRes.status).toBe(200);

        global.fetch = jest.fn(async () => ({
            ok: true,
            arrayBuffer: async () =>
                ciphertext.buffer.slice(
                    ciphertext.byteOffset,
                    ciphertext.byteOffset + ciphertext.byteLength
                ),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${recipient.token}`)
            .buffer(true)
            .parse(binaryParser);

        expect(res.status).toBe(200);
        expect(res.headers["content-type"]).toContain("application/octet-stream");
        expect(res.headers["content-disposition"]).toContain(
            'filename="shared-download.txt"'
        );
        expect(Buffer.isBuffer(res.body)).toBe(true);
        expect(res.body.toString()).toBe(ciphertext.toString());
    });

    it("returns 409 when ciphertext integrity verification fails", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const expectedCiphertext = Buffer.from("expected ciphertext");
        const actualCiphertext = Buffer.from("tampered ciphertext");

        const createRes = await createMetadata(owner.token, {
            filename: "tampered.txt",
            mime: "text/plain",
            cid: "bafy-integrity-fail",
            cipher_sha256_b64: sha256B64(expectedCiphertext),
        });

        expect(createRes.status).toBe(200);

        global.fetch = jest.fn(async () => ({
            ok: true,
            arrayBuffer: async () =>
                actualCiphertext.buffer.slice(
                    actualCiphertext.byteOffset,
                    actualCiphertext.byteOffset + actualCiphertext.byteLength
                ),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${owner.token}`);

        expect(res.status).toBe(409);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe(
            "Integrity verification failed. The stored file may be corrupted or tampered with."
        );
    });

    it("returns 409 when stored ciphertext hash is missing", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const ciphertext = Buffer.from("ciphertext with missing stored hash");

        const createRes = await createMetadata(owner.token, {
            filename: "missing-hash.txt",
            mime: "text/plain",
            cid: "bafy-missing-hash",
            cipher_sha256_b64: "temporary-hash",
        });

        expect(createRes.status).toBe(200);

        await pool.query(`UPDATE files
                          SET cipher_sha256 = NULL
                          WHERE id = $1`, [
            createRes.body.fileId,
        ]);

        global.fetch = jest.fn(async () => ({
            ok: true,
            arrayBuffer: async () =>
                ciphertext.buffer.slice(
                    ciphertext.byteOffset,
                    ciphertext.byteOffset + ciphertext.byteLength
                ),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${owner.token}`);

        expect(res.status).toBe(409);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe(
            "Integrity verification failed. The stored file may be corrupted or tampered with."
        );
    });

    it("returns 502 when IPFS gateway fetch fails", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const ciphertext = Buffer.from("ciphertext");
        const hash = sha256B64(ciphertext);

        const createRes = await createMetadata(owner.token, {
            filename: "gateway-fail.txt",
            mime: "text/plain",
            cid: "bafy-gateway-fail",
            cipher_sha256_b64: hash,
        });

        expect(createRes.status).toBe(200);

        global.fetch = jest.fn(async () => ({
            ok: false,
            arrayBuffer: async () => new ArrayBuffer(0),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${owner.token}`);

        expect(res.status).toBe(502);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Failed to fetch from IPFS gateway");
    });

    it("returns 403 for a user without access", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const stranger = await registerAndLogin("stranger@test.com");

        const ciphertext = Buffer.from("private ciphertext");
        const hash = sha256B64(ciphertext);

        const createRes = await createMetadata(owner.token, {
            filename: "private-download.txt",
            mime: "text/plain",
            cid: "bafy-private-download",
            cipher_sha256_b64: hash,
        });

        expect(createRes.status).toBe(200);

        mockedRequireFileAccessOrOwner.mockRejectedValueOnce(
            new HttpError(403, "Not authorised")
        );

        global.fetch = jest.fn(async () => ({
            ok: true,
            arrayBuffer: async () =>
                ciphertext.buffer.slice(
                    ciphertext.byteOffset,
                    ciphertext.byteOffset + ciphertext.byteLength
                ),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${stranger.token}`);

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised");
    });

    it("returns 403 for a previously shared user after revoke", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const admin = await registerAndLogin("admin@test.com");
        const recipient = await registerAndLogin("recipient@test.com");

        await pool.query(`UPDATE users
                          SET role = 'admin'
                          WHERE id = $1`, [
            admin.userId,
        ]);

        const adminLogin = await request(app)
            .post("/auth/login")
            .send({email: admin.email, password: admin.password});

        const adminToken = adminLogin.body.token as string;

        const ciphertext = Buffer.from("revoked ciphertext");
        const hash = sha256B64(ciphertext);

        const createRes = await createMetadata(owner.token, {
            filename: "revoked-download.txt",
            mime: "text/plain",
            cid: "bafy-revoked-download",
            cipher_sha256_b64: hash,
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

        const revokeRes = await request(app)
            .post(`/api/files/${createRes.body.fileId}/revoke`)
            .set("Authorization", `Bearer ${adminToken}`)
            .send({recipientUserId: recipient.userId});

        expect(revokeRes.status).toBe(200);

        mockedRequireFileAccessOrOwner.mockRejectedValueOnce(
            new HttpError(403, "Not authorised")
        );

        global.fetch = jest.fn(async () => ({
            ok: true,
            arrayBuffer: async () =>
                ciphertext.buffer.slice(
                    ciphertext.byteOffset,
                    ciphertext.byteOffset + ciphertext.byteLength
                ),
        })) as any;

        const res = await request(app)
            .get(`/api/files/${createRes.body.fileId}/download`)
            .set("Authorization", `Bearer ${recipient.token}`);

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not authorised");
    });
});