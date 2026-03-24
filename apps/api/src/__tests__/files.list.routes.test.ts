import request from "supertest";
import app from "../app";
import {resetDb} from "../testUtils";

beforeEach(async () => {
    await resetDb();
});

async function registerAndLogin(email: string, password = "password1234") {
    await request(app).post("/auth/register").send({email, password});

    const login = await request(app)
        .post("/auth/login")
        .send({email, password});

    return {
        token: login.body.token as string,
    };
}

async function createMetadata(token: string, overrides?: Partial<{
    filename: string;
    mime: string;
    cid: string;
    cipher_iv_b64: string;
    wrapped_key_b64: string;
    cipher_sha256_b64: string;
}>) {
    const payload = {
        filename: "doc.txt",
        mime: "text/plain",
        cid: `bafy-${Math.random().toString(36).slice(2)}`,
        cipher_iv_b64: "iv-b64",
        wrapped_key_b64: "wrapped-key-b64",
        cipher_sha256_b64: "sha256-b64",
        ...overrides,
    };

    return request(app)
        .post("/api/files/metadata")
        .set("Authorization", `Bearer ${token}`)
        .send(payload);
}

describe("Files list", () => {
    it("requires authentication", async () => {
        const res = await request(app).get("/api/files");

        expect(res.status).toBe(401);
    });

    it("returns an empty array when user has no files", async () => {
        const {token} = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .get("/api/files")
            .set("Authorization", `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.files)).toBe(true);
        expect(res.body.files).toHaveLength(0);
    });

    it("returns files owned by the authenticated user", async () => {
        const {token} = await registerAndLogin("owner@test.com");

        const first = await createMetadata(token, {
            filename: "first.txt",
            cid: "bafy-owner-file-1",
        });
        const second = await createMetadata(token, {
            filename: "second.txt",
            cid: "bafy-owner-file-2",
        });

        expect(first.status).toBe(200);
        expect(second.status).toBe(200);

        const res = await request(app)
            .get("/api/files")
            .set("Authorization", `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.files)).toBe(true);
        expect(res.body.files).toHaveLength(2);

        const filenames = res.body.files.map((f: any) => f.filename);
        expect(filenames).toEqual(expect.arrayContaining(["first.txt", "second.txt"]));

        for (const file of res.body.files) {
            expect(file.id).toBeDefined();
            expect(file.cid).toBeDefined();
            expect(file.created_at).toBeDefined();
        }
    });

    it("does not return files owned by another user", async () => {
        const {token: ownerToken} = await registerAndLogin("owner@test.com");
        const {token: otherToken} = await registerAndLogin("other@test.com");

        const ownerCreate = await createMetadata(ownerToken, {
            filename: "owner-file.txt",
            cid: "bafy-owner-only-file",
        });

        const otherCreate = await createMetadata(otherToken, {
            filename: "other-file.txt",
            cid: "bafy-other-only-file",
        });

        expect(ownerCreate.status).toBe(200);
        expect(otherCreate.status).toBe(200);

        const ownerList = await request(app)
            .get("/api/files")
            .set("Authorization", `Bearer ${ownerToken}`);

        expect(ownerList.status).toBe(200);
        expect(ownerList.body.ok).toBe(true);
        expect(ownerList.body.files).toHaveLength(1);
        expect(ownerList.body.files[0].filename).toBe("owner-file.txt");

        const otherList = await request(app)
            .get("/api/files")
            .set("Authorization", `Bearer ${otherToken}`);

        expect(otherList.status).toBe(200);
        expect(otherList.body.ok).toBe(true);
        expect(otherList.body.files).toHaveLength(1);
        expect(otherList.body.files[0].filename).toBe("other-file.txt");
    });

    it("returns files in descending created_at order", async () => {
        const {token} = await registerAndLogin("owner@test.com");

        const first = await createMetadata(token, {
            filename: "older.txt",
            cid: "bafy-older-file",
        });

        expect(first.status).toBe(200);

        await new Promise((resolve) => setTimeout(resolve, 20));

        const second = await createMetadata(token, {
            filename: "newer.txt",
            cid: "bafy-newer-file",
        });

        expect(second.status).toBe(200);

        const res = await request(app)
            .get("/api/files")
            .set("Authorization", `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.files).toHaveLength(2);
        expect(res.body.files[0].filename).toBe("newer.txt");
        expect(res.body.files[1].filename).toBe("older.txt");
    });
});