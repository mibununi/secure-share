import request from "supertest";
import app from "../app";
import { resetDb } from "../testUtils";

async function loginAs(email: string, password: string) {
    await request(app).post("/auth/register").send({ email, password });
    const r = await request(app).post("/auth/login").send({ email, password });
    return r.body.token as string;
}

beforeEach(async () => {
    await resetDb();
});

describe("PUT /keys/public", () => {
    it("requires auth", async () => {
        const r = await request(app).put("/keys/public").send({ publicKey: "ABC" });
        expect(r.status).toBe(401);
    });

    it("persists public key for the user", async () => {
        const token = await loginAs("email@test.com", "password1234");
        const pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...";
        const r = await request(app)
            .put("/keys/public")
            .set("Authorization", `Bearer ${token}`)
            .send({ publicKey: pub });
        expect(r.status).toBe(200);
        expect(r.body.ok).toBe(true);
    });
});