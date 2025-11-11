import request from "supertest";
import app from "../app";
import { resetDb } from "../testUtils";

beforeEach(async () => {
    await resetDb();
});

describe("Auth", () => {
    const email = "email@test.com";
    const password = "password1234";

    it("registers new user", async () => {
        const r1 = await request(app).post("/auth/register").send({ email, password });
        expect([200,201]).toContain(r1.status);
    });

    it("rejects duplicate user", async () => {
        await request(app).post("/auth/register").send({ email, password });
        const r2 = await request(app).post("/auth/register").send({ email, password });
        expect(r2.status).toBe(409);
    });

    it("logs in and returns a token", async () => {
        await request(app).post("/auth/register").send({ email, password });
        const r = await request(app).post("/auth/login").send({ email, password });
        expect(r.status).toBe(200);
        expect(r.body.ok).toBe(true);
        expect(typeof r.body.token).toBe("string");
    });

    it("me requires JWT", async () => {
        await request(app).post("/auth/register").send({ email, password });
        const login = await request(app).post("/auth/login").send({ email, password });
        const token = login.body.token as string;

        const noAuth = await request(app).get("/auth/me");
        expect(noAuth.status).toBe(401);

        const ok = await request(app).get("/auth/me").set("Authorization", `Bearer ${token}`);
        expect(ok.status).toBe(200);
        expect(ok.body.ok).toBe(true);
        expect(ok.body.me.email).toBe(email);
    });
});