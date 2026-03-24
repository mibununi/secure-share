import request from "supertest";
import app from "../app";
import {resetDb} from "../testUtils";

beforeEach(async () => {
    await resetDb();
});

describe("Auth", () => {
    const email = "email@test.com";
    const password = "password1234";

    it("registers a new user", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({email, password});

        expect(res.status).toBe(201);
        expect(res.body.ok).toBe(true);
        expect(res.body.user).toBeDefined();
        expect(res.body.user.email).toBe(email);
        expect(res.body.user.id).toBeDefined();
        expect(res.body.user.created_at).toBeDefined();
    });

    it("rejects duplicate user", async () => {
        await request(app)
            .post("/auth/register")
            .send({email, password});

        const res = await request(app)
            .post("/auth/register")
            .send({email, password});

        expect(res.status).toBe(409);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Email already registered");
    });

    it("rejects invalid registration input", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({email: "not-an-email", password: "short"});

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBeDefined();
    });

    it("logs in and returns a token", async () => {
        await request(app)
            .post("/auth/register")
            .send({email, password});

        const res = await request(app)
            .post("/auth/login")
            .send({email, password});

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(typeof res.body.token).toBe("string");
        expect(res.body.token.length).toBeGreaterThan(0);
    });

    it("rejects login with wrong password", async () => {
        await request(app)
            .post("/auth/register")
            .send({email, password});

        const res = await request(app)
            .post("/auth/login")
            .send({email, password: "wrongpassword123"});

        expect(res.status).toBe(401);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Invalid credentials");
    });

    it("rejects login for non-existent user", async () => {
        const res = await request(app)
            .post("/auth/login")
            .send({email, password});

        expect(res.status).toBe(401);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Invalid credentials");
    });

    it("me requires JWT and returns current user", async () => {
        await request(app)
            .post("/auth/register")
            .send({email, password});

        const login = await request(app)
            .post("/auth/login")
            .send({email, password});

        const token = login.body.token as string;

        const noAuth = await request(app).get("/auth/me");
        expect(noAuth.status).toBe(401);

        const res = await request(app)
            .get("/auth/me")
            .set("Authorization", `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.me).toBeDefined();
        expect(res.body.me.email).toBe(email);
        expect(res.body.me.id).toBeDefined();
        expect(res.body.me.created_at).toBeDefined();
        expect(res.body.me).toHaveProperty("role");
        expect(res.body.me).toHaveProperty("public_key");
    });
});