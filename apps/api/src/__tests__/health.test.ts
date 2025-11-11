import request from "supertest";
import app from "../app";

describe("GET /health", () => {
    it("returns ok:true", async () => {
        const r = await request(app).get("/health");
        expect(r.status).toBe(200);
        expect(r.body).toEqual({ ok: true });
    });
});