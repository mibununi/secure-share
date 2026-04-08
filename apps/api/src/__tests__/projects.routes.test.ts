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

describe("Projects", () => {
    it("requires authentication to create a project", async () => {
        const res = await request(app)
            .post("/api/projects")
            .send({name: "Project Alpha"});

        expect(res.status).toBe(401);
    });

    it("rejects empty project name", async () => {
        const user = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${user.token}`)
            .send({name: "   "});

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Project name is required");
    });

    it("creates a project successfully", async () => {
        const user = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${user.token}`)
            .send({name: "Project Alpha"});

        expect(res.status).toBe(201);
        expect(res.body.ok).toBe(true);
        expect(res.body.project).toBeDefined();
        expect(res.body.project.id).toBeDefined();
        expect(res.body.project.name).toBe("Project Alpha");
        expect(res.body.project.created_at).toBeDefined();
    });

    it("automatically makes the creator an admin in the project", async () => {
        const user = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${user.token}`)
            .send({name: "Project Beta"});

        expect(res.status).toBe(201);

        const projectId = res.body.project.id;

        const dbRes = await pool.query(
            `
                SELECT project_id, user_id, role
                FROM project_members
                WHERE project_id = $1
                  AND user_id = $2
            `,
            [projectId, user.userId]
        );

        expect(dbRes.rowCount).toBe(1);
        expect(dbRes.rows[0].project_id).toBe(projectId);
        expect(dbRes.rows[0].user_id).toBe(user.userId);
        expect(dbRes.rows[0].role).toBe("admin");
    });

    it("lists only projects the user belongs to", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const other = await registerAndLogin("other@test.com");

        const p1 = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${owner.token}`)
            .send({name: "Owner Project 1"});

        const p2 = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${owner.token}`)
            .send({name: "Owner Project 2"});

        const p3 = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${other.token}`)
            .send({name: "Other Project"});

        expect(p1.status).toBe(201);
        expect(p2.status).toBe(201);
        expect(p3.status).toBe(201);

        const ownerList = await request(app)
            .get("/api/projects")
            .set("Authorization", `Bearer ${owner.token}`);

        expect(ownerList.status).toBe(200);
        expect(ownerList.body.ok).toBe(true);
        expect(Array.isArray(ownerList.body.projects)).toBe(true);
        expect(ownerList.body.projects).toHaveLength(2);

        const ownerNames = ownerList.body.projects.map((p: any) => p.name);
        expect(ownerNames).toEqual(
            expect.arrayContaining(["Owner Project 1", "Owner Project 2"])
        );
        expect(ownerNames).not.toContain("Other Project");

        for (const p of ownerList.body.projects) {
            expect(p.role).toBe("admin");
        }
    });

    it("returns project details for a member", async () => {
        const owner = await registerAndLogin("owner@test.com");

        const createRes = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${owner.token}`)
            .send({name: "Project Gamma"});

        expect(createRes.status).toBe(201);

        const projectId = createRes.body.project.id;

        const res = await request(app)
            .get(`/api/projects/${projectId}`)
            .set("Authorization", `Bearer ${owner.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.project).toBeDefined();
        expect(res.body.project.id).toBe(projectId);
        expect(res.body.project.name).toBe("Project Gamma");
        expect(res.body.project.role).toBe("admin");
    });

    it("returns 404 when project does not exist", async () => {
        const user = await registerAndLogin("owner@test.com");

        const res = await request(app)
            .get("/api/projects/00000000-0000-0000-0000-000000000000")
            .set("Authorization", `Bearer ${user.token}`);

        expect(res.status).toBe(404);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Project not found");
    });

    it("blocks a non-member from viewing project details", async () => {
        const owner = await registerAndLogin("owner@test.com");
        const stranger = await registerAndLogin("stranger@test.com");

        const createRes = await request(app)
            .post("/api/projects")
            .set("Authorization", `Bearer ${owner.token}`)
            .send({name: "Private Project"});

        expect(createRes.status).toBe(201);

        const projectId = createRes.body.project.id;

        const res = await request(app)
            .get(`/api/projects/${projectId}`)
            .set("Authorization", `Bearer ${stranger.token}`);

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe("Not a member of this project");
    });

    it("returns an empty list when the user belongs to no projects", async () => {
        const user = await registerAndLogin("empty@test.com");

        const res = await request(app)
            .get("/api/projects")
            .set("Authorization", `Bearer ${user.token}`);

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(Array.isArray(res.body.projects)).toBe(true);
        expect(res.body.projects).toHaveLength(0);
    });
});