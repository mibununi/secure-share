import { Context, Contract } from "fabric-contract-api";
import { Buffer } from "buffer";

type AuditEvent = {
    action: "CREATE" | "GRANT" | "REVOKE";
    actorId: string;
    targetUserId?: string;
    ts: string;
};

type FileRecord = {
    fileId: string;
    ownerId: string;
    cid: string;
    hash: string;
    createdAt: string;
};

type ACLRecord = {
    fileId: string;
    ownerId: string;
    allowed: Record<string, true>;
};

function fileKey(fileId: string) { return `file:${fileId}`; }
function aclKey(fileId: string) { return `acl:${fileId}`; }
function auditPrefix(fileId: string) { return `audit:${fileId}:`; }

export class FilesContract extends Contract {
    async CreateFile(ctx: Context, fileId: string, ownerId: string, cid: string, hash: string, createdAt: string) {
        const fk = fileKey(fileId);
        const existing = await ctx.stub.getState(fk);
        if (existing && existing.length > 0) throw new Error("File already exists on ledger");

        const file: FileRecord = { fileId, ownerId, cid, hash, createdAt };
        const acl: ACLRecord = { fileId, ownerId, allowed: { [ownerId]: true } };

        await ctx.stub.putState(fk, Buffer.from(JSON.stringify(file)));
        await ctx.stub.putState(aclKey(fileId), Buffer.from(JSON.stringify(acl)));

        await this.appendAudit(ctx, fileId, { action: "CREATE", actorId: ownerId, ts: createdAt });
        return true;
    }

    async GrantAccess(ctx: Context, fileId: string, ownerId: string, granteeId: string, ts: string) {
        const acl = await this.getACLInternal(ctx, fileId);
        if (acl.ownerId !== ownerId) throw new Error("Only owner can grant access");

        acl.allowed[granteeId] = true;
        await ctx.stub.putState(aclKey(fileId), Buffer.from(JSON.stringify(acl)));

        await this.appendAudit(ctx, fileId, { action: "GRANT", actorId: ownerId, targetUserId: granteeId, ts });
        return true;
    }

    async RevokeAccess(ctx: Context, fileId: string, ownerId: string, granteeId: string, ts: string) {
        const acl = await this.getACLInternal(ctx, fileId);
        if (acl.ownerId !== ownerId) throw new Error("Only owner can revoke access");
        if (granteeId === ownerId) throw new Error("Cannot revoke owner");

        delete acl.allowed[granteeId];
        await ctx.stub.putState(aclKey(fileId), Buffer.from(JSON.stringify(acl)));

        await this.appendAudit(ctx, fileId, { action: "REVOKE", actorId: ownerId, targetUserId: granteeId, ts });
        return true;
    }

    async CanAccess(ctx: Context, fileId: string, userId: string) {
        const acl = await this.getACLInternal(ctx, fileId);
        return !!acl.allowed[userId];
    }

    async GetFile(ctx: Context, fileId: string) {
        const data = await ctx.stub.getState(fileKey(fileId));
        if (!data || data.length === 0) throw new Error("File not found");
        return Buffer.from(data as unknown as Uint8Array).toString("utf8");
    }

    async GetACL(ctx: Context, fileId: string) {
        const acl = await this.getACLInternal(ctx, fileId);
        return JSON.stringify(acl);
    }

    // simple audit retrieval (prefix scan)
    async GetAudit(ctx: Context, fileId: string) {
        const start = `audit:${fileId}:`;
        const end = `audit:${fileId}:\uffff`;

        const iter = await ctx.stub.getStateByRange(start, end);

        const events: any[] = [];
        while (true) {
            const res = await iter.next();

            if (res.value && res.value.value) {
                const bytes = res.value.value as unknown as Uint8Array;
                const json = Buffer.from(bytes).toString("utf8");
                events.push(JSON.parse(json));
            }

            if (res.done) {
                await iter.close();
                break;
            }
        }

        return JSON.stringify(events);
    }

    private async getACLInternal(ctx: Context, fileId: string): Promise<ACLRecord> {
        const data = await ctx.stub.getState(aclKey(fileId));
        if (!data || data.length === 0) throw new Error("ACL not found");
        return JSON.parse(Buffer.from(data as unknown as Uint8Array).toString("utf8")) as ACLRecord;
    }

    private async appendAudit(ctx: Context, fileId: string, event: AuditEvent) {
        const txId = ctx.stub.getTxID();
        const key = `${auditPrefix(fileId)}${txId}`;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(event)));
    }

    async Ping() {
        return "ok";
    }
}