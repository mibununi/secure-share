import {type Contract} from '@hyperledger/fabric-gateway';

export type FileRecord = {
    fileId: string;
    ownerId: string;
    cid: string;
    hash: string;
    createdAt: string;
};

export type ACLRecord = {
    fileId: string;
    ownerId: string;
    allowed: Record<string, true>;
};

export type AuditEvent = {
    action: 'CREATE' | 'GRANT' | 'REVOKE';
    actorId: string;
    targetUserId?: string;
    ts: string;
};

function asJson<T>(bytes: Uint8Array): T {
    return JSON.parse(Buffer.from(bytes).toString('utf8')) as T;
}

function asBool(bytes: Uint8Array): boolean {
    const s = Buffer.from(bytes).toString('utf8').trim();
    if (s === 'true') return true;
    if (s === 'false') return false;
    return JSON.parse(s) as boolean;
}

export class FilesLedger {
    constructor(private readonly contract: Contract) {
    }

    async createFile(fileId: string, ownerId: string, cid: string, hash: string, ts: string) {
        const res = await this.contract.submitTransaction('CreateFile', fileId, ownerId, cid, hash, ts);
        return asJson<FileRecord>(res);
    }

    async grantAccess(
        fileId: string,
        ownerId: string,
        actorId: string,
        recipientId: string,
        ts: string
    ) {
        const res = await this.contract.submitTransaction(
            'GrantAccess',
            fileId,
            ownerId,
            actorId,
            recipientId,
            ts
        );
        return asJson<ACLRecord>(res);
    }

    async revokeAccess(
        fileId: string,
        ownerId: string,
        actorId: string,
        recipientId: string,
        ts: string
    ) {
        const res = await this.contract.submitTransaction(
            'RevokeAccess',
            fileId,
            ownerId,
            actorId,
            recipientId,
            ts
        );
        return asJson<ACLRecord>(res);
    }

    async canAccess(fileId: string, userId: string) {
        const res = await this.contract.evaluateTransaction('CanAccess', fileId, userId);
        return asBool(res);
    }

    async getFile(fileId: string) {
        const res = await this.contract.evaluateTransaction('GetFile', fileId);
        return asJson<FileRecord>(res);
    }

    async getACL(fileId: string) {
        const res = await this.contract.evaluateTransaction('GetACL', fileId);
        return asJson<ACLRecord>(res);
    }

    async getAudit(fileId: string) {
        const res = await this.contract.evaluateTransaction('GetAudit', fileId);
        return asJson<AuditEvent[]>(res);
    }

    async ping() {
        const res = await this.contract.evaluateTransaction("Ping");
        return Buffer.from(res).toString("utf8");
    }
}