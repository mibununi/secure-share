import type { FilesLedger } from "../fabric/filesLedger";

export class HttpError extends Error {
    constructor(public status: number, message: string) {
        super(message);
    }
}

export async function requireFileAccessOrOwner(params: {
    filesLedger: FilesLedger | null;
    fileId: string;
    ownerId: string;
    userId: string;
}) {
    const { filesLedger, fileId, ownerId, userId } = params;

    if (userId === ownerId) return;

    if (!filesLedger) throw new HttpError(503, "Fabric not available");

    const allowed = await filesLedger.canAccess(String(fileId), String(userId));
    if (!allowed) throw new HttpError(403, "Not authorised");
}