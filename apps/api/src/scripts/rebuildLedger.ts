import "dotenv/config";
import {pool} from "../db";
import {getFilesLedger} from "../fabric/gateway";

async function rebuildLedger() {
    const filesLedger = await getFilesLedger();
    console.log("Rebuilding Fabric ledger from database...");

    const {rows: files} = await pool.query(`
        SELECT id, owner_id, cid, cipher_sha256, created_at
        FROM files
        ORDER BY created_at ASC
    `);

    for (const f of files) {
        const fileId = String(f.id);
        const ownerId = String(f.owner_id);

        // create file on ledger if missing
        let onLedger = true;
        try {
            await filesLedger.getFile(fileId);
        } catch {
            onLedger = false;
        }

        if (!onLedger) {
            await filesLedger.createFile(
                fileId,
                ownerId,
                String(f.cid),
                String(f.cipher_sha256),
                new Date(f.created_at).toISOString()
            );
        }

        const {rows: perms} = await pool.query(
            `
                SELECT user_id, granted_by_user_id, created_at, revoked_at
                FROM file_permissions
                WHERE file_id = $1
                ORDER BY created_at ASC
            `,
            [fileId]
        );

        for (const p of perms) {
            const userId = String(p.user_id);
            if (userId === ownerId) continue;

            const grantActorId = String(p.granted_by_user_id || ownerId);
            const grantedAt = new Date(p.created_at).toISOString();

            const hasAccess = await filesLedger.canAccess(fileId, userId);

            if (!p.revoked_at) {
                if (!hasAccess) {
                    await filesLedger.grantAccess(
                        fileId,
                        ownerId,
                        grantActorId,
                        userId,
                        grantedAt
                    );
                }
            } else {
                // ensure grant happened
                if (!hasAccess) {
                    await filesLedger.grantAccess(
                        fileId,
                        ownerId,
                        grantActorId,
                        userId,
                        grantedAt
                    );
                }

                const revokedAt = new Date(p.revoked_at).toISOString();
                const stillHas = await filesLedger.canAccess(fileId, userId);
                if (stillHas) {
                    const revokeActorId = ownerId;
                    await filesLedger.revokeAccess(
                        fileId,
                        ownerId,
                        revokeActorId,
                        userId,
                        revokedAt
                    );
                }
            }
        }
    }
    console.log("Ledger rebuild complete.");
}

rebuildLedger()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });