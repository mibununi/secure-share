import { useEffect, useState } from "react";
import { api, type MyFilesResponse } from "../lib/api";
import { fromB64, importSpkiFromB64, toB64 } from "../lib/keys";

type FileRow = MyFilesResponse["files"][number];

type Props = {
    token: string;
    sessionPrivateKey: CryptoKey | null;
    filesVersion: number;
};

export default function MyFilesPanel({ token, sessionPrivateKey, filesVersion }: Props) {
    const [files, setFiles] = useState<FileRow[]>([]);
    const [status, setStatus] = useState("");

    const [activeFileId, setActiveFileId] = useState<string | null>(null);
    const [recipientEmail, setRecipientEmail] = useState("");
    const [recipientUserId, setRecipientUserId] = useState<string | null>(null);
    const [recipientPublicKeyB64, setRecipientPublicKeyB64] = useState<string | null>(null);
    const [shareStatus, setShareStatus] = useState("");
    const [permsStatus, setPermsStatus] = useState("");
    const [permissions, setPermissions] = useState<{
        user_id: string;
        email: string;
        revoked_at: string | null;
        is_owner: boolean;
    }[]>([]);

    useEffect(() => {
        let cancelled = false;
        async function load() {
            try {
                setStatus("Loading files...");
                const res = await api.myFiles(token);
                if (cancelled) return;
                setFiles(res.files);
                setStatus("");
            } catch (e: unknown) {
                const msg = e instanceof Error ? e.message : String(e);
                if (cancelled) return;
                setStatus(`Failed to load files: ${msg}`);
            }
        }
        if (token) void load();
        return () => {
            cancelled = true;
        };
    }, [token, filesVersion]);

    async function refresh() {
        const res = await api.myFiles(token);
        setFiles(res.files);
    }

    async function loadPermissions(fileId: string) {
        try {
            setPermsStatus("Loading access list...");
            const res = await api.filePermissions(fileId, token);
            setPermissions(res.permissions);
            setPermsStatus("");
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setPermissions([]);
            setPermsStatus(`Failed to load access list: ${msg}`);
        }
    }

    async function revokeUser(fileId: string, recipientUserId: string) {
        try {
            setPermsStatus("Revoking...");
            await api.revokeAccess(fileId, recipientUserId, token);
            setPermsStatus("Access revoked.");
            await loadPermissions(fileId);
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setPermsStatus(`Revoke failed: ${msg}`);
        }
    }

    async function lookupRecipient() {
        try {
            setShareStatus("Looking up user...");
            const json = await api.lookupPublicKey(recipientEmail, token);
            setRecipientUserId(json.userId);
            setRecipientPublicKeyB64(json.publicKey);
            setShareStatus("User found.");

        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setRecipientUserId(null);
            setRecipientPublicKeyB64(null);
            setShareStatus(`Lookup failed: ${msg}`);
        }
    }

    async function shareFile(fileId: string) {
        try {
            if (!recipientUserId || !recipientPublicKeyB64) throw new Error("Lookup a recipient first.");

            setShareStatus("Preparing keys...");

            const access = await api.fileAccess(fileId, token);
            const ownerWrappedKeyB64 = access.file.wrapped_key_b64;

            if (!sessionPrivateKey) {
                throw new Error("Private key unavailable. Log out and log back in to unlock keys on this device.");
            }

            const ownerWrappedKeyU8 = fromB64(ownerWrappedKeyB64);
            const ownerWrappedKeyView = ownerWrappedKeyU8.slice();

            const aesRawBuf = await crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                sessionPrivateKey,
                ownerWrappedKeyView
            );

            const recipientPk = await importSpkiFromB64(recipientPublicKeyB64);
            const wrappedForRecipient = new Uint8Array(
                await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPk, aesRawBuf)
            );

            setShareStatus("Sharing...");

            await api.shareFile(fileId, recipientUserId, toB64(wrappedForRecipient), token);
            setShareStatus("Shared successfully.");
            await refresh();
            await loadPermissions(fileId);

        } catch (e: unknown) {
            console.error("shareFile error:", e);

            const msg =
                e instanceof Error
                    ? `${e.name}${e.message ? `: ${e.message}` : ""}`
                    : String(e);
            setShareStatus(`Share failed: ${msg}`);
    }
}

    return (
        <div className="panel" style={{ marginTop: 16 }}>
            <h3>My Files</h3>
            {status && <p className="muted">Status: {status}</p>}

            {files.length === 0 ? (
                <p className="muted" style={{ marginTop: 8 }}>No files uploaded yet.</p>
            ) : (
                <div style={{ marginTop: 12 }}>
                    {files.map((f) => (
                        <div key={f.id} style={{ padding: 10, borderBottom: "1px solid #eee" }}>
                            <div><b>{f.filename}</b></div>
                            <div className="muted">Uploaded: {new Date(f.created_at).toLocaleString()}</div>
                            <div className="muted" style={{ wordBreak: "break-all" }}>File ID: {f.id}</div>

                            <button
                                type="button"
                                className="btn"
                                style={{marginTop: 8}}
                                onClick={() => {
                                    if (activeFileId === f.id) {
                                        setActiveFileId(null);
                                        setPermissions([]);
                                        setPermsStatus("");
                                        return;
                                    }
                                    setActiveFileId(f.id);
                                    setRecipientEmail("");
                                    setRecipientUserId(null);
                                    setRecipientPublicKeyB64(null);
                                    setShareStatus("");
                                    setPermissions([]);
                                    setPermsStatus("");
                                    void loadPermissions(f.id);
                                }}
                            >
                                {activeFileId === f.id ? "Close" : "Access"}
                            </button>

                            {activeFileId === f.id && (
                                <div style={{marginTop: 10}}>
                                    <input
                                        className="input"
                                        type="email"
                                        placeholder="Recipient email"
                                        value={recipientEmail}
                                        onChange={(e) => setRecipientEmail(e.target.value)}
                                    />
                                    <div style={{display: "flex", gap: 8, marginTop: 8}}>
                                        <button type="button" className="btn" disabled={!recipientEmail}
                                                onClick={lookupRecipient}>
                                            Find user
                                        </button>
                                        <button
                                            type="button"
                                            className="btn btn--success"
                                            disabled={!sessionPrivateKey || !recipientUserId || !recipientPublicKeyB64}
                                            onClick={() => shareFile(f.id)}
                                        >
                                            Share File
                                        </button>
                                    </div>

                                    <p className="muted" style={{marginTop: 8}}>Share
                                        status: {shareStatus || "Idle"}</p>
                                    {recipientUserId && <p className="muted"><b>Recipient ID:</b> {recipientUserId}</p>}
                                    <div style={{marginTop: 16, borderTop: "1px solid #eee", paddingTop: 12}}>
                                        <h4 style={{margin: 0}}>Who has access</h4>
                                        {permsStatus && <p className="muted" style={{marginTop: 8}}>{permsStatus}</p>}

                                        {permissions.length === 0 ? (
                                            <p className="muted" style={{marginTop: 8}}>No access entries found.</p>
                                        ) : (
                                            <div style={{marginTop: 8}}>
                                                {permissions.map((p) => (
                                                    <div key={p.user_id} style={{
                                                        display: "flex",
                                                        justifyContent: "space-between",
                                                        gap: 12,
                                                        padding: "6px 0"
                                                    }}>
                                                        <div style={{minWidth: 0}}>
                                                            <div style={{wordBreak: "break-word"}}>
                                                                <b>{p.email}</b>
                                                            </div>
                                                            <div className="muted" style={{fontSize: 12}}>
                                                                {p.revoked_at ? `Revoked: ${new Date(p.revoked_at).toLocaleString()}` : "Active"}
                                                            </div>
                                                        </div>

                                                        {!p.revoked_at && (
                                                            <button
                                                                type="button"
                                                                className="btn btn--danger"
                                                                onClick={() => revokeUser(f.id, p.user_id)}
                                                                disabled={p.is_owner}
                                                                title={p.is_owner ? "The owner cannot be revoked" : undefined}
                                                            >
                                                                {p.is_owner ? "Owner" : "Revoke"}
                                                            </button>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}