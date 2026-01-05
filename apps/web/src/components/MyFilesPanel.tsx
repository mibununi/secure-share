import { useEffect, useState } from "react";
import { api, type MyFilesResponse } from "../lib/api";
import { fromB64, importSpkiFromB64, toB64 } from "../lib/keys";

type FileRow = MyFilesResponse["files"][number];

type Props = {
    token: string;
    sessionPrivateKey: CryptoKey | null;
};

export default function MyFilesPanel({ token, sessionPrivateKey }: Props) {
    const [files, setFiles] = useState<FileRow[]>([]);
    const [status, setStatus] = useState("");

    const [activeFileId, setActiveFileId] = useState<string | null>(null);
    const [recipientEmail, setRecipientEmail] = useState("");
    const [recipientUserId, setRecipientUserId] = useState<string | null>(null);
    const [recipientPublicKeyB64, setRecipientPublicKeyB64] = useState<string | null>(null);
    const [shareStatus, setShareStatus] = useState("");

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
        if (token) load();
        return () => {
            cancelled = true;
        };
    }, [token]);

    async function refresh() {
        const res = await api.myFiles(token);
        setFiles(res.files);
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
            const ownerWrappedKey = new Uint8Array(ownerWrappedKeyU8).buffer;

            const aesRawBuf = await crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                sessionPrivateKey,
                ownerWrappedKey
            );

            const recipientPk = await importSpkiFromB64(recipientPublicKeyB64);
            const wrappedForRecipient = new Uint8Array(
                await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPk, aesRawBuf)
            );

            setShareStatus("Sharing...");

            await api.shareFile(fileId, recipientUserId, toB64(wrappedForRecipient), token);
            setShareStatus("Shared successfully.");
            await refresh();

        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
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
                                style={{ marginTop: 8 }}
                                onClick={() => {
                                    setActiveFileId(f.id);
                                    setRecipientEmail("");
                                    setRecipientUserId(null);
                                    setRecipientPublicKeyB64(null);
                                    setShareStatus("");
                                }}
                            >
                                Share
                            </button>

                            {activeFileId === f.id && (
                                <div style={{ marginTop: 10 }}>
                                    <input
                                        className="input"
                                        type="email"
                                        placeholder="Recipient email"
                                        value={recipientEmail}
                                        onChange={(e) => setRecipientEmail(e.target.value)}
                                    />
                                    <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                                        <button type="button" className="btn" disabled={!recipientEmail} onClick={lookupRecipient}>
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

                                    <p className="muted" style={{ marginTop: 8 }}>Share status: {shareStatus || "Idle"}</p>
                                    {recipientUserId && <p className="muted"><b>Recipient ID:</b> {recipientUserId}</p>}
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}