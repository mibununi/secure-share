import {useEffect, useMemo, useState} from "react";
import {api, type MyFilesResponse, type UserRole, type SharedWithMeResponse} from "../lib/api";
import {fromB64, importSpkiFromB64, toB64} from "../lib/keys";

type OwnedRow = MyFilesResponse["files"][number];

type SharedRow = SharedWithMeResponse["files"][number];

type OwnedFile = OwnedRow & { kind: "owned" };
type SharedFile = SharedRow & { kind: "shared" };
type AnyFile = OwnedFile | SharedFile;

type PermissionRow = {
    user_id: string;
    email: string;
    revoked_at: string | null;
    is_owner: boolean;
    role?: UserRole;
};

type Props = {
    token: string;
    meId: string;
    role: UserRole;
    sessionPrivateKey: CryptoKey | null;
    filesVersion: number;
};

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
    const ab = u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
    return ab as ArrayBuffer;
}

async function sha256(u8: Uint8Array): Promise<Uint8Array> {
    const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(u8));
    return new Uint8Array(digest);
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

export default function AllFilesPanel({token, meId, role, sessionPrivateKey, filesVersion}: Props) {
    const [owned, setOwned] = useState<OwnedRow[]>([]);
    const [shared, setShared] = useState<SharedRow[]>([]);
    const [status, setStatus] = useState("");

    const [activeFileId, setActiveFileId] = useState<string | null>(null);

    const [recipientEmail, setRecipientEmail] = useState("");
    const [recipientUserId, setRecipientUserId] = useState<string | null>(null);
    const [recipientPublicKeyB64, setRecipientPublicKeyB64] = useState<string | null>(null);
    const [shareStatus, setShareStatus] = useState("");

    const [permsStatus, setPermsStatus] = useState("");
    const [permissions, setPermissions] = useState<PermissionRow[]>([]);

    const [downloadStatus, setDownloadStatus] = useState<Record<string, string>>({});

    const canManageAccessUI = role === "admin" || role === "manager";

    const allFiles: AnyFile[] = useMemo(() => {
        const o: AnyFile[] = owned.map((f) => ({...f, kind: "owned" as const}));
        const s: AnyFile[] = shared.map((f) => ({...f, kind: "shared" as const}));
        const merged = [...o, ...s];
        merged.sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at));
        return merged;
    }, [owned, shared]);

    useEffect(() => {
        let cancelled = false;

        async function load() {
            if (!token) return;
            try {
                setStatus("Loading files...");
                const [o, s] = await Promise.all([api.myFiles(token), api.sharedWithMe(token)]);
                if (cancelled) return;

                setOwned(o.files);
                setShared(s.files);
                setStatus("");
            } catch (e: unknown) {
                if (cancelled) return;
                const msg = e instanceof Error ? e.message : String(e);
                setStatus(`Failed to load files: ${msg}`);
            }
        }

        void load();
        return () => {
            cancelled = true;
        };
    }, [token, filesVersion]);

    async function refreshAll() {
        const [o, s] = await Promise.all([api.myFiles(token), api.sharedWithMe(token)]);
        setOwned(o.files);
        setShared(s.files); // no cast
    }

    function resetAccessUI() {
        setRecipientEmail("");
        setRecipientUserId(null);
        setRecipientPublicKeyB64(null);
        setShareStatus("");
        setPermissions([]);
        setPermsStatus("");
    }

    async function loadPermissions(fileId: string) {
        try {
            setPermsStatus("Loading access list...");
            const res = await api.filePermissions(fileId, token);

            const rows = (res.permissions as unknown as PermissionRow[]) ?? [];
            setPermissions(rows);
            setPermsStatus("");
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setPermissions([]);
            setPermsStatus(`Failed to load access list: ${msg}`);
        }
    }

    async function revokeUser(fileId: string, targetUserId: string) {
        try {
            setPermsStatus("Revoking...");
            await api.revokeAccess(fileId, targetUserId, token);
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

    function canShareThisFile(file: AnyFile): boolean {
        // employees can share only their own (owned) files
        // managers/admins can share all files (for now)
        if (role === "admin" || role === "manager") return true;
        return file.kind === "owned";
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

            // unwrap AES raw key with my RSA private key
            const wrappedBytes = fromB64(ownerWrappedKeyB64);
            const aesRawBuf = await crypto.subtle.decrypt(
                {name: "RSA-OAEP"},
                sessionPrivateKey,
                toArrayBuffer(wrappedBytes)
            );

            // re-wrap AES raw key for recipient using their RSA public key
            const recipientPk = await importSpkiFromB64(recipientPublicKeyB64);
            const wrappedForRecipientBuf = await crypto.subtle.encrypt({name: "RSA-OAEP"}, recipientPk, aesRawBuf);
            const wrappedForRecipient = new Uint8Array(wrappedForRecipientBuf);

            setShareStatus("Sharing...");
            await api.shareFile(fileId, recipientUserId, toB64(wrappedForRecipient), token);

            setShareStatus("Shared successfully.");
            await refreshAll();
            await loadPermissions(fileId);
        } catch (e: unknown) {
            const msg =
                e instanceof Error ? `${e.name}${e.message ? `: ${e.message}` : ""}` : String(e);
            setShareStatus(`Share failed: ${msg}`);
        }
    }

    async function downloadAndDecrypt(file: AnyFile) {
        try {
            setDownloadStatus((m) => ({...m, [file.id]: "Preparing..."}));

            if (!sessionPrivateKey) {
                throw new Error("Private key unavailable. Log out and log back in to unlock keys on this device.");
            }

            // fetch access metadata
            const access = await api.fileAccess(file.id, token);
            const {filename, mime, cipher_iv_b64, cipher_sha256_b64, wrapped_key_b64} = access.file;

            // unwrap AES key using my RSA private key
            setDownloadStatus((m) => ({...m, [file.id]: "Unwrapping key..."}));
            let aesRawBuf: ArrayBuffer;
            try {
                const wrappedKeyBytes = fromB64(wrapped_key_b64);
                aesRawBuf = await crypto.subtle.decrypt(
                    { name: "RSA-OAEP" },
                    sessionPrivateKey,
                    toArrayBuffer(wrappedKeyBytes)
                );
            } catch (e: unknown) {
                const msg = e instanceof Error ? `${e.name}${e.message ? `: ${e.message}` : ""}` : String(e);
                throw new Error(`Step 2 (RSA unwrap) failed: ${msg}`);
            }

            // import AES-GCM key
            let aesKey: CryptoKey;
            try {
                aesKey = await crypto.subtle.importKey("raw", aesRawBuf, { name: "AES-GCM" }, false, ["decrypt"]);
            } catch (e: unknown) {
                const msg = e instanceof Error ? `${e.name}${e.message ? `: ${e.message}` : ""}` : String(e);
                throw new Error(`Step 3 (AES import) failed: ${msg}`);
            }

            // download ciphertext
            setDownloadStatus((m) => ({...m, [file.id]: "Downloading..."}));
            const url = `${import.meta.env.VITE_API_BASE ?? "http://localhost:4000"}/api/files/${file.id}/download`;
            const resp = await fetch(url, {
                headers: { Authorization: `Bearer ${token}` },
                cache: "no-store",
            });
            if (!resp.ok) {
                const text = await resp.text().catch(() => "");
                throw new Error(`Download failed: ${resp.status} ${resp.statusText}${text ? ` - ${text}` : ""}`);
            }
            const ctBuf = await resp.arrayBuffer();
            const ct = new Uint8Array(ctBuf);

            // verify integrity
            if (cipher_sha256_b64) {
                setDownloadStatus((m) => ({...m, [file.id]: "Verifying..."}));
                const expected = fromB64(cipher_sha256_b64);
                const actual = await sha256(ct);
                if (!eqBytes(actual, expected)) {
                    throw new Error("Ciphertext hash mismatch (file may be corrupted or wrong CID).");
                }
            }

            // decrypt AES-GCM
            setDownloadStatus((m) => ({...m, [file.id]: "Decrypting..."}));
            let ptBuf: ArrayBuffer;
            try {
                const ivBytes = fromB64(cipher_iv_b64);
                ptBuf = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: toArrayBuffer(ivBytes) },
                    aesKey,
                    toArrayBuffer(ct)
                );
            } catch (e: unknown) {
                const msg = e instanceof Error ? `${e.name}${e.message ? `: ${e.message}` : ""}` : String(e);
                throw new Error(`Step 6 (AES-GCM decrypt) failed: ${msg}`);
            }

            // save
            setDownloadStatus((m) => ({...m, [file.id]: "Saving..."}));
            const outBlob = new Blob([ptBuf], {type: mime ?? "application/octet-stream"});
            downloadBlob(outBlob, filename);

            setDownloadStatus((m) => ({...m, [file.id]: "Done."}));
            setTimeout(() => {
                setDownloadStatus((m) => {
                    const next = {...m};
                    delete next[file.id];
                    return next;
                });
            }, 2000);
        } catch (e: unknown) {
            console.error("downloadAndDecrypt error:", e);

            const msg =
                e instanceof DOMException
                    ? `${e.name}${e.message ? `: ${e.message}` : ""}`
                    : e instanceof Error
                        ? `${e.name}${e.message ? `: ${e.message}` : ""}`
                        : String(e);

            setDownloadStatus((m) => ({ ...m, [file.id]: `Failed: ${msg}` }));
        }
    }

    return (
        <div className="panel" style={{marginTop: 16}}>
            <h3>All Files</h3>
            {status && <p className="muted">Status: {status}</p>}

            {allFiles.length === 0 ? (
                <p className="muted" style={{marginTop: 8}}>
                    No files found.
                </p>
            ) : (
                <div style={{marginTop: 12}}>
                    {allFiles.map((f) => {
                        const expanded = activeFileId === f.id;
                        const shareAllowed = canShareThisFile(f);
                        const showAccessControls = canManageAccessUI;
                        const canOpenAccessPanel = shareAllowed || showAccessControls;

                        return (
                            <div key={`${f.kind}:${f.id}`} style={{padding: 10, borderBottom: "1px solid #eee"}}>
                                <div style={{display: "flex", justifyContent: "space-between", gap: 12}}>
                                    <div style={{minWidth: 0}}>
                                        <div>
                                            <b>{f.filename}</b>{" "}
                                            <span className="muted" style={{fontSize: 12}}> {f.kind === "owned" ? "(Owned)" : "(Shared)"}</span>
                                        </div>
                                        {f.kind === "shared" && (
                                            <div className="muted" style={{marginTop: 4, wordBreak: "break-word"}}>
                                                Shared by: <b>{f.shared_by_email ?? f.owner_email}</b>
                                            </div>
                                        )}
                                        <div className="muted">Uploaded: {new Date(f.created_at).toLocaleString()}</div>
                                        <div className="muted" style={{wordBreak: "break-all"}}>
                                            File ID: {f.id}
                                        </div>
                                    </div>

                                    <div style={{
                                        display: "flex",
                                        flexDirection: "column",
                                        gap: 8,
                                        alignItems: "flex-end"
                                    }}>
                                        <button
                                            type="button"
                                            className="btn btn--success"
                                            onClick={() => void downloadAndDecrypt(f)}
                                            disabled={!sessionPrivateKey}
                                            title={!sessionPrivateKey ? "Unlock session keys by logging in again" : undefined}
                                        >
                                            Download
                                        </button>

                                        {downloadStatus[f.id] && (
                                            <div className="muted" style={{fontSize: 12, textAlign: "right"}}>
                                                {downloadStatus[f.id]}
                                            </div>
                                        )}
                                        {canOpenAccessPanel && (
                                            <button
                                                type="button"
                                                className="btn"
                                                onClick={() => {
                                                    if (expanded) {
                                                        setActiveFileId(null);
                                                        resetAccessUI();
                                                        return;
                                                    }
                                                    setActiveFileId(f.id);
                                                    resetAccessUI();

                                                    // load permissions for admins/managers
                                                    if (showAccessControls) {
                                                        void loadPermissions(f.id);
                                                    }
                                                }}
                                            >
                                                {expanded ? "Close" : "Access"}
                                            </button>
                                        )}
                                    </div>
                                </div>

                                {expanded && canOpenAccessPanel && (
                                    <div style={{marginTop: 12}}>
                                        <div style={{marginTop: 10}}>
                                            <div className="muted" style={{fontSize: 12, marginBottom: 6}}>
                                                Share (requires permission)
                                            </div>

                                            <input
                                                className="input"
                                                type="email"
                                                placeholder="Recipient email"
                                                value={recipientEmail}
                                                onChange={(e) => setRecipientEmail(e.target.value)}
                                                disabled={!shareAllowed}
                                            />

                                            <div style={{display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap"}}>
                                                <button
                                                    type="button"
                                                    className="btn"
                                                    disabled={!shareAllowed || !recipientEmail}
                                                    onClick={() => void lookupRecipient()}
                                                    title={!shareAllowed ? "You are not allowed to share this file" : undefined}
                                                >
                                                    Find user
                                                </button>

                                                <button
                                                    type="button"
                                                    className="btn btn--success"
                                                    disabled={
                                                        !shareAllowed ||
                                                        !sessionPrivateKey ||
                                                        !recipientUserId ||
                                                        !recipientPublicKeyB64
                                                    }
                                                    onClick={() => void shareFile(f.id)}
                                                    title={!shareAllowed ? "You are not allowed to share this file" : undefined}
                                                >
                                                    Share File
                                                </button>
                                            </div>

                                            <p className="muted" style={{marginTop: 8}}>
                                                Share status: {shareStatus || "Idle"}
                                            </p>
                                            {recipientUserId && (
                                                <p className="muted">
                                                    <b>Recipient ID:</b> {recipientUserId}
                                                </p>
                                            )}
                                        </div>

                                        {showAccessControls && (
                                            <div style={{marginTop: 16, borderTop: "1px solid #eee", paddingTop: 12}}>
                                                <h4 style={{margin: 0}}>Who has access</h4>
                                                {permsStatus && (
                                                    <p className="muted" style={{marginTop: 8}}>
                                                        {permsStatus}
                                                    </p>
                                                )}

                                                {permissions.length === 0 ? (
                                                    <p className="muted" style={{marginTop: 8}}>
                                                        No access entries found.
                                                    </p>
                                                ) : (
                                                    <div style={{marginTop: 8}}>
                                                        {permissions.map((p) => {
                                                            const isSelf = p.user_id === meId;
                                                            const managerCantRevokeAdmin = role === "manager" && p.role === "admin";

                                                            const revokeDisabled = p.is_owner || isSelf || managerCantRevokeAdmin;

                                                            const revokeTitle = p.is_owner
                                                                ? "The owner cannot be revoked"
                                                                : isSelf
                                                                    ? "You cannot revoke yourself"
                                                                    : managerCantRevokeAdmin
                                                                        ? "Managers cannot revoke admins"
                                                                        : undefined;

                                                            return (
                                                                <div
                                                                    key={p.user_id}
                                                                    style={{
                                                                        display: "flex",
                                                                        justifyContent: "space-between",
                                                                        gap: 12,
                                                                        padding: "6px 0",
                                                                    }}
                                                                >
                                                                    <div style={{minWidth: 0}}>
                                                                        <div style={{wordBreak: "break-word"}}>
                                                                            <b>{p.email}</b>
                                                                            {p.is_owner && (
                                                                                <span className="muted" style={{
                                                                                    marginLeft: 8,
                                                                                    fontSize: 12
                                                                                }}>
                                                                                    (Owner)
                                                                                </span>
                                                                            )}
                                                                            {p.role && !p.is_owner && (
                                                                                <span className="muted" style={{
                                                                                    marginLeft: 8,
                                                                                    fontSize: 12
                                                                                }}>
                                                                                    ({p.role})
                                                                                </span>
                                                                            )}
                                                                        </div>
                                                                        <div className="muted" style={{fontSize: 12}}>
                                                                            {p.revoked_at
                                                                                ? `Revoked: ${new Date(p.revoked_at).toLocaleString()}`
                                                                                : "Active"}
                                                                        </div>
                                                                    </div>

                                                                    {!p.revoked_at && (
                                                                        <button
                                                                            type="button"
                                                                            className="btn btn--danger"
                                                                            onClick={() => void revokeUser(f.id, p.user_id)}
                                                                            disabled={revokeDisabled}
                                                                            title={revokeTitle}
                                                                        >
                                                                            {p.is_owner ? "Owner" : "Revoke"}
                                                                        </button>
                                                                    )}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {!showAccessControls && (
                                            <div className="muted" style={{marginTop: 16, fontSize: 12}}>
                                                Access list / revocation is available only for <b>admins/managers</b>.
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}