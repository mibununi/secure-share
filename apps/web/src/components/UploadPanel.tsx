import React, {useState} from "react";
import {API_BASE} from "../lib/api";
import {loadKeystore} from "../lib/keystore";
import {importSpkiFromB64, toB64} from "../lib/keys";

type Props = {
    onUploaded: () => void;
    projectId?: string | null;
    email: string;
    disabled?: boolean;
};

type UploadOk = {
    ok: true;
    provider: string;
    cid: string;
    gatewayUrl: string;
    size?: number;
};

type UploadErr = { ok: false; error: string };

type MetadataOk = { ok: true; fileId: string; createdAt: string };
type MetadataErr = { ok: false; error: string };

type UploadSummary = {
    cid: string;
    gatewayUrl: string;
    size?: number;
    fileId?: string;
    createdAt?: string;
};

function rand(n: number) {
    const u = new Uint8Array(n);
    crypto.getRandomValues(u);
    return u;
}

async function generateAesKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        {name: "AES-GCM", length: 256},
        true,
        ["encrypt", "decrypt"]
    );
}

type ProjectMember = {
    user_id: string;
    email: string;
    role: "admin" | "manager" | "employee";
};

async function fetchProjectMembers(token: string, projectId: string): Promise<ProjectMember[]> {
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/members`, {
        headers: {Authorization: `Bearer ${token}`},
    });

    const json = await res.json();
    if (!res.ok || !json.ok) {
        throw new Error(json?.error || "Failed to load project members");
    }

    return json.members ?? [];
}

async function fetchUserPublicKey(token: string, email: string): Promise<CryptoKey> {
    const res = await fetch(
        `${API_BASE}/api/users/public-key?email=${encodeURIComponent(email)}`,
        {headers: {Authorization: `Bearer ${token}`}}
    );

    const json = await res.json();
    if (!res.ok || !json.ok) {
        throw new Error(json?.error || "Failed to fetch user public key");
    }

    return importSpkiFromB64(json.publicKey);
}

export default function UploadPanel({onUploaded, projectId, email, disabled = false}: Props) {
    const [status, setStatus] = useState("");
    const [last, setLast] = useState<UploadSummary | null>(null);
    const [file, setFile] = useState<File | null>(null);

    async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        const form = e.currentTarget;

        if (disabled) {
            setStatus("Encryption keys are not ready yet.");
            return;
        }

        setStatus("Uploading...");
        setLast(null);

        try {
            if (!file) {
                setStatus("No file selected");
                return;
            }

            const normalizedEmail = email.trim().toLowerCase();
            if (!normalizedEmail) {
                throw new Error("User email is unavailable.");
            }

            const ks = await loadKeystore(normalizedEmail);
            if (!ks?.publicSpkiB64) {
                throw new Error("Public key not found locally.");
            }

            const publicKey = await importSpkiFromB64(ks.publicSpkiB64);

            const pt = new Uint8Array(await file.arrayBuffer());

            const aesKey = await generateAesKey();
            const iv = rand(12);
            const ctBuf = await crypto.subtle.encrypt(
                {name: "AES-GCM", iv: iv as BufferSource},
                aesKey,
                pt.buffer
            );
            const ct = new Uint8Array(ctBuf);

            const sha = new Uint8Array(await crypto.subtle.digest("SHA-256", ct));

            const rawKeyBuf = await crypto.subtle.exportKey("raw", aesKey);

            const token = localStorage.getItem("token") || "";
            if (!token) {
                throw new Error("Missing session token.");
            }

            const meRes = await fetch(`${API_BASE}/auth/me`, {
                headers: {Authorization: `Bearer ${token}`},
            });
            const meJson = await meRes.json();
            if (!meRes.ok || !meJson.ok) {
                throw new Error(meJson?.error || "Failed to resolve current user");
            }

            const currentUserId = String(meJson.me.id);

            const recipients: { userId: string; email: string; publicKey: CryptoKey }[] = [
                {
                    userId: currentUserId,
                    email: normalizedEmail,
                    publicKey,
                },
            ];

            if (projectId) {
                const members = await fetchProjectMembers(token, projectId);

                const leaders = members.filter(
                    (m) => m.role === "admin" || m.role === "manager"
                );

                for (const m of leaders) {
                    // avoid duplicate wrapping for self
                    if (m.email.toLowerCase() === normalizedEmail) continue;

                    const pk = await fetchUserPublicKey(token, m.email);

                    recipients.push({
                        userId: m.user_id,
                        email: m.email,
                        publicKey: pk,
                    });
                }
            }

            // wrap AES key for each recipient
            const wrappedKeys: { userId: string; wrapped_key_b64: string }[] = [];

            for (const r of recipients) {
                const wrappedBuf = await crypto.subtle.encrypt(
                    {name: "RSA-OAEP"},
                    r.publicKey,
                    rawKeyBuf
                );

                wrappedKeys.push({
                    userId: r.userId,
                    wrapped_key_b64: toB64(new Uint8Array(wrappedBuf)),
                });
            }

            const fd = new FormData();
            fd.append(
                "file",
                new Blob([ct], {type: "application/octet-stream"}),
                `${file.name}.enc`
            );
            const uploadRes = await fetch(`${API_BASE}/api/upload`, {
                method: "POST",
                headers: {Authorization: `Bearer ${token}`},
                body: fd,
            });
            const uploadJson = (await uploadRes.json()) as UploadOk | UploadErr;
            if (!uploadRes.ok || !uploadJson.ok) {
                const msg = uploadJson.ok ? uploadRes.statusText : uploadJson.error;
                throw new Error(msg || "Upload failed");
            }

            const metaRes = await fetch(`${API_BASE}/api/files/metadata`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                    filename: file.name,
                    mime: file.type || null,
                    cid: uploadJson.cid,
                    cipher_iv_b64: toB64(iv),
                    cipher_sha256_b64: toB64(sha),
                    wrapped_keys: wrappedKeys,
                    projectId: projectId ?? null,
                }),
            });
            const metaJson = (await metaRes.json()) as MetadataOk | MetadataErr;
            if (!metaRes.ok || !metaJson.ok) {
                const msg = metaJson.ok ? metaRes.statusText : metaJson.error;
                throw new Error(msg || "Metadata save failed");
            }

            setLast({
                cid: uploadJson.cid,
                gatewayUrl: uploadJson.gatewayUrl,
                size: uploadJson.size,
                fileId: metaJson.ok ? metaJson.fileId : undefined,
                createdAt: metaJson.ok ? metaJson.createdAt : undefined,
            });
            setStatus("Encrypted upload complete.");
            onUploaded();
            setFile(null);
            form.reset();
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : "Upload failed";
            setStatus(`Failed: ${msg}`);
            console.error(err);
        }
    }

    return (
        <div className="panel" style={{marginTop: 16}}>
            <h3>Encrypt & Upload</h3>

            <div className="muted" style={{marginTop: 4}}>
                Target: {projectId ? "Project file" : "Personal file"}
            </div>

            {disabled && (
                <p className="muted" style={{marginTop: 8}}>
                    Upload is disabled until your encryption keys are ready.
                </p>
            )}

            <form onSubmit={onSubmit} className="form" style={{marginTop: 12}}>
                <input
                    className="input"
                    type="file"
                    name="file"
                    disabled={disabled}
                    onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)}
                />

                <button
                    className="btn btn--success"
                    style={{marginTop: 8}}
                    disabled={disabled || !file}
                    title={disabled ? "Encryption keys are not ready yet" : undefined}
                >
                    Upload
                </button>
            </form>

            <p className="muted" style={{marginTop: 8}}>
                Status: {status || "Idle"}
            </p>

            {last?.cid && (
                <div style={{marginTop: 12}}>
                    <div><b>CID:</b> {last.cid}</div>
                    <div>
                        <b>Gateway:</b>{" "}
                        <a href={last.gatewayUrl} target="_blank" rel="noreferrer">
                            {last.gatewayUrl}
                        </a>
                    </div>
                    {last.fileId && <div><b>File ID:</b> {last.fileId}</div>}
                    {last.createdAt && (
                        <div><b>Created:</b> {new Date(last.createdAt).toLocaleString()}</div>
                    )}
                </div>
            )}
        </div>
    );
}