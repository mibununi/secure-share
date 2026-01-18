import { useEffect, useState } from "react";
import { api, type SharedWithMeResponse } from "../lib/api";
import { fromB64 } from "../lib/keys";

type Row = SharedWithMeResponse["files"][number];

type Props = {
    token: string;
    sessionPrivateKey: CryptoKey | null;
};

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

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

async function importAesKey(raw: ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        raw,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
}

async function sha256(u8: Uint8Array): Promise<Uint8Array> {
    const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(u8));
    return new Uint8Array(digest);
}

function eqBytes(a: Uint8Array, b: Uint8Array) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

export default function SharedWithMePanel({ token, sessionPrivateKey }: Props) {
    const [files, setFiles] = useState<Row[]>([]);
    const [status, setStatus] = useState("");
    const [busyId, setBusyId] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;

        async function load() {
            try {
                setStatus("Loading shared files...");
                const res = await api.sharedWithMe(token);
                if (cancelled) return;
                setFiles(res.files);
                setStatus("");
            } catch (e: unknown) {
                const msg = e instanceof Error ? e.message : String(e);
                if (cancelled) return;
                setStatus(`Failed to load shared files: ${msg}`);
            }
        }

        if (token) load();
        return () => { cancelled = true; };
    }, [token]);

    async function downloadAndDecrypt(fileId: string) {
        try {
            if (!sessionPrivateKey) {
                throw new Error("Private key unavailable. Log out and log back in on this device.");
            }

            setBusyId(fileId);
            setStatus("Fetching access metadata...");

            const access = await api.fileAccess(fileId, token);

            const {
                cid,
                filename,
                cipher_iv_b64,
                wrapped_key_b64,
                cipher_sha256_b64,
            } = access.file;

            setStatus("Unwrapping file key...");
            const wrappedKeyBytes = fromB64(wrapped_key_b64);
            const aesRawBuf = await crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                sessionPrivateKey,
                toArrayBuffer(wrappedKeyBytes)
            );

            const aesKey = await importAesKey(aesRawBuf);

            setStatus("Downloading encrypted file from IPFS...");
            const url = `https://gateway.pinata.cloud/ipfs/${cid}`;
            const resp = await fetch(url, { cache: "no-store" });
            if (!resp.ok) throw new Error(`Failed to download ciphertext (${resp.status})`);

            const ctBuf = await resp.arrayBuffer();
            const ct = new Uint8Array(ctBuf);

            if (cipher_sha256_b64) {
                setStatus("Verifying integrity...");
                const expected = fromB64(cipher_sha256_b64);
                const actual = await sha256(ct);
                if (!eqBytes(actual, expected)) {
                    throw new Error("Ciphertext hash mismatch (file may be corrupted or wrong CID).");
                }
            }

            setStatus("Decrypting...");
            const iv = fromB64(cipher_iv_b64);
            const ptBuf = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv as BufferSource },
                aesKey,
                ctBuf
            );

            const blob = new Blob([ptBuf]);
            downloadBlob(blob, filename);

            setStatus("Download complete.");
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setStatus(`Download failed: ${msg}`);
        } finally {
            setBusyId(null);
        }
    }

    return (
        <div className="panel" style={{ marginTop: 16 }}>
            <h3>Shared With Me</h3>

            {status && <p className="muted">Status: {status}</p>}

            {files.length === 0 ? (
                <p className="muted" style={{ marginTop: 8 }}>No files have been shared with you yet.</p>
            ) : (
                <div style={{ marginTop: 12 }}>
                    {files.map((f) => (
                        <div key={f.id} style={{ padding: 10, borderBottom: "1px solid #eee" }}>
                            <div><b>{f.filename}</b></div>
                            <div className="muted">Shared file ID: {f.id}</div>
                            <div className="muted">Uploaded: {new Date(f.created_at).toLocaleString()}</div>

                            <button
                                type="button"
                                className="btn btn--success"
                                style={{ marginTop: 8 }}
                                disabled={!sessionPrivateKey || busyId === f.id}
                                onClick={() => downloadAndDecrypt(f.id)}
                            >
                                {busyId === f.id ? "Working..." : "Download & Decrypt"}
                            </button>

                            {!sessionPrivateKey && (
                                <p className="muted" style={{ marginTop: 8 }}>
                                    Log out and log back in on this device to unlock decryption keys.
                                </p>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}