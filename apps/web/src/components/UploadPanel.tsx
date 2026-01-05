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

import React, { useState } from "react";
import { API_BASE } from "../lib/api";
import { loadKeystore } from "../lib/keystore";
import {
    importSpkiFromB64,
    toB64,
} from "../lib/keys";

function rand(n: number) {
    const u = new Uint8Array(n);
    crypto.getRandomValues(u);
    return u;
}

async function generateAesKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

export default function UploadPanel() {
    const [status, setStatus] = useState("");
    const [last, setLast] = useState<UploadSummary | null>(null);
    const [file, setFile] = useState<File | null>(null);

    async function onSubmit(e: React.FormEvent) {
        e.preventDefault();
        setStatus("Uploading...");
        setLast(null);

        try {
            if (!file) {
                setStatus("No file selected");
                return;
            }

            const ks = await loadKeystore();
            if (!ks?.publicSpkiB64) throw new Error("Public key not found locally.");
            const publicKey = await importSpkiFromB64(ks.publicSpkiB64);

            const pt = new Uint8Array(await file.arrayBuffer());

            const aesKey = await generateAesKey();
            const iv = rand(12);
            const ctBuf = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv as BufferSource },
                aesKey,
                pt.buffer
            );
            const ct = new Uint8Array(ctBuf);

            const sha = new Uint8Array(await crypto.subtle.digest("SHA-256", ct));

            const rawKeyBuf = await crypto.subtle.exportKey("raw", aesKey);
            const wrapped = new Uint8Array(
                await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKeyBuf)
            );

            const token = localStorage.getItem("token") || "";
            const fd = new FormData();
            fd.append(
                "file",
                new Blob([ct], { type: "application/octet-stream" }),
                file.name + ".enc"
            );
            const uploadRes = await fetch(`${API_BASE}/api/upload`, {
                method: "POST",
                headers: { Authorization: `Bearer ${token}`, },
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
                    wrapped_key_b64: toB64(wrapped),
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
            setFile(null);
            (e.target as HTMLFormElement).reset();
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : "Upload failed";
            setStatus(`Failed: ${msg}`);
            console.error(err);
        }
    }

    return (
        <div className="panel" style={{marginTop: 16}}>
            <h3>Encrypt & Upload</h3>
            <form onSubmit={onSubmit} className="form" style={{marginTop: 12}}>
                <input
                    className="input"
                    type="file"
                    name="file"
                    onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)}
                />
                <button className="btn btn--success" style={{marginTop: 8}} disabled={!file}>
                    Upload
                </button>
            </form>

            <p className="muted" style={{marginTop: 8}}>Status: {status || "Idle"}</p>

            {last?.cid && (
                <div style={{marginTop: 12}}>
                    <div><b>CID:</b> {last.cid}</div>
                    <div>
                        <b>Gateway:</b>{" "}
                        <a href={last.gatewayUrl} target="_blank" rel="noreferrer">
                            {last.gatewayUrl}
                        </a>
                    </div>
                </div>
            )}
        </div>
    );
}