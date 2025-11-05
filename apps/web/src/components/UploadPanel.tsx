import React, { useState } from "react";

const API = import.meta.env.VITE_API_BASE_URL as string;

export default function UploadPanel() {
    const [status, setStatus] = useState("");
    const [last, setLast] = useState<any>(null);
    const [file, setFile] = useState<File | null>(null);

    async function onSubmit(e: React.FormEvent) {
        e.preventDefault();
        setStatus("Uploading...");
        setLast(null);
        if (!file) { setStatus("No file selected"); return; }

        const form = new FormData();
        form.append("file", file);

        const token = localStorage.getItem("token") || "";
        const r = await fetch(`${API}/api/upload`, {
            method: "POST",
            headers: { Authorization: `Bearer ${token}` },
            body: form,
        });
        const json = await r.json();
        setLast(json);
        setStatus(json.ok ? "Uploaded" : `Failed: ${json.error || r.statusText}`);
    }

    return (
        <div className="panel" style={{ marginTop: 16 }}>
            <h3>Upload a file</h3>
            <form onSubmit={onSubmit} className="form" style={{ marginTop: 12 }}>
                <input
                    className="input"
                    type="file"
                    name="file"
                    onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)}
                />
                <button className="btn btn--success" style={{ marginTop: 8 }} disabled={!file}>
                    Upload
                </button>
            </form>

            <p className="muted" style={{ marginTop: 8 }}>
                Status: {status || "Idle"}
            </p>

            {last?.ok && (
                <div style={{ marginTop: 12 }}>
                    <div><b>Provider:</b> {last.provider}</div>
                    <div><b>CID:</b> {last.cid}</div>
                    <div>
                        <b>Gateway:</b>{" "}
                        <a href={last.gatewayUrl} target="_blank" rel="noreferrer">{last.gatewayUrl}</a>
                    </div>
                </div>
            )}
        </div>
    );
}