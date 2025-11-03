import { useState } from "react";
const API = import.meta.env.VITE_API_BASE_URL;

export default function App() {
  const [status, setStatus] = useState("");
  const [last, setLast] = useState<any>(null);

  async function upload(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setStatus("Uploading...");
    setLast(null);

    const input = e.currentTarget.elements.namedItem("file") as HTMLInputElement | null;
    const file = input?.files?.[0];
    if (!file) { setStatus("No file selected"); return; }

    const fd = new FormData();
    fd.append("file", file);

    const r = await fetch(`${API}/api/upload`, { method: "POST", body: fd });
    const json = await r.json();
    setLast(json);
    setStatus(json.ok ? "Uploaded" : "Failed");
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Upload to IPFS (via backend)</h2>
      <form onSubmit={upload}>
        <input type="file" name="file" />
        <button type="submit">Upload</button>
      </form>
      <p>Status: {status || "Idle"}</p>

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