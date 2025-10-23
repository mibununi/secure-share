import { useState } from "react";
import {
  generateAesGcmKey, randomIv,
  encryptAesGcm, decryptAesGcm,
  enc, dec, toBase64, exportRawKey, importRawKey
} from "./crypto/aesGcm";

export default function App() {
  const [log, setLog] = useState<string>("");

  function add(line: string) {
    setLog((prev) => prev + line + "\n");
  }

  async function runDemo() {
    setLog("");
    try {
      const key = await generateAesGcmKey();
      const iv = randomIv(12);
      const message = "Hello world";
      add(`Plaintext: ${message}`);

      const ct = await encryptAesGcm(key, iv, enc.encode(message));
      add(`Ciphertext (b64): ${toBase64(ct)}`);
      add(`IV (b64): ${toBase64(iv)}`);

      const pt = await decryptAesGcm(key, iv, ct);
      add(`Decrypted: ${dec.decode(pt)}`);

      const b64key = await exportRawKey(key);
      const imported = await importRawKey(b64key);

      const tampered = new Uint8Array(ct);
      tampered[0] ^= 0b00000001;
      try {
        await decryptAesGcm(imported, iv, tampered);
        add("Tamper test: UNEXPECTEDLY succeeded (should fail)");
      } catch {
        add("Tamper test: decrypt failed as expected (integrity check works)");
      }
    } catch (e: any) {
      add(`Error: ${e?.message || String(e)}`);
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "ui-sans-serif, system-ui" }}>
      <h2>AES-GCM Test</h2>
      <button onClick={runDemo} style={{ padding: "8px 12px", cursor: "pointer" }}>
        Run AES-GCM
      </button>
      <pre style={{ background: "#111", color: "#0f0", padding: 16, marginTop: 16, whiteSpace: "pre-wrap" }}>
        {log}
      </pre>
    </div>
  );
}