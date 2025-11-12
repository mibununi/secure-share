import { generateRsaOaep, exportSpkiB64, exportPkcs8, deriveAesKey, wrapPrivateKey, rand, toB64, fromB64, unwrapPrivateKey, importPkcs8ToCryptoKey } from "./keys";
import { saveKeystore, loadKeystore } from "./keystore";

const API = import.meta.env.VITE_API_BASE_URL;

export async function setupKeysAfterRegister(password: string, token: string) {
    const { publicKey, privateKey } = await generateRsaOaep();

    const publicSpkiB64 = await exportSpkiB64(publicKey);
    const pkcs8 = await exportPkcs8(privateKey);

    const salt = rand(16);
    const iv = rand(12);
    const aesKey = await deriveAesKey(password, salt);

    const wrapped = await wrapPrivateKey(pkcs8, aesKey, iv);

    await saveKeystore({
        version: 1,
        saltB64: toB64(salt),
        ivB64: toB64(iv),
        wrappedPrivB64: toB64(wrapped),
        publicSpkiB64,
        createdAt: new Date().toISOString(),
    });

    await fetch(`${API}/keys/public`, {
        method: "PUT",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ publicKey: publicSpkiB64 }),
    });
}

export async function loadSessionKeysAfterLogin(password: string) {
    const ks = await loadKeystore();
    if (!ks) throw new Error("No local keystore found.");

    const salt = fromB64(ks.saltB64);
    const iv = fromB64(ks.ivB64);
    const wrapped = fromB64(ks.wrappedPrivB64);

    const aesKey = await deriveAesKey(password, salt);
    const pkcs8 = await unwrapPrivateKey(wrapped, aesKey, iv);
    const privateKey = await importPkcs8ToCryptoKey(pkcs8);

    return { publicSpkiB64: ks.publicSpkiB64, privateKey };
}