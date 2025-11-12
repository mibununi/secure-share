export type RsaPair = { publicKey: CryptoKey; privateKey: CryptoKey };

export async function generateRsaOaep(): Promise<RsaPair> {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
    return keyPair as RsaPair;
}

export async function exportSpkiB64(pub: CryptoKey): Promise<string> {
    const spki = await crypto.subtle.exportKey("spki", pub);
    return toB64(new Uint8Array(spki));
}

export async function exportPkcs8(priv: CryptoKey): Promise<Uint8Array> {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", priv);
    return new Uint8Array(pkcs8);
}

async function getKeyMaterial(password: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    return crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
}

export async function deriveAesKey(
    password: string,
    salt: Uint8Array,
    iterations = 210_000
): Promise<CryptoKey> {
    const material = await getKeyMaterial(password);
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt as BufferSource,
            iterations,
            hash: "SHA-256",
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function wrapPrivateKey(
    pkcs8: Uint8Array,
    aesKey: CryptoKey,
    iv: Uint8Array
): Promise<Uint8Array> {
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        aesKey,
        pkcs8 as BufferSource
    );
    return new Uint8Array(ct);
}

export async function unwrapPrivateKey(
    wrapped: Uint8Array,
    aesKey: CryptoKey,
    iv: Uint8Array
): Promise<Uint8Array> {
    const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource},
        aesKey,
        wrapped as BufferSource
    );
    return new Uint8Array(pt);
}

export async function importPkcs8ToCryptoKey(pkcs8: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "pkcs8",
        pkcs8 as BufferSource,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
}

export function rand(bytes: number): Uint8Array {
    const u = new Uint8Array(bytes);
    crypto.getRandomValues(u);
    return u;
}
export function toB64(u8: Uint8Array): string {
    return btoa(String.fromCharCode(...u8));
}
export function fromB64(b64: string): Uint8Array {
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
}