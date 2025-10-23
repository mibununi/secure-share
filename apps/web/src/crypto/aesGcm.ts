export async function generateAesGcmKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export function randomIv(bytes = 12): Uint8Array {
  const iv = new Uint8Array(bytes);
  crypto.getRandomValues(iv);
  return iv;
}

export async function encryptAesGcm(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const alg: AesGcmParams = aad
    ? { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource }
    : { name: "AES-GCM", iv: iv as BufferSource };
  const ct = await crypto.subtle.encrypt(alg, key, plaintext as BufferSource);
  return new Uint8Array(ct);
}

export async function decryptAesGcm(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const alg: AesGcmParams = aad
    ? { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource }
    : { name: "AES-GCM", iv: iv as BufferSource };
  const pt = await crypto.subtle.decrypt(alg, key, ciphertext as BufferSource);
  return new Uint8Array(pt);
}

export async function importRawKey(b64: string): Promise<CryptoKey> {
  const raw = fromBase64(b64);
  return crypto.subtle.importKey(
    "raw",
    raw.buffer as ArrayBuffer,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

export const enc = new TextEncoder();
export const dec = new TextDecoder();

export function toBase64(u8: Uint8Array): string {
  return btoa(String.fromCharCode(...u8));
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export async function exportRawKey(key: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return toBase64(raw);
}