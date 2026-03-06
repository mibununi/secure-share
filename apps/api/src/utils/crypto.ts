import crypto from "node:crypto";

export function sha256B64(buf: Buffer): string {
    return crypto.createHash("sha256").update(buf).digest("base64");
}

export function timingSafeEqualStr(a: string, b: string): boolean {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);

    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}