import argon2 from 'argon2';
import jwt, { type Secret, type SignOptions } from 'jsonwebtoken';
import type { StringValue as MsString } from 'ms';
import type { Request, Response, NextFunction } from 'express';

const JWT_SECRET: Secret = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES: MsString = (process.env.JWT_EXPIRES as MsString) ?? ('15m' as MsString);

export type UserRole = 'admin' | 'manager' | 'employee';
export type AuthUser = {
    id: string;
    email: string;
    role: UserRole
};

export function signAccessToken(payload: {id: any; email: any; role: UserRole }) {
    const opts: SignOptions = { expiresIn: JWT_EXPIRES };
    return jwt.sign(payload, JWT_SECRET, opts);
}

export async function hashPassword(password: string) {
    return argon2.hash(password, { type: argon2.argon2id });
}

export async function verifyPassword(hash: string, password: string) {
    return argon2.verify(hash, password);
}

export interface AuthReq extends Request {
    user?: AuthUser;
}

export function requireAuth(req: AuthReq, res: Response, next: NextFunction) {
    const hdr = req.header('Authorization');
    if (!hdr?.startsWith('Bearer ')) {
        return res.status(401).json({ ok: false, error: 'Missing token' });
    }
    const token = hdr.slice(7);
    try {
        req.user = jwt.verify(token, JWT_SECRET) as { id: string; email: string; role: "admin" | "manager" | "employee" };
        return next();
    } catch {
        return res.status(401).json({ ok: false, error: 'Invalid or expired token' });
    }
}