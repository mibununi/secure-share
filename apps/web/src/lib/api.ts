export const API_BASE = import.meta.env.VITE_API_BASE_URL as string;

async function postJSON<T>(
    path: string,
    body: unknown,
    token?: string
): Promise<T> {
    const r = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
    });
    const json = await r.json();
    if (!r.ok || json?.ok === false) {
        throw new Error(json?.error || r.statusText);
    }
    return json as T;
}

async function getJSON<T>(path: string, token?: string): Promise<T> {
    const r = await fetch(`${API_BASE}${path}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    const json = await r.json();
    if (!r.ok || json?.ok === false) {
        throw new Error(json?.error || r.statusText);
    }
    return json as T;
}

export type AuthResponse = { ok: true; token: string };
export type RegisterResponse = { ok: true; user: { id: string; email: string } };
export type MeResponse = { ok: true; me: { id: string; email: string; public_key: string | null; created_at: string } };

export const api = {
    register: (email: string, password: string) =>
        postJSON<RegisterResponse>("/auth/register", { email, password }),
    login: (email: string, password: string) =>
        postJSON<AuthResponse>("/auth/login", { email, password }),
    me: (token: string) => getJSON<MeResponse>("/auth/me", token),
};