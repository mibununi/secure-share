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
        cache: "no-store",
    });
    const text = await r.text();
    let json: unknown = null;

    try {
        json = JSON.parse(text);
    } catch {
        //non-JSON response is allowed
    }

    if (!r.ok || (json as { ok?: boolean })?.ok === false) {
        throw new Error(
            (json as { error?: string })?.error || r.statusText
        );
    }

    return json as T;
}

async function getJSON<T>(path: string, token?: string): Promise<T> {
    const r = await fetch(`${API_BASE}${path}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        cache: "no-store",
    });
    const text = await r.text();
    let json: unknown = null;

    try {
        json = JSON.parse(text);
    } catch {
        //non-JSON response is allowed
    }

    if (!r.ok || (json as { ok?: boolean })?.ok === false) {
        throw new Error(
            (json as { error?: string })?.error || r.statusText
        );
    }

    return json as T;
}

export type AuthResponse = { ok: true; token: string };
export type RegisterResponse = { ok: true; user: { id: string; email: string } };
export type MeResponse = { ok: true; me: { id: string; email: string; public_key: string | null; created_at: string } };

export type MyFilesResponse = {
    ok: true;
    files: { id: string; filename: string; cid: string; mime: string | null; created_at: string }[];
};

export type FileAccessResponse = {
    ok: true;
    file: {
        id: string;
        filename: string;
        cid: string;
        mime: string | null;
        created_at: string;
        cipher_iv_b64: string;
        cipher_sha256_b64: string | null;
        wrapped_key_b64: string;
    };
};
export type PublicKeyLookupResponse = {
    ok: true;
    userId: string;
    publicKey: string;
};

export type ShareFileResponse = { ok: true };

export type SharedWithMeResponse = {
    ok: true;
    files: {
        id: string;
        owner_id: string;
        filename: string;
        cid: string;
        mime: string | null;
        created_at: string;
    }[];
};

export const api = {
    register: (email: string, password: string) =>
        postJSON<RegisterResponse>("/auth/register", { email, password }),
    login: (email: string, password: string) =>
        postJSON<AuthResponse>("/auth/login", { email, password }),
    me: (token: string) => getJSON<MeResponse>("/auth/me", token),
    myFiles: (token: string) => getJSON<MyFilesResponse>("/api/files", token),
    fileAccess: (fileId: string, token: string) =>
        getJSON<FileAccessResponse>(`/api/files/${fileId}/access`, token),
    lookupPublicKey: (email: string, token: string) =>
        getJSON<PublicKeyLookupResponse>(
            `/api/users/public-key?email=${encodeURIComponent(email)}`,
            token
        ),
    shareFile: (fileId: string, recipientUserId: string, wrapped_key_b64: string, token: string) =>
        postJSON<ShareFileResponse>(
            `/api/files/${fileId}/share`,
            { recipientUserId, wrapped_key_b64 },
            token
        ),
    sharedWithMe: (token: string) =>
        getJSON<SharedWithMeResponse>("/api/files/shared-with-me", token),
};
