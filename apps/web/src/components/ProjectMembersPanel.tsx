import {useEffect, useState} from "react";
import {API_BASE} from "../lib/api";
import {importSpkiFromB64, toB64, unwrapAesKeyWithPrivateKey} from "../lib/keys";

type Member = {
    user_id: string;
    email: string;
    role: "admin" | "manager" | "employee";
};

type ProjectDetails = {
    id: string;
    name: string;
    created_at: string;
    role: "admin" | "manager" | "employee";
};

type Props = {
    token: string;
    projectId: string | null;
    currentUserEmail: string;
    privateKey: CryptoKey | null;
    onChanged?: () => void;
};

type BootstrapFile = {
    id: string;
    filename: string;
    owner_id: string;
    created_at: string;
};

async function fetchFilesForBootstrap(token: string, projectId: string, userId: string): Promise<BootstrapFile[]> {
    const res = await fetch(
        `${API_BASE}/api/projects/${projectId}/files-for-manager-bootstrap?userId=${encodeURIComponent(userId)}`,
        {
            headers: {Authorization: `Bearer ${token}`},
        }
    );

    const json = await res.json();
    if (!res.ok || !json.ok) {
        throw new Error(json?.error || "Failed to fetch project files");
    }

    return json.files ?? [];
}

async function bootstrapManagerAccess(
    token: string,
    projectId: string,
    userId: string,
    grants: { fileId: string; wrapped_key_b64: string }[]
) {
    const res = await fetch(
        `${API_BASE}/api/projects/${projectId}/bootstrap-manager-access`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
                userId,
                grants,
            }),
        }
    );

    const json = await res.json();
    if (!res.ok || !json.ok) {
        throw new Error(json?.error || "Bootstrap failed");
    }

    return json;
}

async function fetchUserPublicKey(token: string, email: string): Promise<CryptoKey> {
    const res = await fetch(
        `${API_BASE}/api/users/public-key?email=${encodeURIComponent(email)}`,
        {
            headers: {Authorization: `Bearer ${token}`},
        }
    );

    const json = await res.json();
    if (!res.ok || !json.ok) {
        throw new Error(json?.error || "Failed to fetch user public key");
    }

    return importSpkiFromB64(json.publicKey);
}

async function getDecryptedAesKey(
    fileId: string,
    token: string,
    privateKey: CryptoKey
): Promise<ArrayBuffer> {
    const res = await fetch(`${API_BASE}/api/files/${fileId}/access`, {
        headers: {Authorization: `Bearer ${token}`},
    });

    const json = await res.json();
    if (!res.ok || !json.ok) {
        throw new Error(json?.error || "Failed to fetch file access");
    }

    const wrappedKeyB64 = json.file.wrapped_key_b64;
    return unwrapAesKeyWithPrivateKey(wrappedKeyB64, privateKey);
}

export default function ProjectMembersPanel({
                                                token,
                                                projectId,
                                                currentUserEmail,
                                                privateKey,
                                                onChanged,
                                            }: Props) {
    const [project, setProject] = useState<ProjectDetails | null>(null);
    const [members, setMembers] = useState<Member[]>([]);
    const [email, setEmail] = useState("");
    const [role, setRole] = useState<"manager" | "employee">("employee");
    const [status, setStatus] = useState("");

    async function loadProjectAndMembers() {
        if (!projectId) {
            setProject(null);
            setMembers([]);
            setStatus("");
            return;
        }

        try {
            setStatus("Loading project details...");
            const [projectRes, membersRes] = await Promise.all([
                fetch(`${API_BASE}/api/projects/${projectId}`, {
                    headers: {Authorization: `Bearer ${token}`},
                }),
                fetch(`${API_BASE}/api/projects/${projectId}/members`, {
                    headers: {Authorization: `Bearer ${token}`},
                }),
            ]);

            const projectJson = await projectRes.json();
            const membersJson = await membersRes.json();

            if (!projectRes.ok || !projectJson.ok) {
                throw new Error(projectJson?.error || "Failed to load project");
            }
            if (!membersRes.ok || !membersJson.ok) {
                throw new Error(membersJson?.error || "Failed to load members");
            }

            setProject(projectJson.project ?? null);
            setMembers(membersJson.members ?? []);
            setStatus("");
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setStatus(`Failed: ${msg}`);
            setProject(null);
            setMembers([]);
        }
    }

    async function addMember(e: React.FormEvent) {
        e.preventDefault();
        if (!projectId) return;

        try {
            const trimmedEmail = email.trim().toLowerCase();
            if (!trimmedEmail) {
                setStatus("Email is required");
                return;
            }

            setStatus("Looking up user...");
            const lookupRes = await fetch(
                `${API_BASE}/api/users/public-key?email=${encodeURIComponent(trimmedEmail)}`,
                {
                    headers: {Authorization: `Bearer ${token}`},
                }
            );
            const lookupJson = await lookupRes.json();

            if (!lookupRes.ok || !lookupJson.ok) {
                throw new Error(lookupJson?.error || "User lookup failed");
            }

            setStatus("Adding member...");
            const addRes = await fetch(`${API_BASE}/api/projects/${projectId}/members`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                    userId: lookupJson.userId,
                    role,
                }),
            });

            const addJson = await addRes.json();
            if (!addRes.ok || !addJson.ok) {
                throw new Error(addJson?.error || "Failed to add member");
            }

            setStatus("Member added.");

            // If manager then bootstrap access to existing files
            if (role === "manager") {
                try {
                    if (!privateKey) {
                        throw new Error("Your private key is not available in this session.");
                    }

                    setStatus("Preparing access to existing files...");

                    const files = await fetchFilesForBootstrap(token, projectId, lookupJson.userId);

                    if (files.length === 0) {
                        setStatus("Manager added (no existing files to grant).");
                    } else {
                        setStatus("Granting access to existing files...");

                        const recipientPublicKey = await fetchUserPublicKey(token, trimmedEmail);

                        const grants: { fileId: string; wrapped_key_b64: string }[] = [];

                        for (const f of files) {
                            const aesKeyRaw = await getDecryptedAesKey(
                                f.id,
                                token,
                                privateKey
                            );

                            const wrapped = await crypto.subtle.encrypt(
                                {name: "RSA-OAEP"},
                                recipientPublicKey,
                                aesKeyRaw
                            );

                            grants.push({
                                fileId: f.id,
                                wrapped_key_b64: toB64(new Uint8Array(wrapped)),
                            });
                        }

                        await bootstrapManagerAccess(token, projectId, lookupJson.userId, grants);

                        setStatus("Manager access granted.");
                    }
                } catch (e: unknown) {
                    const msg = e instanceof Error ? e.message : String(e);
                    setStatus(`Manager added, but bootstrap failed: ${msg}`);
                }
            }

            setEmail("");
            setRole("employee");

            await loadProjectAndMembers();
            onChanged?.();
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setStatus(`Failed: ${msg}`);
        }
    }

    async function revokeMember(userId: string) {
        if (!projectId) return;

        try {
            setStatus("Removing member...");
            const res = await fetch(`${API_BASE}/api/projects/${projectId}/revoke`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({userId}),
            });

            const json = await res.json();
            if (!res.ok || !json.ok) {
                throw new Error(json?.error || "Failed to remove member");
            }

            setStatus("Member removed.");
            await loadProjectAndMembers();
            onChanged?.();
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setStatus(`Failed: ${msg}`);
        }
    }

    useEffect(() => {
        void loadProjectAndMembers();
    }, [token, projectId]);

    if (!projectId) return null;

    return (
        <div className="panel" style={{marginTop: 16}}>
            <h3>Project Members</h3>

            {project && (
                <div className="muted" style={{marginTop: 6}}>
                    <div>
                        <b>Project:</b> {project.name}
                    </div>
                    <div>
                        <b>Your role:</b> {project.role}
                    </div>
                    <div>
                        <b>Signed in as:</b> {currentUserEmail}
                    </div>
                </div>
            )}

            <p className="muted" style={{marginTop: 8}}>Status: {status || "Idle"}</p>

            {project?.role === "admin" && (
                <form onSubmit={addMember} style={{marginTop: 12}}>
                    <input
                        className="input"
                        type="email"
                        placeholder="User email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />

                    <select
                        className="input"
                        value={role}
                        onChange={(e) => setRole(e.target.value as "manager" | "employee")}
                        style={{marginTop: 8}}
                    >
                        <option value="employee">Employee</option>
                        <option value="manager">Manager</option>
                    </select>

                    <button
                        type="submit"
                        className="btn btn--success"
                        style={{marginTop: 8}}
                    >
                        Add Member
                    </button>
                </form>
            )}

            <div style={{marginTop: 14}}>
                {members.length === 0 ? (
                    <p className="muted">No members found.</p>
                ) : (
                    members.map((m) => {
                        const isAdmin = m.role === "admin";
                        return (
                            <div
                                key={m.user_id}
                                style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    gap: 12,
                                    padding: "8px 0",
                                    borderBottom: "1px solid #eee",
                                    alignItems: "center",
                                }}
                            >
                                <div style={{minWidth: 0, wordBreak: "break-word"}}>
                                    <div>{m.email}</div>
                                    <div className="muted" style={{fontSize: 12}}>{m.role}</div>
                                </div>

                                {project?.role === "admin" && !isAdmin && (
                                    <button
                                        type="button"
                                        className="btn btn--danger"
                                        onClick={() => void revokeMember(m.user_id)}
                                    >
                                        Remove
                                    </button>
                                )}
                            </div>
                        );
                    })
                )}
            </div>
        </div>
    );
}