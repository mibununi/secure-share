import {useEffect, useState} from "react";
import "./styles/global.css";
import "./styles/auth.css";
import AuthPage from "./pages/Auth";
import UploadPanel from "./components/UploadPanel";
import {api, type UserRole} from "./lib/api";
import {loadSessionKeysAfterLogin, setupKeysAfterRegister} from "./lib/keySetup";
import {loadKeystore} from "./lib/keystore";
import AllFilesPanel from "./components/AllFilesPanel";
import ProjectsPanel from "./components/ProjectsPanel";
import ProjectMembersPanel from "./components/ProjectMembersPanel";

type Me = {
    id: string;
    email: string;
    role: UserRole;
    public_key: string | null;
    created_at: string;
};

export default function App() {
    const [token, setToken] = useState<string | null>(() => localStorage.getItem("token"));
    const [me, setMe] = useState<Me | null>(null);
    const [status, setStatus] = useState<string>("");
    const [keyStatus, setKeyStatus] = useState<string>("");
    const [keysReady, setKeysReady] = useState(false);
    const [sessionPrivateKey, setSessionPrivateKey] = useState<CryptoKey | null>(null);
    const [unlockPassword, setUnlockPassword] = useState("");
    const [filesVersion, setFilesVersion] = useState(0);
    const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);

    const notifyFilesChanged = () => setFilesVersion((v) => v + 1);

    async function ensureKeysReady(token: string, email: string, password: string): Promise<CryptoKey> {
        let ks = await loadKeystore(email);

        if (!ks) {
            await setupKeysAfterRegister(email, password, token);
            ks = await loadKeystore(email);

            if (!ks) {
                throw new Error("Failed to create local keystore.");
            }
        }

        const {privateKey} = await loadSessionKeysAfterLogin(email, password);
        return privateKey;
    }

    const logout = () => {
        localStorage.removeItem("token");
        setToken(null);
        setMe(null);
        setSessionPrivateKey(null);
        setSelectedProjectId(null);
        setKeysReady(false);
        setKeyStatus("");
        setStatus("");
        setUnlockPassword("");
    };

    async function unlockKeys() {
        if (!token || !me) return;

        const password = unlockPassword;
        if (!password) {
            setKeyStatus("Please enter your password to unlock your encryption keys.");
            return;
        }

        setKeyStatus("Unlocking your encryption keys...");

        try {
            const privateKey = await ensureKeysReady(token, me.email, password);
            setSessionPrivateKey(privateKey);
            setKeysReady(true);
            setKeyStatus("");
            setUnlockPassword("");
        } catch (e: unknown) {
            console.error("Failed to unlock session keys:", e);
            setSessionPrivateKey(null);
            setKeysReady(false);
            setKeyStatus("Failed to unlock encryption keys. Please check your password.");
        }
    }

    useEffect(() => {
        let cancelled = false;

        async function load() {
            if (!token) {
                setMe(null);
                setStatus("");
                setSessionPrivateKey(null);
                setSelectedProjectId(null);
                setKeysReady(false);
                setKeyStatus("");
                setUnlockPassword("");
                return;
            }

            setStatus("Loading profile...");
            try {
                const res = await api.me(token);
                if (cancelled) return;

                setMe(res.me ?? null);
                setStatus("");

                if (!sessionPrivateKey) {
                    setKeysReady(false);
                    setKeyStatus("Please unlock your encryption keys.");
                }
            } catch (e: unknown) {
                console.error("Error loading profile:", e);
                if (cancelled) return;
                logout();
            }
        }

        void load();

        return () => {
            cancelled = true;
        };
    }, [token, sessionPrivateKey]);

    const onLoggedIn = async (t: string, email: string, password: string) => {
        localStorage.setItem("token", t);
        setToken(t);

        setKeysReady(false);
        setSessionPrivateKey(null);
        setUnlockPassword("");
        setKeyStatus("Preparing your encryption keys...");

        try {
            const privateKey = await ensureKeysReady(t, email, password);
            setSessionPrivateKey(privateKey);
            setKeysReady(true);
            setKeyStatus("");
        } catch (e: unknown) {
            console.error("Failed to prepare session keys:", e);
            setSessionPrivateKey(null);
            setKeysReady(false);
            setKeyStatus("Failed to prepare encryption keys. Please sign in again.");
        }
    };

    if (!token) {
        return <AuthPage onLoggedIn={onLoggedIn}/>;
    }

    if (!keysReady) {
        return (
            <div className="container">
                <div className="panel">
                    <div className="header">
                        <h2>SecureShare</h2>
                        <button className="btn btn--danger" onClick={logout}>
                            Logout
                        </button>
                    </div>

                    {status && <p className="message">{status}</p>}
                    {me && (
                        <div className="muted" style={{marginBottom: 12}}>
                            <div><b>Email:</b> {me.email}</div>
                            <div><b>Public key:</b> {me.public_key ? "Yes" : "No"}</div>
                        </div>
                    )}

                    <p className="message">
                        {keyStatus || "Please unlock your encryption keys."}
                    </p>

                    {me && (
                        <form
                            onSubmit={(e) => {
                                e.preventDefault();
                                void unlockKeys();
                            }}
                            style={{marginTop: 12}}
                        >
                            <input
                                className="input"
                                type="password"
                                placeholder="Enter your password"
                                value={unlockPassword}
                                onChange={(e) => setUnlockPassword(e.target.value)}
                            />

                            <button
                                type="submit"
                                className="btn btn--success"
                                style={{marginTop: 8}}
                            >
                                Unlock Keys
                            </button>
                        </form>
                    )}
                </div>
            </div>
        );
    }

    return (
        <div className="container">
            <div className="header">
                <h2>SecureShare</h2>
                <button className="btn btn--danger" onClick={logout}>
                    Logout
                </button>
            </div>

            {status && <p className="message">{status}</p>}
            {keyStatus && <p className="message">{keyStatus}</p>}

            {me && (
                <div className="panel">
                    <div><b>User ID:</b> {me.id}</div>
                    <div><b>Email:</b> {me.email}</div>
                    <div><b>Public key:</b> {me.public_key ? "Yes" : "No"}</div>
                    <div><b>Session keys:</b> {sessionPrivateKey ? "Unlocked" : "Locked"}</div>
                    <div className="muted"><b>Joined:</b> {new Date(me.created_at).toLocaleString()}</div>
                </div>
            )}

            <ProjectsPanel
                token={token}
                selectedProjectId={selectedProjectId}
                onSelectProject={setSelectedProjectId}
                onProjectsChanged={notifyFilesChanged}
            />

            {selectedProjectId && me && (
                <ProjectMembersPanel
                    token={token}
                    projectId={selectedProjectId}
                    currentUserEmail={me.email}
                    privateKey={sessionPrivateKey}
                    onChanged={notifyFilesChanged}
                />
            )}

            <UploadPanel
                onUploaded={notifyFilesChanged}
                projectId={selectedProjectId}
                email={me?.email ?? ""}
                disabled={!keysReady}
            />

            {me && (
                <AllFilesPanel
                    token={token}
                    meId={me.id}
                    role={me.role}
                    sessionPrivateKey={sessionPrivateKey}
                    filesVersion={filesVersion}
                    selectedProjectId={selectedProjectId}
                    keysReady={keysReady}
                />
            )}
        </div>
    );
}