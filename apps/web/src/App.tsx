import { useEffect, useState } from "react";
import "./styles/global.css";
import "./styles/auth.css";
import AuthPage from "./pages/Auth";
import UploadPanel from "./components/UploadPanel";
import { api } from "./lib/api";
import MyFilesPanel from "./components/MyFilesPanel";
import { loadSessionKeysAfterLogin } from "./lib/keySetup";

type Me = { id: string; email: string; public_key: string | null; created_at: string };

export default function App() {
    const [token, setToken] = useState<string | null>(() => localStorage.getItem("token"));
    const [me, setMe] = useState<Me | null>(null);
    const [status, setStatus] = useState<string>("");
    const [sessionPrivateKey, setSessionPrivateKey] = useState<CryptoKey | null>(null);
    const [filesVersion, setFilesVersion] = useState(0);
    const notifyFilesChanged = () => setFilesVersion(v => v + 1);

    useEffect(() => {
        let cancelled = false;

        async function load() {
            if (!token) {
                setMe(null);
                setStatus("");
                setSessionPrivateKey(null);
                return;
            }

            setStatus("Loading profile...");
            try {
                const { me } = await api.me(token);
                if (cancelled) return;
                setMe(me);
                setStatus("");
            } catch (e: unknown) {
                console.error("Error loading profile:", e);
                if (cancelled) return;
                logout();
                setStatus("");
            }
        }
        load();
        return () => { cancelled = true; };
    }, [token]);

    const onLoggedIn = async (t: string, password: string) => {
        localStorage.setItem("token", t);
        setToken(t);

        try {
            const { privateKey } = await loadSessionKeysAfterLogin(password);
            setSessionPrivateKey(privateKey);
        } catch (e: unknown) {
            console.error("Failed to unlock session keys:", e);
            setSessionPrivateKey(null);
        }
    };
    const logout = () => {
        localStorage.removeItem("token");
        setToken(null);
        setMe(null);
        setSessionPrivateKey(null);
    };

    if (!token) return <AuthPage onLoggedIn={onLoggedIn} />;

    return (
        <div className="container">
            <div className="header">
                <h2>SecureShare</h2>
                <button className="btn btn--danger" onClick={logout}>Logout</button>
            </div>

            {status && <p className="message">{status}</p>}

            {me && (
                <div className="panel">
                    <div><b>User ID:</b> {me.id}</div>
                    <div><b>Email:</b> {me.email}</div>
                    <div><b>Public key:</b> {me.public_key ? "Yes" : "No"}</div>
                    <div><b>Session keys:</b> {sessionPrivateKey ? "Unlocked" : "Locked"}</div>
                    <div className="muted"><b>Joined:</b> {new Date(me.created_at).toLocaleString()}</div>
                </div>
            )}

            <UploadPanel onUploaded={notifyFilesChanged} />
            <MyFilesPanel
                token={token ?? ""}
                sessionPrivateKey={sessionPrivateKey}
                filesVersion={filesVersion}
            />
        </div>
    );
}